"""Blob storage: atomic writes, safe names, no leftovers, integrity checks on read."""

import os
import re
import stat
from pathlib import Path

import pytest

from app.files.storage import BlobIntegrityError, BlobStorage, StorageError, new_blob_name

DATA = b"ciphertext-bytes" * 50


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "blobs"


@pytest.fixture
def storage(root: Path) -> BlobStorage:
    return BlobStorage(root)


def listing(root: Path) -> list[str]:
    return sorted(path.name for path in root.iterdir()) if root.exists() else []


def test_blob_names_are_random_and_well_formed() -> None:
    names = {new_blob_name() for _ in range(500)}

    assert len(names) == 500
    assert all(re.fullmatch(r"[0-9a-f]{32}\.bin", name) for name in names)


def test_a_blob_round_trips_and_leaves_nothing_else_behind(
    storage: BlobStorage, root: Path
) -> None:
    name = new_blob_name()

    storage.write(name, DATA)

    assert storage.read(name, expected_size=len(DATA)) == DATA
    assert listing(root) == [name]


def test_the_directory_is_not_created_until_it_is_needed(root: Path) -> None:
    storage = BlobStorage(root)

    assert not root.exists()
    with pytest.raises(BlobIntegrityError):
        storage.read(new_blob_name(), expected_size=1)
    storage.delete(new_blob_name())
    assert not root.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_the_directory_is_private_to_the_service_user(storage: BlobStorage, root: Path) -> None:
    storage.write(new_blob_name(), DATA)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_a_failed_rename_leaves_no_temp_file_and_no_blob(
    storage: BlobStorage, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise OSError("disk exploded")

    monkeypatch.setattr(os, "replace", refuse)

    with pytest.raises(StorageError):
        storage.write(new_blob_name(), DATA)

    assert listing(root) == []


def test_a_failed_write_leaves_no_temp_file_and_no_blob(
    storage: BlobStorage, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", refuse)

    with pytest.raises(StorageError):
        storage.write(new_blob_name(), DATA)

    assert listing(root) == []


def test_an_unexpected_error_still_removes_the_temp_file(
    storage: BlobStorage, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(*_: object, **__: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", crash)

    with pytest.raises(KeyboardInterrupt):
        storage.write(new_blob_name(), DATA)

    assert listing(root) == []


def test_an_existing_blob_is_never_overwritten(storage: BlobStorage, root: Path) -> None:
    name = new_blob_name()
    storage.write(name, DATA)

    with pytest.raises(StorageError):
        storage.write(name, b"other bytes!" * 10)

    assert storage.read(name, expected_size=len(DATA)) == DATA
    assert listing(root) == [name]


@pytest.mark.parametrize(
    "name",
    [
        "",
        "../" + "0" * 32 + ".bin",
        "..\\" + "0" * 32 + ".bin",
        "/" + "0" * 31 + ".bin",
        "C:\\" + "0" * 32 + ".bin",
        "0" * 32,
        "0" * 32 + ".BIN",
        "0" * 32 + ".bin\n",
        "0" * 32 + ".bin/",
        "0" * 31 + ".bin",
        "0" * 33 + ".bin",
        "G" * 32 + ".bin",
        "A" * 32 + ".bin",
        "0" * 32 + ".bin\x00",
        "0" * 32 + ".bin.tmp",
        ".tmp-" + "0" * 27 + ".bin",
        "sub/" + "0" * 32 + ".bin",
        "%2e%2e%2f" + "0" * 23 + ".bin",
    ],
)
def test_invalid_blob_names_are_refused_on_every_access(storage: BlobStorage, name: str) -> None:
    with pytest.raises(StorageError):
        storage.write(name, DATA)
    with pytest.raises(StorageError):
        storage.read(name, expected_size=len(DATA))
    with pytest.raises(StorageError):
        storage.delete(name)


def test_a_missing_blob_is_an_integrity_failure(storage: BlobStorage) -> None:
    with pytest.raises(BlobIntegrityError):
        storage.read(new_blob_name(), expected_size=10)


@pytest.mark.parametrize("delta", [-1, 1, -16, 100])
def test_a_blob_of_the_wrong_size_is_an_integrity_failure(storage: BlobStorage, delta: int) -> None:
    name = new_blob_name()
    storage.write(name, DATA)

    with pytest.raises(BlobIntegrityError):
        storage.read(name, expected_size=len(DATA) + delta)


def test_a_directory_in_place_of_a_blob_is_an_integrity_failure(
    storage: BlobStorage, root: Path
) -> None:
    name = new_blob_name()
    root.mkdir(parents=True)
    (root / name).mkdir()

    with pytest.raises(BlobIntegrityError):
        storage.read(name, expected_size=0)


def test_a_symlink_in_place_of_a_blob_is_never_followed(storage: BlobStorage, root: Path) -> None:
    secret = root.parent / "outside.txt"
    secret.write_bytes(DATA)
    name = new_blob_name()
    root.mkdir(parents=True)
    try:
        (root / name).symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("this account may not create symbolic links")

    with pytest.raises(BlobIntegrityError):
        storage.read(name, expected_size=len(DATA))


def test_deleting_is_idempotent(storage: BlobStorage, root: Path) -> None:
    name = new_blob_name()
    storage.write(name, DATA)

    storage.delete(name)
    storage.delete(name)
    storage.delete(new_blob_name())

    assert listing(root) == []


def test_a_blob_that_cannot_be_deleted_is_a_storage_error(
    storage: BlobStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = new_blob_name()
    storage.write(name, DATA)

    def locked(*_: object) -> None:
        raise PermissionError("in use")

    monkeypatch.setattr(os, "unlink", locked)

    with pytest.raises(StorageError):
        storage.delete(name)


def test_an_unusable_storage_directory_is_a_storage_error(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"file")

    with pytest.raises(StorageError):
        BlobStorage(blocker / "blobs").write(new_blob_name(), DATA)

"""Where ciphertext lives: one flat directory of randomly named blobs.

Only ciphertext is ever written, and only after it was produced in memory, so plaintext never
touches the disk (not even briefly, not even in a temp file). Names are generated here and
re-validated on every access; they never contain user input. Writes are atomic: a reader sees
the whole blob or none of it, and a failed write leaves nothing behind.
"""

import logging
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path

logger = logging.getLogger("cipherforge.files")

_NAME_PATTERN = re.compile(r"[0-9a-f]{32}\.bin")
_TEMP_PREFIX = ".tmp-"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class StorageError(Exception):
    """The storage could not be used (permissions, full disk, ...). Not a statement about data."""


class BlobIntegrityError(Exception):
    """The blob is missing or is not the regular file of the size that was stored."""


def new_blob_name() -> str:
    return secrets.token_hex(16) + ".bin"


def _is_link(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


class BlobStorage:
    def __init__(self, root: Path) -> None:
        # Nothing touches the disk until the first read or write, so an application without a
        # configured master key never creates the directory.
        self._configured_root = root
        self._root: Path | None = None

    def _resolved_root(self) -> Path:
        if self._root is None:
            self._root = self._configured_root.resolve()
        return self._root

    def _blob_path(self, name: str) -> Path:
        if _NAME_PATTERN.fullmatch(name) is None:
            raise StorageError("Invalid blob name.")
        root = self._resolved_root()
        path = root / name
        # The pattern already excludes separators; this keeps the invariant explicit.
        if path.parent != root:
            raise StorageError("Blob path escapes the storage directory.")
        return path

    def _ensure_root(self) -> Path:
        root = self._resolved_root()
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix":
                mode = stat.S_IMODE(root.stat().st_mode)
                if mode & 0o077:
                    try:
                        root.chmod(0o700)
                    except OSError:
                        logger.warning("storage_directory_permissive")
        except OSError as exc:
            raise StorageError("Storage directory unavailable.") from exc
        return root

    def write(self, name: str, data: bytes) -> None:
        """Store ``data`` atomically under ``name``. A failure leaves no file behind."""
        path = self._blob_path(name)
        root = self._ensure_root()
        temp_path: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(dir=root, prefix=_TEMP_PREFIX)
            temp_path = Path(temp_name)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if os.path.lexists(path):
                raise StorageError("Blob already exists.")
            os.replace(temp_path, path)
            temp_path = None
            self._sync_directory(root)
        except OSError as exc:
            raise StorageError("Could not write the blob.") from exc
        finally:
            if temp_path is not None:
                self._discard(temp_path)

    @staticmethod
    def _sync_directory(root: Path) -> None:
        # Make the rename durable. Directories cannot be opened on Windows; best effort only.
        if os.name != "posix":
            return
        try:
            fd = os.open(root, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            logger.debug("directory_sync_failed")
        finally:
            os.close(fd)

    @staticmethod
    def _discard(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("temp_file_cleanup_failed")

    def read(self, name: str, *, expected_size: int) -> bytes:
        """The blob's bytes. Raises BlobIntegrityError unless it is a regular, non-link file of
        exactly ``expected_size`` bytes (and StorageError for I/O problems that say nothing about
        the data itself)."""
        path = self._blob_path(name)
        try:
            before = os.lstat(path)
        except FileNotFoundError:
            raise BlobIntegrityError("Blob is missing.") from None
        except OSError as exc:
            raise StorageError("Could not inspect the blob.") from exc
        if _is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise BlobIntegrityError("Blob has an unexpected type or size.")

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            raise BlobIntegrityError("Blob is missing.") from None
        except OSError as exc:
            raise StorageError("Could not open the blob.") from exc
        try:
            with os.fdopen(fd, "rb") as handle:
                after = os.fstat(handle.fileno())
                same_file = (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
                if (
                    not stat.S_ISREG(after.st_mode)
                    or after.st_size != expected_size
                    or (os.name == "posix" and not same_file)
                ):
                    raise BlobIntegrityError("Blob changed while it was opened.")
                data = handle.read(expected_size + 1)
        except OSError as exc:
            raise StorageError("Could not read the blob.") from exc
        if len(data) != expected_size:
            raise BlobIntegrityError("Blob has an unexpected size.")
        return data

    def delete(self, name: str) -> None:
        """Remove the blob. Idempotent: a missing blob is not an error."""
        path = self._blob_path(name)
        try:
            os.unlink(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StorageError("Could not delete the blob.") from exc

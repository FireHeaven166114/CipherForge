"""Capture files: display names, the structure check, uploads, the spool, analysis and the runner.

Everything here is hostile-input territory: the bytes, the name and the length fields all come from
the client, so the tests lean on malformed files, lying length fields and failures part-way.
"""

import asyncio
import functools
import logging
import os
import threading
import time
import unicodedata
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import ClientDisconnect

from app.core.config import Settings
from app.core.errors import ApiError
from app.database.session import build_engine, build_session_factory
from app.models.enums import CaptureSource, CaptureStatus
from app.network import pcap as pcap_module
from app.network.pcap import (
    ALLOWED_EXTENSIONS,
    BATCH_SIZE,
    AnalysisOutcome,
    CaptureFile,
    InvalidCaptureError,
    PcapRunner,
    ReceivedUpload,
    UploadSpool,
    analyze_file,
    display_name,
    inspect_capture,
    receive_upload,
)
from app.network.scapy_support import CaptureLibraryMissingError
from tests.network_helpers import (
    HOST,
    SCAN_FLOWS,
    SCAN_FRAMES,
    SCANNER,
    SERVER,
    T0,
    FakeClock,
    RecordingMonitor,
    assert_no_module_threads,
    build_rig,
    classic_pcap,
    pcap_record_header,
    pcapng_block,
    pcapng_file,
    scan_frames,
    scan_traffic,
    scapy_syn,
    wait_until,
    write_scan_capture,
)
from tests.network_helpers import MonitorRig as Rig

SessionFactory = sessionmaker[Session]

# Bytes that stand in for a frame where only the structure of the file matters.
FILLER = b"\x00" * 60
CLASSIC_RECORD = 16 + len(FILLER)
NG_PACKET_BLOCK = 12 + 20 + len(FILLER)
MIB = 1024 * 1024
LIMIT = MIB


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


@pytest.fixture
def rig(factory: SessionFactory, make_settings: Callable[..., Settings], db_url: str) -> Rig:
    settings = make_settings(database_url=db_url)
    return build_rig(factory, settings, stream_time=True, source=CaptureSource.PCAP)


@pytest.fixture
def spool(tmp_path: Path) -> Iterator[UploadSpool]:
    base = tmp_path / "spool"
    base.mkdir()
    instance = UploadSpool(base)
    yield instance
    instance.close()


def stored(tmp_path: Path, data: bytes, name: str = "capture.pcap") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@functools.cache
def syn_frame() -> bytes:
    return bytes(scapy_syn(T0, SCANNER, SERVER, 80))


def classic(count: int = 3, **options: Any) -> bytes:
    return classic_pcap([(T0 + index, FILLER) for index in range(count)], **options)


def ng(count: int = 3, **options: Any) -> bytes:
    return pcapng_file([(T0 + index, FILLER) for index in range(count)], **options)


# --- display_name ----------------------------------------------------------------------------


def refused_name(raw: str | None) -> ApiError:
    with pytest.raises(ApiError) as caught:
        display_name(raw)
    assert (caught.value.status_code, caught.value.code) == (422, "invalid_filename")
    return caught.value


ACCEPTED_NAMES = [
    ("capture.pcap", "capture.pcap"),
    ("capture.pcapng", "capture.pcapng"),
    ("legacy.cap", "legacy.cap"),
    ("UPPER.PCAP", "UPPER.PCAP"),
    ("Mixed.PcApNg", "Mixed.PcApNg"),
    ("my%20capture%20%281%29.pcap", "my capture (1).pcap"),
    ("a+b.pcap", "a+b.pcap"),
    ("two.dots.in.the.name.pcap", "two.dots.in.the.name.pcap"),
    ("a%252Fb.pcap", "a%2Fb.pcap"),
    ("%20%20padded.pcap%20", "padded.pcap"),
    ("caf%C3%A9.pcap", "caf\u00e9.pcap"),
    ("%E6%97%A5%E6%9C%AC.pcap", "\u65e5\u672c.pcap"),
    ("inv%E2%80%8Boice%E2%80%AE.pcap", "invoice.pcap"),
]


@pytest.mark.parametrize(("raw", "expected"), ACCEPTED_NAMES)
def test_a_name_is_decoded_once_and_kept_for_display(raw: str, expected: str) -> None:
    assert display_name(raw) == expected


def test_a_name_is_normalised_to_nfc() -> None:
    decomposed = display_name("cafe%CC%81.pcap")
    assert decomposed == "caf\u00e9.pcap"
    assert unicodedata.is_normalized("NFC", decomposed)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("..%5Cwindows%5Csystem32%5Cx.pcap", "x.pcap"),
        ("..\\..\\x.pcap", "x.pcap"),
        ("../../etc/passwd.pcap", "passwd.pcap"),
        ("%2E%2E%2F%2E%2E%2Fsecret.pcap", "secret.pcap"),
        ("%2Fetc%2Fshadow.pcap", "shadow.pcap"),
        ("/absolute/path/name.pcap", "name.pcap"),
        ("C:%5Cusers%5Cpublic%5Cx.pcap", "x.pcap"),
        ("C:\\x.pcapng", "x.pcapng"),
        ("\\\\server\\share\\x.pcap", "x.pcap"),
        ("a/./b/../c.pcap", "c.pcap"),
    ],
)
def test_only_the_last_path_component_survives(raw: str, expected: str) -> None:
    assert display_name(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a%00b.pcap", "ab.pcap"),
        ("tab%09bed.pcap", "tabbed.pcap"),
        ("x%0D%0AInjected-Header: 1.pcap", "xInjected-Header: 1.pcap"),
        ("x.txt%00.pcap", "x.txt.pcap"),
    ],
)
def test_control_characters_are_dropped(raw: str, expected: str) -> None:
    assert display_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "%20",
        "%00",
        "%7F",
        "x",
        "pcap",
        ".pcap",
        ".pcapng",
        ".cap",
        ".",
        "..",
        "a/..",
        "dir/",
        "dir\\",
        "dir%2F",
        "%2E%2E",
        "report.txt",
        "report.pcap.txt",
        "report.pcap.exe",
        "report.pcapx",
        "report.zip",
        "report.pcap.gz",
        "x.pcap%00.txt",
        "%FF.pcap",
        "%C3.pcap",
        "%E0%A4%A.pcap",
        "a" * 1020 + ".pcap",
    ],
    ids=repr,
)
def test_names_without_a_capture_extension_or_a_usable_name_are_refused(raw: str | None) -> None:
    refused_name(raw)


def test_a_refusal_never_echoes_the_name() -> None:
    for raw in ("hunter2-secret.txt", "%FF-hunter2.pcap", "hunter2" * 200 + ".pcap"):
        error = refused_name(raw)
        assert "hunter2" not in str(error.detail)


@pytest.mark.parametrize(
    "raw", ["CON.pcap", "prn.pcap", "AUX.pcapng", "nul.cap", "COM1.pcap", "LPT9.pcap"]
)
def test_reserved_device_names_are_harmless_because_a_name_is_only_displayed(raw: str) -> None:
    assert display_name(raw) == raw


def test_long_names_are_shortened_but_keep_their_extension() -> None:
    assert display_name("a" * 115 + ".pcap") == "a" * 115 + ".pcap"
    assert display_name("a" * 116 + ".pcap") == "a" * 115 + ".pcap"
    shortened = display_name("b" * 500 + ".PCAPNG")
    assert len(shortened) == 120
    assert shortened.endswith(".PCAPNG")
    assert display_name("c" * 1019 + ".pcap") == "c" * 115 + ".pcap"


def test_whatever_the_input_the_result_is_a_plain_capture_name() -> None:
    hostile = [
        "..%2F..%2Fx.pcap",
        "a%00%1F%7F%C2%85b.pcap",
        "%E2%80%AEgnp.exe.pcap",
        "dir%5Cdir%5Cx%00.pcap%20",
        "\u202e\u0000x.pcapng",
        "x" * 300 + ".cap",
        "\ufeffbom.pcap",
        "line%0Abreak.pcap",
    ]
    for raw in hostile:
        name = display_name(raw)
        assert "/" not in name
        assert "\\" not in name
        assert not any(unicodedata.category(char) in {"Cc", "Cf"} for char in name)
        assert name.lower().endswith(ALLOWED_EXTENSIONS)
        assert 0 < len(name) <= 120


# --- inspect_capture: classic files ----------------------------------------------------------


def inspected(tmp_path: Path, data: bytes) -> CaptureFile:
    return inspect_capture(stored(tmp_path, data))


def invalid(tmp_path: Path, data: bytes) -> None:
    with pytest.raises(InvalidCaptureError):
        inspect_capture(stored(tmp_path, data))


@pytest.mark.parametrize(
    ("endian", "nano", "magic"),
    [
        ("<", False, "d4c3b2a1"),
        (">", False, "a1b2c3d4"),
        ("<", True, "4d3cb2a1"),
        (">", True, "a1b23c4d"),
    ],
    ids=["little", "big", "little-nano", "big-nano"],
)
def test_a_classic_file_is_recognised_by_its_magic_number(
    tmp_path: Path, endian: str, nano: bool, magic: str
) -> None:
    data = classic(endian=endian, nano=nano)
    assert data[:4].hex() == magic
    assert inspected(tmp_path, data) == CaptureFile("pcap", 3, False)


def test_a_classic_file_with_only_its_header_has_no_packets(tmp_path: Path) -> None:
    assert inspected(tmp_path, classic(0)) == CaptureFile("pcap", 0, False)


@pytest.mark.parametrize("cut", [1, 30, 59, 60, 61, 75])
def test_a_classic_file_cut_inside_its_last_record_keeps_the_complete_ones(
    tmp_path: Path, cut: int
) -> None:
    assert inspected(tmp_path, classic()[:-cut]) == CaptureFile("pcap", 2, True)


def test_a_cut_on_a_record_boundary_is_not_truncation(tmp_path: Path) -> None:
    assert inspected(tmp_path, classic()[:-CLASSIC_RECORD]) == CaptureFile("pcap", 2, False)


def test_stray_bytes_after_the_last_record_count_as_truncation(tmp_path: Path) -> None:
    assert inspected(tmp_path, classic() + b"\x01\x02\x03") == CaptureFile("pcap", 3, True)


def test_a_record_claiming_one_byte_too_many_ends_the_count(tmp_path: Path) -> None:
    lying = classic(2) + pcap_record_header(len(FILLER) + 1) + FILLER
    assert inspected(tmp_path, lying) == CaptureFile("pcap", 2, True)
    honest = classic(2) + pcap_record_header(len(FILLER)) + FILLER
    assert inspected(tmp_path, honest) == CaptureFile("pcap", 3, False)


@pytest.mark.parametrize("claimed", [1 << 24, (1 << 24) + 1, 0x7FFFFFFF, 0xFFFFFFFF])
def test_a_hostile_record_length_never_reaches_a_reader(tmp_path: Path, claimed: int) -> None:
    data = classic(1) + pcap_record_header(claimed) + FILLER
    assert inspected(tmp_path, data) == CaptureFile("pcap", 1, True)


def test_a_file_whose_first_record_is_hostile_is_invalid(tmp_path: Path) -> None:
    invalid(tmp_path, classic(0) + pcap_record_header(0xFFFFFFFF) + FILLER)


def test_a_lying_big_endian_length_is_read_in_the_right_byte_order(tmp_path: Path) -> None:
    lying = classic(1, endian=">") + pcap_record_header(0xFFFFFFFF, endian=">") + FILLER
    assert inspected(tmp_path, lying) == CaptureFile("pcap", 1, True)


def test_records_without_bytes_are_still_records(tmp_path: Path) -> None:
    data = classic_pcap([(T0, b"")] * 20_000)
    assert inspected(tmp_path, data) == CaptureFile("pcap", 20_000, False)


@pytest.mark.parametrize("version", [(3, 0), (1, 4), (0, 0), (2, 100), (2, 65535)])
def test_an_unsupported_classic_version_is_invalid(
    tmp_path: Path, version: tuple[int, int]
) -> None:
    invalid(tmp_path, classic(version=version))


@pytest.mark.parametrize("version", [(2, 0), (2, 4), (2, 99)])
def test_the_supported_classic_versions_are_accepted(
    tmp_path: Path, version: tuple[int, int]
) -> None:
    assert inspected(tmp_path, classic(version=version)).packets == 3


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00",
        b"\xd4\xc3\xb2\xa1" + b"\x00" * 7,
        b"\xd4\xc3\xb2\xa1" + b"\x00" * 8,
        b"\xd4\xc3\xb2\xa1" + b"\x00" * 19,
        b"\x00" * 64,
        b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n" + b"\x00" * 40,
        b"PK\x03\x04" + b"\x00" * 60,
        b"MZ" + b"\x90" * 100,
        bytes(range(256)),
        b"\x0a\x0d\x0d\x0a" + b"\x00" * 60,
    ],
    ids=[
        "empty",
        "one-byte",
        "eleven-bytes",
        "twelve-bytes",
        "short-header",
        "zeros",
        "http",
        "zip",
        "executable",
        "ramp",
        "section-header-without-byte-order",
    ],
)
def test_bytes_that_are_not_a_capture_are_invalid(tmp_path: Path, data: bytes) -> None:
    invalid(tmp_path, data)


def test_a_header_followed_by_less_than_a_record_is_invalid(tmp_path: Path) -> None:
    invalid(tmp_path, classic(0) + b"\x01" * 15)
    invalid(tmp_path, classic(0) + pcap_record_header(5) + b"abc")


def test_a_header_is_not_enough_when_a_garbage_record_follows(tmp_path: Path) -> None:
    invalid(tmp_path, classic(0) + b"\xff" * 40)


def test_a_path_that_is_not_a_file_is_not_a_capture(tmp_path: Path) -> None:
    with pytest.raises(InvalidCaptureError):
        inspect_capture(tmp_path / "missing.pcap")
    with pytest.raises(InvalidCaptureError):
        inspect_capture(tmp_path)


def test_the_file_is_released_after_the_check(tmp_path: Path) -> None:
    path = stored(tmp_path, classic())
    inspect_capture(path)
    path.unlink()
    assert not path.exists()
    failed = stored(tmp_path, b"not a capture at all", "bad.pcap")
    with pytest.raises(InvalidCaptureError):
        inspect_capture(failed)
    failed.unlink()


# --- inspect_capture: PCAPNG files -----------------------------------------------------------


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little", "big"])
def test_a_pcapng_file_is_recognised_in_either_byte_order(tmp_path: Path, endian: str) -> None:
    assert inspected(tmp_path, ng(endian=endian)) == CaptureFile("pcapng", 3, False)


def test_the_format_follows_the_content_and_not_the_name(tmp_path: Path) -> None:
    path = stored(tmp_path, ng(), "really-pcapng.pcap")
    assert inspect_capture(path).format == "pcapng"
    path = stored(tmp_path, classic(), "really-classic.pcapng")
    assert inspect_capture(path).format == "pcap"


def test_simple_and_obsolete_packet_blocks_count_and_other_blocks_do_not(tmp_path: Path) -> None:
    assert inspected(tmp_path, ng(simple=True)) == CaptureFile("pcapng", 3, False)
    extras = (
        pcapng_block(2, b"\x00" * 20)
        + pcapng_block(4, b"\x00" * 8)
        + pcapng_block(5, b"\x00" * 20)
        + pcapng_block(0x40000BAD, b"\x00" * 8)
    )
    assert inspected(tmp_path, ng(2) + extras) == CaptureFile("pcapng", 3, False)


def test_a_pcapng_file_without_packets_is_valid(tmp_path: Path) -> None:
    assert inspected(tmp_path, ng(0)) == CaptureFile("pcapng", 0, False)


@pytest.mark.parametrize("cut", [1, 4, 11, 12, 40, 80, 91])
def test_a_pcapng_file_cut_inside_its_last_block_keeps_the_complete_ones(
    tmp_path: Path, cut: int
) -> None:
    assert inspected(tmp_path, ng()[:-cut]) == CaptureFile("pcapng", 2, True)


def test_a_pcapng_cut_on_a_block_boundary_is_not_truncation(tmp_path: Path) -> None:
    assert inspected(tmp_path, ng()[:-NG_PACKET_BLOCK]) == CaptureFile("pcapng", 2, False)


def test_a_block_whose_trailing_length_disagrees_ends_the_count(tmp_path: Path) -> None:
    damaged = bytearray(ng())
    damaged[-4:] = (NG_PACKET_BLOCK + 4).to_bytes(4, "little")
    assert inspected(tmp_path, bytes(damaged)) == CaptureFile("pcapng", 2, True)


@pytest.mark.parametrize("length", [0, 4, 8, 11, 13, NG_PACKET_BLOCK + 1, 0xFFFFFFFC, 0xFFFFFFFF])
def test_a_hostile_block_length_ends_the_count(tmp_path: Path, length: int) -> None:
    damaged = bytearray(ng())
    start = len(damaged) - NG_PACKET_BLOCK
    damaged[start + 4 : start + 8] = length.to_bytes(4, "little")
    assert inspected(tmp_path, bytes(damaged)) == CaptureFile("pcapng", 2, True)


def test_a_file_whose_first_packet_block_is_damaged_is_invalid(tmp_path: Path) -> None:
    damaged = bytearray(ng(1))
    start = len(damaged) - NG_PACKET_BLOCK
    damaged[start + 4 : start + 8] = (0xFFFFFFFC).to_bytes(4, "little")
    invalid(tmp_path, bytes(damaged))


@pytest.mark.parametrize("version", [(2, 0), (0, 1), (1, 0)])
def test_only_pcapng_major_version_one_is_accepted(
    tmp_path: Path, version: tuple[int, int]
) -> None:
    data = ng(version=version)
    if version[0] == 1:
        assert inspected(tmp_path, data).packets == 3
    else:
        invalid(tmp_path, data)


def test_a_cut_section_header_is_invalid(tmp_path: Path) -> None:
    invalid(tmp_path, ng()[:20])
    invalid(tmp_path, ng()[:27])


def test_sections_in_different_byte_orders_are_all_counted(tmp_path: Path) -> None:
    both = ng(2, endian="<") + ng(1, endian=">")
    assert inspected(tmp_path, both) == CaptureFile("pcapng", 3, False)


def test_a_second_section_with_a_bad_byte_order_ends_the_count(tmp_path: Path) -> None:
    broken = bytearray(ng(1))
    broken[8:12] = b"\x00\x00\x00\x00"
    assert inspected(tmp_path, ng(2) + bytes(broken)) == CaptureFile("pcapng", 2, True)


def test_garbage_after_valid_blocks_is_truncation(tmp_path: Path) -> None:
    assert inspected(tmp_path, ng() + b"\xff" * 33) == CaptureFile("pcapng", 3, True)


# --- UploadSpool -----------------------------------------------------------------------------


def test_the_spool_makes_one_private_directory_when_first_needed(tmp_path: Path) -> None:
    spool = UploadSpool(tmp_path)
    assert list(tmp_path.iterdir()) == []
    directory = spool.directory()
    try:
        assert directory.parent == tmp_path
        assert directory.name.startswith("cipherforge-pcap-")
        assert spool.directory() == directory
        if os.name == "posix":
            assert directory.stat().st_mode & 0o777 == 0o700
    finally:
        spool.close()


def test_a_directory_removed_behind_its_back_is_made_again(tmp_path: Path) -> None:
    spool = UploadSpool(tmp_path)
    first = spool.directory()
    first.rmdir()
    second = spool.directory()
    try:
        assert second.is_dir()
    finally:
        spool.close()


def test_spool_files_have_random_names_that_say_nothing_about_the_upload(
    spool: UploadSpool,
) -> None:
    paths = [spool.new_file() for _ in range(50)]
    assert len(set(paths)) == 50
    for path in paths:
        assert path.parent == spool.directory()
        assert path.suffix == ".upload"
        assert len(path.stem) == 32
        assert int(path.stem, 16) >= 0
        assert not path.exists()


def test_remove_deletes_a_file_and_forgives_everything_else(spool: UploadSpool) -> None:
    path = spool.new_file()
    path.write_bytes(b"x")
    spool.remove(path)
    assert not path.exists()
    spool.remove(path)
    spool.remove(spool.directory() / "missing-parent" / "nothing")
    folder = spool.directory() / "folder"
    folder.mkdir()
    spool.remove(folder)
    assert folder.is_dir()


def test_close_removes_the_directory_and_what_is_in_it(tmp_path: Path) -> None:
    spool = UploadSpool(tmp_path)
    directory = spool.directory()
    (directory / "left-behind.upload").write_bytes(b"x")
    spool.close()
    assert not directory.exists()
    spool.close()
    assert list(tmp_path.iterdir()) == []


def test_a_spool_that_was_never_used_closes_without_a_trace(tmp_path: Path) -> None:
    UploadSpool(tmp_path).close()
    assert list(tmp_path.iterdir()) == []


def test_a_closed_spool_can_be_used_again(tmp_path: Path) -> None:
    spool = UploadSpool(tmp_path)
    first = spool.directory()
    spool.close()
    second = spool.directory()
    try:
        assert second.is_dir()
        assert not first.exists() or first != second
    finally:
        spool.close()


def age(path: Path, seconds: float) -> None:
    moment = time.time() - seconds
    os.utime(path, (moment, moment))


def test_purge_stale_removes_only_old_spool_directories(tmp_path: Path) -> None:
    old = tmp_path / "cipherforge-pcap-old"
    old.mkdir()
    (old / "stale.upload").write_bytes(b"x")
    fresh = tmp_path / "cipherforge-pcap-fresh"
    fresh.mkdir()
    unrelated = tmp_path / "somebody-elses-directory"
    unrelated.mkdir()
    plain_file = tmp_path / "cipherforge-pcap-a-file"
    plain_file.write_bytes(b"x")
    for item in (old, unrelated, plain_file):
        age(item, 3 * 24 * 3600)
    assert UploadSpool(tmp_path).purge_stale() == 1
    assert not old.exists()
    assert fresh.is_dir()
    assert unrelated.is_dir()
    assert plain_file.is_file()


def test_purge_stale_honours_the_age_it_is_given(tmp_path: Path) -> None:
    middling = tmp_path / "cipherforge-pcap-middling"
    middling.mkdir()
    age(middling, 600)
    spool = UploadSpool(tmp_path)
    assert spool.purge_stale(max_age=3600) == 0
    assert middling.is_dir()
    assert spool.purge_stale(max_age=60) == 1
    assert not middling.exists()


def test_purge_stale_does_not_follow_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "precious"
    target.mkdir()
    (target / "keep.txt").write_bytes(b"x")
    age(target, 3 * 24 * 3600)
    link = tmp_path / "cipherforge-pcap-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    assert UploadSpool(tmp_path).purge_stale() == 0
    assert (target / "keep.txt").is_file()
    assert link.is_symlink()


def test_purge_stale_of_a_missing_base_is_zero(tmp_path: Path) -> None:
    assert UploadSpool(tmp_path / "does-not-exist").purge_stale() == 0


def test_purge_stale_without_a_base_looks_in_the_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pcap_module.tempfile, "gettempdir", lambda: str(tmp_path))
    old = tmp_path / "cipherforge-pcap-crashed"
    old.mkdir()
    age(old, 3 * 24 * 3600)
    assert UploadSpool().purge_stale() == 1
    assert not old.exists()


# --- receive_upload --------------------------------------------------------------------------


async def stream(*chunks: bytes) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk


def receive(
    chunks: AsyncIterator[bytes], spool: UploadSpool, max_bytes: int = LIMIT
) -> ReceivedUpload:
    return asyncio.run(receive_upload(chunks, spool=spool, max_bytes=max_bytes))


def spooled(spool: UploadSpool) -> list[Path]:
    return sorted(spool.directory().iterdir())


def pieces(data: bytes, size: int) -> list[bytes]:
    return [data[index : index + size] for index in range(0, len(data), size)]


@pytest.mark.parametrize(
    ("length", "size"),
    [
        (5_000, 1),
        (5_000, 7),
        (700_001, 4096),
        (700_001, 262_143),
        (700_001, 262_144),
        (700_001, 262_145),
        (700_001, 700_001),
        (700_001, 1_000_000),
    ],
)
def test_an_upload_is_stored_exactly_as_received_whatever_the_chunking(
    spool: UploadSpool, length: int, size: int
) -> None:
    data = (bytes(range(251)) * (length // 251 + 1))[:length]
    upload = receive(stream(*pieces(data, size)), spool)
    assert upload.size == length
    assert upload.path.read_bytes() == data
    assert upload.path.parent == spool.directory()
    assert upload.path.suffix == ".upload"
    assert spooled(spool) == [upload.path]
    upload.path.unlink()


def test_the_stored_file_is_closed_and_private(spool: UploadSpool) -> None:
    upload = receive(stream(b"x" * 1000), spool)
    if os.name == "posix":
        assert upload.path.stat().st_mode & 0o777 == 0o600
    upload.path.unlink()
    assert spooled(spool) == []


def test_the_limit_itself_is_accepted_and_one_byte_more_is_refused(spool: UploadSpool) -> None:
    exact = receive(stream(b"x" * 400_000, b"y" * 400_000, b"z" * (LIMIT - 800_000)), spool)
    assert exact.size == LIMIT
    exact.path.unlink()
    with pytest.raises(ApiError) as caught:
        receive(stream(b"x" * 400_000, b"y" * 400_000, b"z" * (LIMIT - 800_000 + 1)), spool)
    assert (caught.value.status_code, caught.value.code) == (413, "file_too_large")
    assert spooled(spool) == []


def test_the_limit_is_enforced_mid_stream_and_the_partial_file_removed(spool: UploadSpool) -> None:
    requested: list[int] = []
    on_disk: list[int] = []

    async def endless() -> AsyncIterator[bytes]:
        for index in range(100):
            requested.append(index)
            if index == 3:
                on_disk.extend(path.stat().st_size for path in spool.directory().iterdir())
            yield b"x" * (300 * 1024)

    with pytest.raises(ApiError) as caught:
        receive(endless(), spool)
    assert (caught.value.status_code, caught.value.code) == (413, "file_too_large")
    assert "1 MB" in str(caught.value.detail)
    assert str(spool.directory()) not in str(caught.value.detail)
    assert requested == [0, 1, 2, 3]
    assert on_disk == [900 * 1024]
    assert spooled(spool) == []


def test_one_chunk_over_the_limit_is_refused_before_anything_is_written(
    spool: UploadSpool,
) -> None:
    with pytest.raises(ApiError) as caught:
        receive(stream(b"x" * (LIMIT + 1)), spool)
    assert caught.value.code == "file_too_large"
    assert spooled(spool) == []


@pytest.mark.parametrize("chunks", [(), (b"",), (b"", b"", b"")], ids=["none", "one", "three"])
def test_an_empty_body_is_refused_and_leaves_nothing(
    spool: UploadSpool, chunks: tuple[bytes, ...]
) -> None:
    with pytest.raises(ApiError) as caught:
        receive(stream(*chunks), spool)
    assert (caught.value.status_code, caught.value.code) == (422, "invalid_capture_file")
    assert spooled(spool) == []


@pytest.mark.parametrize(
    "error", [ClientDisconnect(), RuntimeError("stream broke"), OSError("reset")], ids=repr
)
def test_a_stream_that_fails_leaves_no_partial_file(
    spool: UploadSpool, error: BaseException
) -> None:
    on_disk: list[int] = []

    async def failing() -> AsyncIterator[bytes]:
        yield b"x" * (300 * 1024)
        on_disk.extend(path.stat().st_size for path in spool.directory().iterdir())
        raise error

    with pytest.raises(type(error)):
        receive(failing(), spool)
    assert on_disk == [300 * 1024]
    assert spooled(spool) == []


def test_a_cancelled_upload_leaves_no_partial_file(spool: UploadSpool) -> None:
    async def stalled() -> AsyncIterator[bytes]:
        yield b"x" * (300 * 1024)
        await asyncio.sleep(30)
        yield b"never sent"

    async def attempt() -> None:
        await asyncio.wait_for(receive_upload(stalled(), spool=spool, max_bytes=LIMIT), 0.25)

    with pytest.raises(TimeoutError):
        asyncio.run(attempt())
    assert spooled(spool) == []


def test_concurrent_uploads_never_share_a_file(spool: UploadSpool) -> None:
    payloads = [bytes([index]) * (50_000 + index) for index in range(8)]

    async def everything() -> list[ReceivedUpload]:
        return await asyncio.gather(
            *(
                receive_upload(stream(*pieces(data, 9_000)), spool=spool, max_bytes=LIMIT)
                for data in payloads
            )
        )

    uploads = asyncio.run(everything())
    assert len({upload.path for upload in uploads}) == 8
    assert [upload.path.read_bytes() for upload in uploads] == payloads
    for upload in uploads:
        upload.path.unlink()


# --- analyze_file ----------------------------------------------------------------------------


def analyse(path: Path, monitor: Any, **options: Any) -> AnalysisOutcome:
    options.setdefault("cancel", threading.Event())
    return analyze_file(path, inspect_capture(path), monitor, **options)


def scan_files(tmp_path: Path) -> dict[str, Path]:
    frames = scan_frames()
    return {
        "classic": write_scan_capture(tmp_path / "scan.pcap"),
        "pcapng": write_scan_capture(tmp_path / "scan.pcapng", ng=True),
        "classic-big-endian-nano": stored(
            tmp_path, classic_pcap(frames, endian=">", nano=True), "be.pcap"
        ),
        "classic-little-endian-nano": stored(
            tmp_path, classic_pcap(frames, nano=True), "le-nano.pcap"
        ),
        "pcapng-big-endian": stored(tmp_path, pcapng_file(frames, endian=">"), "be.pcapng"),
        "pcapng-little-endian": stored(tmp_path, pcapng_file(frames), "le.pcapng"),
    }


SCAN_KINDS = [
    "classic",
    "pcapng",
    "classic-big-endian-nano",
    "classic-little-endian-nano",
    "pcapng-big-endian",
    "pcapng-little-endian",
]


@pytest.mark.parametrize("kind", SCAN_KINDS)
def test_every_supported_file_flavour_yields_the_same_packets(tmp_path: Path, kind: str) -> None:
    monitor = RecordingMonitor()
    outcome = analyse(scan_files(tmp_path)[kind], monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, None, SCAN_FRAMES)
    packets = monitor.processed
    assert len(packets) == SCAN_FRAMES - 1
    assert (monitor.non_ip, monitor.malformed) == (1, 0)
    assert [packet.timestamp for packet in packets[:30]] == pytest.approx(
        [T0 + 0.1 * index for index in range(30)], abs=1e-5
    )
    assert [packet.dst_port for packet in packets[:30]] == list(range(2000, 2030))
    assert {packet.src_ip for packet in packets[:30]} == {SCANNER}
    assert packets[-1].dst_ip == SERVER
    assert packets[-1].src_ip == HOST


def test_packets_reach_the_monitor_in_batches(tmp_path: Path) -> None:
    frames = [(T0 + index * 0.001, syn_frame()) for index in range(1100)]
    monitor = RecordingMonitor()
    outcome = analyse(stored(tmp_path, classic_pcap(frames)), monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, None, 1100)
    assert [len(batch) for batch in monitor.batches if batch] == [BATCH_SIZE, BATCH_SIZE, 76]
    assert len(monitor.processed) == 1100


def test_the_file_is_left_for_the_caller_to_remove(tmp_path: Path) -> None:
    path = write_scan_capture(tmp_path / "scan.pcap")
    analyse(path, RecordingMonitor())
    assert path.is_file()
    path.unlink()


def test_cancelling_before_the_first_record_reads_nothing(tmp_path: Path) -> None:
    cancel = threading.Event()
    cancel.set()
    monitor = RecordingMonitor()
    outcome = analyse(write_scan_capture(tmp_path / "scan.pcap"), monitor, cancel=cancel)
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "interrupted", 0)
    assert monitor.processed == []


class CancellingMonitor(RecordingMonitor):
    """Asks for the analysis to stop as soon as the first batch has been handed over."""

    def __init__(self, cancel: threading.Event) -> None:
        super().__init__()
        self.cancel = cancel

    def process_batch(self, packets: Any) -> None:
        super().process_batch(packets)
        self.cancel.set()


def test_cancelling_mid_file_stops_after_the_batch_in_hand(tmp_path: Path) -> None:
    frames = [(T0 + index * 0.001, syn_frame()) for index in range(1100)]
    cancel = threading.Event()
    monitor = CancellingMonitor(cancel)
    outcome = analyse(stored(tmp_path, classic_pcap(frames)), monitor, cancel=cancel)
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "interrupted", BATCH_SIZE)
    assert len(monitor.processed) == BATCH_SIZE


class Ticker:
    """A clock that advances one second every time it is read."""

    def __init__(self) -> None:
        self.now = -1.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def test_the_deadline_is_measured_with_the_clock_it_is_given(tmp_path: Path) -> None:
    path = write_scan_capture(tmp_path / "scan.pcap")
    monitor = RecordingMonitor()
    outcome = analyse(path, monitor, timeout=5, clock=Ticker())
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "analysis_timeout", 5)
    assert len(monitor.processed) == 5


def test_a_deadline_already_gone_reads_nothing(tmp_path: Path) -> None:
    monitor = RecordingMonitor()
    outcome = analyse(
        write_scan_capture(tmp_path / "scan.pcap"), monitor, timeout=0, clock=Ticker()
    )
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "analysis_timeout", 0)


def test_a_clock_that_stands_still_never_times_out(tmp_path: Path) -> None:
    clock = FakeClock(100.0)
    outcome = analyse(write_scan_capture(tmp_path / "scan.pcap"), RecordingMonitor(), clock=clock)
    assert outcome.status is CaptureStatus.COMPLETED


@pytest.mark.parametrize("ng_file", [False, True], ids=["classic", "pcapng"])
def test_a_file_cut_short_is_analysed_up_to_the_cut(tmp_path: Path, ng_file: bool) -> None:
    frames = scan_frames()
    whole = pcapng_file(frames) if ng_file else classic_pcap(frames)
    path = stored(tmp_path, whole[:-5], "cut.pcapng" if ng_file else "cut.pcap")
    monitor = RecordingMonitor()
    outcome = analyse(path, monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, "capture_truncated", SCAN_FRAMES - 1)
    assert len(monitor.processed) == SCAN_FRAMES - 1


def test_a_file_cut_inside_its_first_record_is_not_a_capture(tmp_path: Path) -> None:
    whole = classic_pcap(scan_frames())
    path = stored(tmp_path, whole[:60])
    with pytest.raises(InvalidCaptureError):
        inspect_capture(path)


def test_a_file_that_vanishes_before_the_analysis_fails_cleanly(tmp_path: Path) -> None:
    path = write_scan_capture(tmp_path / "scan.pcap")
    info = inspect_capture(path)
    path.unlink()
    outcome = analyze_file(path, info, RecordingMonitor(), cancel=threading.Event())
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "invalid_capture_file", 0)


def test_junk_inside_a_valid_file_is_counted_and_skipped(tmp_path: Path) -> None:
    good = syn_frame()
    frames = [
        (T0, good),
        (T0 + 1, b"\xff" * 40),
        (T0 + 2, good[:20]),
        (T0 + 3, b""),
        (T0 + 4, good[:14] + b"\x45" + b"\x00" * 30),
        (T0 + 5, good),
    ]
    monitor = RecordingMonitor()
    outcome = analyse(stored(tmp_path, classic_pcap(frames)), monitor)
    assert outcome.status is CaptureStatus.COMPLETED
    assert outcome.error_code is None
    assert outcome.records_read == 6
    assert len(monitor.processed) >= 2
    assert len(monitor.processed) + monitor.non_ip + monitor.malformed == 6


def test_packets_stamped_outside_the_plausible_years_are_counted_as_malformed(
    tmp_path: Path,
) -> None:
    frames = [(T0, syn_frame()), (1e13, syn_frame()), (T0 + 1, syn_frame())]
    monitor = RecordingMonitor()
    outcome = analyse(stored(tmp_path, pcapng_file(frames)), monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, None, 3)
    assert (len(monitor.processed), monitor.malformed) == (2, 1)
    far_future = classic_pcap([(T0, syn_frame()), (4_294_967_295.0, syn_frame())])
    monitor = RecordingMonitor()
    analyse(stored(tmp_path, far_future, "future.pcap"), monitor)
    assert (len(monitor.processed), monitor.malformed) == (1, 1)


def test_frames_of_a_link_type_nobody_knows_are_counted_as_not_ip(tmp_path: Path) -> None:
    frames = [(T0 + index, syn_frame()) for index in range(3)]
    monitor = RecordingMonitor()
    outcome = analyse(stored(tmp_path, classic_pcap(frames, linktype=999)), monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, None, 3)
    assert monitor.processed == []
    assert monitor.non_ip + monitor.malformed == 3


def test_raw_ip_captures_are_read_without_an_ethernet_header(tmp_path: Path) -> None:
    frames = [(T0 + index, syn_frame()[14:]) for index in range(3)]
    monitor = RecordingMonitor()
    outcome = analyse(stored(tmp_path, classic_pcap(frames, linktype=101)), monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, None, 3)
    assert [packet.src_ip for packet in monitor.processed] == [SCANNER] * 3
    assert monitor.processed[0].length == 40


class FakeReader:
    """What Scapy's reader looks like to ``analyze_file``: a context manager over packets that
    may stop with an error after ``fail_after`` of them."""

    def __init__(
        self, items: list[Any], *, fail_after: int | None = None, error: Exception | None = None
    ) -> None:
        self.items = items
        self.fail_after = fail_after
        self.error = error or ValueError("record is corrupt: secret-marker")
        self.pulled = 0
        self.closed = False

    def __enter__(self) -> "FakeReader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.closed = True

    def __iter__(self) -> "FakeReader":
        return self

    def __next__(self) -> Any:
        if self.fail_after is not None and self.pulled >= self.fail_after:
            raise self.error
        if self.pulled >= len(self.items):
            raise StopIteration
        self.pulled += 1
        return self.items[self.pulled - 1]


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[str]]:
    """Make ``analyze_file`` read from a fake reader. Returns the paths it was asked to open."""

    def install(reader: FakeReader | None = None, *, open_error: Exception | None = None):
        paths: list[str] = []

        def opener(path: str) -> FakeReader:
            paths.append(path)
            if open_error is not None:
                raise open_error
            assert reader is not None
            return reader

        scapy = SimpleNamespace(PcapReader=opener, PcapNgReader=opener)
        monkeypatch.setattr(pcap_module, "load_scapy", lambda: scapy)
        return paths

    return install


def run_fake(info: CaptureFile, monitor: RecordingMonitor, **options: Any) -> AnalysisOutcome:
    return analyze_file(Path("unused.pcap"), info, monitor, cancel=threading.Event(), **options)


def test_a_reader_that_fails_part_way_leaves_a_truncated_analysis(
    opened: Callable[..., list[str]], caplog: pytest.LogCaptureFixture
) -> None:
    reader = FakeReader(scan_traffic(ports=8), fail_after=3)
    paths = opened(reader)
    monitor = RecordingMonitor()
    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        outcome = run_fake(CaptureFile("pcap", 12, False), monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, "capture_truncated", 3)
    assert len(monitor.processed) == 3
    assert reader.closed
    assert paths == ["unused.pcap"]
    assert "secret-marker" not in caplog.text
    assert any(record.__dict__.get("error") == "ValueError" for record in caplog.records)


def test_a_reader_that_fails_on_the_first_record_means_an_invalid_file(
    opened: Callable[..., list[str]],
) -> None:
    reader = FakeReader(scan_traffic(ports=8), fail_after=0)
    opened(reader)
    outcome = run_fake(CaptureFile("pcap", 12, False), RecordingMonitor())
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "invalid_capture_file", 0)
    assert reader.closed


def test_a_file_that_cannot_be_opened_is_an_invalid_capture(
    opened: Callable[..., list[str]], caplog: pytest.LogCaptureFixture
) -> None:
    opened(open_error=OSError("cannot open /secret/path"))
    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        outcome = run_fake(CaptureFile("pcap", 12, False), RecordingMonitor())
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "invalid_capture_file", 0)
    assert "/secret/path" not in caplog.text


def test_the_structure_check_bounds_how_many_records_are_read(
    opened: Callable[..., list[str]],
) -> None:
    reader = FakeReader(scan_traffic(ports=8))
    opened(reader)
    monitor = RecordingMonitor()
    outcome = run_fake(CaptureFile("pcap", 3, False), monitor)
    assert outcome == AnalysisOutcome(CaptureStatus.COMPLETED, None, 3)
    assert reader.pulled == 3


def test_the_reader_is_closed_when_the_analysis_is_cancelled_or_times_out(
    opened: Callable[..., list[str]],
) -> None:
    reader = FakeReader(scan_traffic(ports=8))
    opened(reader)
    cancel = threading.Event()
    cancel.set()
    analyze_file(
        Path("unused.pcap"), CaptureFile("pcap", 12, False), RecordingMonitor(), cancel=cancel
    )
    assert reader.closed
    reader = FakeReader(scan_traffic(ports=8))
    opened(reader)
    outcome = run_fake(
        CaptureFile("pcap", 12, False), RecordingMonitor(), timeout=0, clock=Ticker()
    )
    assert outcome.error_code == "analysis_timeout"
    assert reader.closed


def test_the_reader_that_matches_the_format_is_the_one_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    used: list[str] = []

    def reader_named(name: str) -> Callable[[str], FakeReader]:
        def opener(path: str) -> FakeReader:
            used.append(name)
            return FakeReader([])

        return opener

    scapy = SimpleNamespace(PcapReader=reader_named("pcap"), PcapNgReader=reader_named("pcapng"))
    monkeypatch.setattr(pcap_module, "load_scapy", lambda: scapy)
    run_fake(CaptureFile("pcap", 0, False), RecordingMonitor())
    run_fake(CaptureFile("pcapng", 0, False), RecordingMonitor())
    assert used == ["pcap", "pcapng"]


def test_a_missing_capture_library_fails_the_analysis_without_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing() -> Any:
        raise CaptureLibraryMissingError("scapy is not installed")

    monkeypatch.setattr(pcap_module, "load_scapy", missing)
    outcome = run_fake(CaptureFile("pcap", 3, False), RecordingMonitor())
    assert outcome == AnalysisOutcome(CaptureStatus.FAILED, "analysis_failed", 0)


@pytest.mark.parametrize("ng_file", [False, True], ids=["classic", "pcapng"])
def test_a_flipped_byte_anywhere_never_crashes_the_analysis(tmp_path: Path, ng_file: bool) -> None:
    frames = scan_frames(ports=5)
    original = pcapng_file(frames) if ng_file else classic_pcap(frames)
    analysed = 0
    for offset in range(0, len(original), 3):
        mutated = bytearray(original)
        mutated[offset] ^= 0xFF
        path = stored(tmp_path, bytes(mutated), "mutated.upload")
        try:
            info = inspect_capture(path)
        except InvalidCaptureError:
            continue
        monitor = RecordingMonitor()
        outcome = analyze_file(path, info, monitor, cancel=threading.Event(), timeout=30)
        analysed += 1
        assert outcome.status in {CaptureStatus.COMPLETED, CaptureStatus.FAILED}
        assert outcome.error_code in {None, "capture_truncated", "invalid_capture_file"}
        assert outcome.records_read <= info.packets
        assert len(monitor.processed) + monitor.non_ip + monitor.malformed <= outcome.records_read
    assert analysed > len(original) // 10


@pytest.mark.parametrize("kind", ["classic", "pcapng"])
def test_a_capture_file_becomes_flows_and_one_alert(tmp_path: Path, rig: Rig, kind: str) -> None:
    path = scan_files(tmp_path)[kind]
    info = inspect_capture(path)
    assert info.packets == SCAN_FRAMES
    outcome = analyze_file(path, info, rig.monitor, cancel=threading.Event())
    rig.monitor.finish(outcome.status, outcome.error_code)
    row = rig.row()
    assert (row.status, row.error_code) == ("completed", None)
    assert row.packets_total == SCAN_FRAMES - 1
    assert row.flows_total == SCAN_FLOWS
    assert row.alerts_total == 1
    assert row.ended_at is not None
    assert row.ended_at >= row.started_at
    assert row.stats["non_ip_packets"] == 1
    assert len(rig.flows()) == SCAN_FLOWS
    [alert] = rig.alerts()
    assert (alert.rule_id, alert.src_ip, alert.dst_ip) == ("NET-001", SCANNER, SERVER)


def test_a_truncated_capture_completes_with_its_alerts_and_a_note(tmp_path: Path, rig: Rig) -> None:
    path = stored(tmp_path, classic_pcap(scan_frames())[:-10])
    info = inspect_capture(path)
    outcome = analyze_file(path, info, rig.monitor, cancel=threading.Event())
    rig.monitor.finish(outcome.status, outcome.error_code)
    row = rig.row()
    assert (row.status, row.error_code) == ("completed", "capture_truncated")
    assert row.alerts_total == 1
    assert row.packets_total == SCAN_FRAMES - 1


# --- PcapRunner ------------------------------------------------------------------------------


def test_a_new_runner_is_idle() -> None:
    runner = PcapRunner()
    assert (runner.busy, runner.session_id) == (False, None)
    assert not runner.cancel.is_set()


def test_only_one_analysis_holds_the_slot_at_a_time() -> None:
    runner = PcapRunner()
    first, second = uuid.uuid4(), uuid.uuid4()
    assert runner.reserve(first) is True
    assert (runner.busy, runner.session_id) == (True, first)
    assert runner.reserve(second) is False
    assert runner.session_id == first
    runner.release()
    assert (runner.busy, runner.session_id) == (False, None)
    runner.release()
    assert runner.reserve(second) is True
    assert runner.session_id == second


def test_reserving_clears_a_cancellation_left_over_from_before() -> None:
    runner = PcapRunner()
    runner.cancel.set()
    assert runner.reserve(uuid.uuid4())
    assert not runner.cancel.is_set()


def test_a_refused_reservation_leaves_the_running_analysis_alone() -> None:
    runner = PcapRunner()
    runner.reserve(uuid.uuid4())
    runner.cancel.set()
    assert runner.reserve(uuid.uuid4()) is False
    assert runner.cancel.is_set()


def test_a_job_runs_on_its_own_thread_and_frees_the_slot_when_it_ends() -> None:
    runner = PcapRunner()
    names: list[str] = []
    runner.reserve(uuid.uuid4())
    runner.launch(lambda: names.append(threading.current_thread().name))
    wait_until(lambda: not runner.busy, what="the job to release the slot")
    assert names == ["cipherforge-pcap-analysis"]
    assert runner.session_id is None
    assert runner.shutdown(timeout=2)


def test_the_slot_is_freed_when_the_job_crashes_and_the_log_names_only_the_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = PcapRunner()

    def crash() -> None:
        raise RuntimeError("secret-marker detail")

    runner.reserve(uuid.uuid4())
    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        runner.launch(crash)
        wait_until(lambda: not runner.busy, what="the crashed job to release the slot")
        assert runner.shutdown(timeout=2)
    assert "secret-marker" not in caplog.text
    assert any(
        record.getMessage() == "pcap_analysis_crashed"
        and record.__dict__.get("error") == "RuntimeError"
        for record in caplog.records
    )


def test_a_second_analysis_can_follow_the_first() -> None:
    runner = PcapRunner()
    done: list[int] = []
    for number in range(3):
        assert runner.reserve(uuid.uuid4())
        runner.launch(lambda number=number: done.append(number))
        wait_until(lambda: not runner.busy, what="the job to finish")
    assert done == [0, 1, 2]
    assert runner.shutdown(timeout=2)


def test_shutdown_cancels_a_running_job_and_waits_for_it() -> None:
    runner = PcapRunner()
    started, finished = threading.Event(), threading.Event()

    def job() -> None:
        started.set()
        runner.cancel.wait(5)
        finished.set()

    runner.reserve(uuid.uuid4())
    runner.launch(job)
    assert started.wait(5)
    assert runner.shutdown(timeout=3) is True
    assert finished.is_set()
    assert not runner.busy


def test_shutdown_says_so_when_a_job_ignores_the_cancellation() -> None:
    runner = PcapRunner()
    started, release = threading.Event(), threading.Event()

    def stubborn() -> None:
        started.set()
        release.wait(5)

    runner.reserve(uuid.uuid4())
    runner.launch(stubborn)
    assert started.wait(5)
    assert runner.shutdown(timeout=0.05) is False
    assert runner.cancel.is_set()
    assert runner.busy
    release.set()
    wait_until(lambda: not runner.busy, what="the stubborn job to end")
    assert runner.shutdown(timeout=2) is True


def test_shutting_down_an_idle_runner_is_trivially_clean() -> None:
    runner = PcapRunner()
    assert runner.shutdown(timeout=0.1) is True
    assert runner.cancel.is_set()
    assert runner.reserve(uuid.uuid4())
    assert not runner.cancel.is_set()


def test_simultaneous_reservations_have_one_winner() -> None:
    runner = PcapRunner()
    barrier = threading.Barrier(12)
    results: list[bool] = []
    lock = threading.Lock()

    def race() -> None:
        barrier.wait(5)
        won = runner.reserve(uuid.uuid4())
        with lock:
            results.append(won)

    threads = [threading.Thread(target=race) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert sorted(results) == [False] * 11 + [True]

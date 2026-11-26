"""Offline analysis of PCAP and PCAPNG capture files.

An uploaded capture goes through four steps, none of which trusts the client:

1. the file name is reduced to a display name; it is never used as a path, and the bytes are
   written to a randomly named file in a private temporary directory;
2. the bytes are checked as a capture file, not as a name or a MIME type: the format is decided by
   its magic number, and the whole record structure is walked (without decoding any packet) so a
   length field that points past the end of the file is caught before a reader acts on it;
3. packets are decoded one at a time, reduced to metadata and fed to the same analysis a live
   capture uses;
4. the temporary file is deleted, whatever happened.
"""

import contextlib
import logging
import mmap
import os
import secrets
import shutil
import struct
import tempfile
import threading
import time
import unicodedata
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from starlette.concurrency import run_in_threadpool

from app.core.errors import ApiError
from app.models.enums import CaptureStatus
from app.network.monitor import SessionMonitor
from app.network.packets import MalformedPacketError, extract_packet
from app.network.scapy_support import CaptureLibraryMissingError, load_scapy

logger = logging.getLogger("cipherforge.network")

ALLOWED_EXTENSIONS = (".pcap", ".pcapng", ".cap")
MAX_DISPLAY_NAME = 120
MAX_RAW_NAME = 1024
ANALYSIS_TIMEOUT_SECONDS = 600.0
BATCH_SIZE = 512
STALE_SPOOL_SECONDS = 24 * 3600
_WRITE_BUFFER = 256 * 1024
_SPOOL_PREFIX = "cipherforge-pcap-"

# Classic pcap: the magic number says how the rest of the header is laid out.
_PCAP_MAGICS: dict[bytes, str] = {
    b"\xd4\xc3\xb2\xa1": "<",  # microsecond timestamps, little endian
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",  # nanosecond timestamps, little endian
    b"\xa1\xb2\x3c\x4d": ">",
}
_PCAP_HEADER = 24
_PCAP_RECORD_HEADER = 16
_PCAP_MAJOR_VERSION = 2
_PCAP_MAX_MINOR_VERSION = 99
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_PCAPNG_PACKET_BLOCKS = frozenset({2, 3, 6})
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_PCAPNG_BYTE_ORDER_SWAPPED = 0x4D3C2B1A
_PCAPNG_MAJOR_VERSION = 1
# The smallest block is its type and two copies of its length; a section header adds the
# byte-order magic, the version and the section length.
_PCAPNG_MIN_BLOCK = 12
_PCAPNG_MIN_SECTION_HEADER = 28
_MAX_RECORD_BYTES = 1 << 24
_MIN_CAPTURE_BYTES = 12


class InvalidCaptureError(Exception):
    """The bytes are not a readable capture file."""


@dataclass(frozen=True, slots=True)
class CaptureFile:
    """What the structure check found: the format, how many complete packets, and whether the
    file stops short (or turns to garbage) after them."""

    format: str
    packets: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class ReceivedUpload:
    path: Path
    size: int


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    status: CaptureStatus
    error_code: str | None
    records_read: int


# --- File names ----------------------------------------------------------------------------


def display_name(raw: str | None) -> str:
    """The name to show for an uploaded capture, from the percent-encoded ``X-File-Name`` header.

    Only the last path component survives and control characters are dropped. The result is for
    display; it is never used to open, create or delete anything.
    """
    if not raw or len(raw) > MAX_RAW_NAME:
        raise ApiError(422, "invalid_filename", "A capture file name is required.")
    try:
        decoded = unquote(raw, errors="strict")
    except UnicodeDecodeError:
        raise ApiError(422, "invalid_filename", "The file name is not valid UTF-8.") from None
    decoded = unicodedata.normalize("NFC", decoded)
    name = decoded.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch) not in {"Cc", "Cf"}).strip()
    if not name or name in {".", ".."}:
        raise ApiError(422, "invalid_filename", "The file name is not usable.")
    extension = next((ext for ext in ALLOWED_EXTENSIONS if name.lower().endswith(ext)), None)
    if extension is None or len(name) == len(extension):
        raise ApiError(
            422,
            "invalid_filename",
            "Only .pcap, .pcapng and .cap files can be analysed.",
        )
    if len(name) > MAX_DISPLAY_NAME:
        name = name[: MAX_DISPLAY_NAME - len(extension)] + name[-len(extension) :]
    return name


# --- Structure check -----------------------------------------------------------------------


def inspect_capture(path: Path) -> CaptureFile:
    """Check that ``path`` is a capture file and count its complete packets.

    Raises ``InvalidCaptureError`` if the header is not one of a PCAP or PCAPNG file, or if not
    a single complete record can be found after it. A file that is cut short, or whose records go
    wrong part-way, is accepted up to that point and reported as ``truncated``.
    """
    try:
        size = path.stat().st_size
        if size < _MIN_CAPTURE_BYTES:
            raise InvalidCaptureError("too short")
        with (
            path.open("rb") as handle,
            mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data,
        ):
            if bytes(data[:4]) == _PCAPNG_SECTION:
                return _inspect_pcapng(data, size)
            return _inspect_pcap(data, size)
    except (OSError, ValueError, struct.error) as exc:
        raise InvalidCaptureError(type(exc).__name__) from exc


def _inspect_pcap(data: mmap.mmap, size: int) -> CaptureFile:
    endian = _PCAP_MAGICS.get(bytes(data[:4]))
    if endian is None or size < _PCAP_HEADER:
        raise InvalidCaptureError("not a pcap file")
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    if major != _PCAP_MAJOR_VERSION or minor > _PCAP_MAX_MINOR_VERSION:
        raise InvalidCaptureError("unsupported pcap version")
    offset, packets = _PCAP_HEADER, 0
    while offset < size:
        if size - offset < _PCAP_RECORD_HEADER:
            break
        included = struct.unpack_from(endian + "I", data, offset + 8)[0]
        end = offset + _PCAP_RECORD_HEADER + included
        if included > _MAX_RECORD_BYTES or end > size:
            break
        offset, packets = end, packets + 1
    truncated = offset < size
    if truncated and packets == 0:
        raise InvalidCaptureError("no complete packet")
    return CaptureFile(format="pcap", packets=packets, truncated=truncated)


def _inspect_pcapng(data: mmap.mmap, size: int) -> CaptureFile:
    offset, packets = 0, 0
    endian = "<"
    first = True
    while offset < size:
        if size - offset < _PCAPNG_MIN_BLOCK:
            break
        if bytes(data[offset : offset + 4]) == _PCAPNG_SECTION:
            # A section header says which byte order the blocks of its section use.
            if size - offset < _PCAPNG_MIN_SECTION_HEADER:
                break
            magic = struct.unpack_from("<I", data, offset + 8)[0]
            if magic == _PCAPNG_BYTE_ORDER_MAGIC:
                endian = "<"
            elif magic == _PCAPNG_BYTE_ORDER_SWAPPED:
                endian = ">"
            else:
                break
            if struct.unpack_from(endian + "H", data, offset + 12)[0] != _PCAPNG_MAJOR_VERSION:
                raise InvalidCaptureError("unsupported pcapng version")
        elif first:
            raise InvalidCaptureError("missing section header")
        kind = struct.unpack_from(endian + "I", data, offset)[0]
        length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if (
            length < _PCAPNG_MIN_BLOCK
            or length % 4
            or length > _MAX_RECORD_BYTES + _PCAPNG_MIN_SECTION_HEADER
            or offset + length > size
        ):
            break
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            break
        first = False
        if kind in _PCAPNG_PACKET_BLOCKS:
            packets += 1
        offset += length
    if first:
        raise InvalidCaptureError("no valid section")
    truncated = offset < size
    if truncated and packets == 0:
        raise InvalidCaptureError("no complete packet")
    return CaptureFile(format="pcapng", packets=packets, truncated=truncated)


# --- Temporary storage ---------------------------------------------------------------------


class UploadSpool:
    """A private temporary directory for uploaded captures.

    The directory is made with ``mkdtemp`` (unique name, owner-only access) the first time it is
    needed, files in it have random names, and it is removed when the application shuts down.
    """

    def __init__(self, base: Path | None = None) -> None:
        self._base = base
        self._lock = threading.Lock()
        self._directory: Path | None = None

    def directory(self) -> Path:
        with self._lock:
            if self._directory is None or not self._directory.is_dir():
                parent = str(self._base) if self._base is not None else None
                self._directory = Path(tempfile.mkdtemp(prefix=_SPOOL_PREFIX, dir=parent))
            return self._directory

    def new_file(self) -> Path:
        return self.directory() / f"{secrets.token_hex(16)}.upload"

    def remove(self, path: Path) -> None:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)

    def close(self) -> None:
        with self._lock:
            directory, self._directory = self._directory, None
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)

    def purge_stale(self, max_age: float = STALE_SPOOL_SECONDS) -> int:
        """Delete spool directories a crashed process left behind. Returns how many."""
        removed = 0
        parent = self._base or Path(tempfile.gettempdir())
        cutoff = time.time() - max_age
        try:
            candidates = [p for p in parent.iterdir() if p.name.startswith(_SPOOL_PREFIX)]
        except OSError:
            return 0
        for candidate in candidates:
            try:
                if candidate.is_symlink() or not candidate.is_dir():
                    continue
                if candidate.stat().st_mtime < cutoff:
                    shutil.rmtree(candidate, ignore_errors=True)
                    removed += 1
            except OSError:
                continue
        return removed


def _open_exclusive(path: Path) -> Any:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


async def receive_upload(
    chunks: AsyncIterator[bytes], *, spool: UploadSpool, max_bytes: int
) -> ReceivedUpload:
    """Stream a request body to a new spool file, refusing anything larger than ``max_bytes``.

    The file is removed again if the transfer fails for any reason.
    """
    path = await run_in_threadpool(spool.new_file)
    handle = None
    written = 0
    pending = bytearray()
    try:
        handle = await run_in_threadpool(_open_exclusive, path)
        async for chunk in chunks:
            written += len(chunk)
            if written > max_bytes:
                raise ApiError(
                    413,
                    "file_too_large",
                    f"The capture file is larger than the {max_bytes // (1024 * 1024)} MB limit.",
                )
            pending.extend(chunk)
            if len(pending) >= _WRITE_BUFFER:
                await run_in_threadpool(handle.write, bytes(pending))
                pending.clear()
        if pending:
            await run_in_threadpool(handle.write, bytes(pending))
        await run_in_threadpool(handle.close)
    except BaseException:
        if handle is not None:
            with contextlib.suppress(Exception):
                handle.close()
        spool.remove(path)
        raise
    if written == 0:
        spool.remove(path)
        raise ApiError(422, "invalid_capture_file", "The upload is empty.")
    return ReceivedUpload(path=path, size=written)


# --- Analysis ------------------------------------------------------------------------------


def analyze_file(
    path: Path,
    info: CaptureFile,
    monitor: SessionMonitor,
    *,
    cancel: threading.Event,
    timeout: float = ANALYSIS_TIMEOUT_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> AnalysisOutcome:
    """Feed every complete packet of a checked capture file to ``monitor``."""
    try:
        scapy = load_scapy()
    except CaptureLibraryMissingError:
        return AnalysisOutcome(CaptureStatus.FAILED, "analysis_failed", 0)
    reader_type = scapy.PcapNgReader if info.format == "pcapng" else scapy.PcapReader
    deadline = clock() + timeout
    records = 0
    reader_failed = False
    batch: list[Any] = []
    try:
        with reader_type(str(path)) as reader:
            iterator = iter(islice(reader, info.packets))
            while True:
                if cancel.is_set():
                    monitor.process_batch(batch)
                    return AnalysisOutcome(CaptureStatus.FAILED, "interrupted", records)
                if clock() > deadline:
                    monitor.process_batch(batch)
                    return AnalysisOutcome(CaptureStatus.FAILED, "analysis_timeout", records)
                try:
                    raw = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:  # a record the reader cannot decode ends the analysis
                    logger.warning("pcap_read_failed", extra={"error": type(exc).__name__})
                    reader_failed = True
                    break
                records += 1
                try:
                    meta = extract_packet(raw)
                except MalformedPacketError:
                    monitor.note_malformed()
                    continue
                if meta is None:
                    monitor.note_non_ip()
                    continue
                batch.append(meta)
                if len(batch) >= BATCH_SIZE:
                    monitor.process_batch(batch)
                    batch = []
    except Exception as exc:  # the file could not be opened as a capture at all
        logger.warning("pcap_open_failed", extra={"error": type(exc).__name__})
        return AnalysisOutcome(CaptureStatus.FAILED, "invalid_capture_file", records)
    monitor.process_batch(batch)
    if reader_failed or info.truncated:
        if records == 0:
            return AnalysisOutcome(CaptureStatus.FAILED, "invalid_capture_file", 0)
        return AnalysisOutcome(CaptureStatus.COMPLETED, "capture_truncated", records)
    return AnalysisOutcome(CaptureStatus.COMPLETED, None, records)


class PcapRunner:
    """Runs one capture-file analysis at a time on a thread of its own."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._busy = False
        self._session_id: uuid.UUID | None = None
        self.cancel = threading.Event()

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._busy

    @property
    def session_id(self) -> uuid.UUID | None:
        with self._lock:
            return self._session_id if self._busy else None

    def reserve(self, session_id: uuid.UUID) -> bool:
        """Claim the single analysis slot. False if an analysis is already running."""
        with self._lock:
            if self._busy:
                return False
            self._busy = True
            self._session_id = session_id
            self.cancel.clear()
            return True

    def release(self) -> None:
        with self._lock:
            self._busy = False
            self._session_id = None

    def launch(self, job: Callable[[], None]) -> None:
        """Run ``job`` on a new thread. The slot is released when it returns, however it ends."""

        def run() -> None:
            try:
                job()
            except Exception as exc:  # the job reports its own failures; this is the last resort
                logger.error("pcap_analysis_crashed", extra={"error": type(exc).__name__})
            finally:
                self.release()

        thread = threading.Thread(target=run, name="cipherforge-pcap-analysis", daemon=True)
        with self._lock:
            self._thread = thread
        thread.start()

    def shutdown(self, timeout: float = 10.0) -> bool:
        """Cancel a running analysis and wait for it. True if nothing is left running."""
        self.cancel.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        return thread is None or not thread.is_alive()

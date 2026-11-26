"""Error codes of the network-monitoring module and the wording that is safe to show for them.

A session that ends badly keeps a short code in ``capture_sessions.error_code``. The API turns it
into one of these messages; raw exception text, paths and file names never reach the client.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    status: int
    message: str


ERRORS: dict[str, ErrorInfo] = {
    "capture_permission_denied": ErrorInfo(
        503,
        "The operating system refused packet capture to the CipherForge server process. Start "
        "the API with the privileges capture needs (see docs/network-monitoring.md).",
    ),
    "capture_backend_missing": ErrorInfo(
        503,
        "No packet-capture driver was found. Install Npcap (Windows) or libpcap (Linux), then "
        "restart the API.",
    ),
    "interface_unavailable": ErrorInfo(
        503,
        "The selected network interface is not available. It may have been disconnected or "
        "disabled.",
    ),
    "capture_failed": ErrorInfo(
        503, "Packet capture stopped because of an error. The server log has the details."
    ),
    "interrupted": ErrorInfo(
        503, "The application stopped while this session was running, so it ended early."
    ),
    "invalid_capture_file": ErrorInfo(
        422, "The file is not a readable PCAP or PCAPNG capture, or it holds no complete packet."
    ),
    "capture_truncated": ErrorInfo(
        422,
        "The capture file is cut short or damaged after some point. Everything before that "
        "point was analysed.",
    ),
    "analysis_timeout": ErrorInfo(
        503, "The analysis took too long and was stopped. The results so far are kept."
    ),
    "analysis_failed": ErrorInfo(
        503, "The capture file could not be analysed. The server log has the details."
    ),
    "results_incomplete": ErrorInfo(
        503,
        "Some results could not be stored because the database was unavailable, so the totals "
        "may be incomplete.",
    ),
}


def message_for(code: str | None) -> str | None:
    if code is None:
        return None
    info = ERRORS.get(code)
    return info.message if info is not None else "The session ended with an error."


class CaptureFailure(Exception):
    """A capture could not start or had to end. ``code`` is one of ``ERRORS``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

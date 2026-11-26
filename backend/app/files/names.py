"""File names: header decoding, sanitising and the ``Content-Disposition`` header.

A client-supplied name is *display data only*. The server never uses it as a path: blobs get
random names (``app.files.storage``) and the original name is stored encrypted. Sanitising is
still strict because the name is sent back in ``Content-Disposition`` and shown in the UI, and
because a user will save the download under that name on their own machine.
"""

import re
import unicodedata
from urllib.parse import quote, unquote

MAX_NAME_LENGTH = 255
MAX_HEADER_LENGTH = 1024
# An "extension" longer than this is not treated as one when a long name is shortened.
_MAX_EXTENSION_LENGTH = 32

_SEPARATORS = re.compile(r"[\\/]")
_ILLEGAL_ON_WINDOWS = str.maketrans(dict.fromkeys('<>:"|?*', "_"))
# Control, format (bidi overrides, zero-width), surrogate, and line/paragraph separator chars.
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_RESERVED_DEVICE = re.compile(
    r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9\u00b9\u00b2\u00b3]", re.IGNORECASE
)
_FALLBACK_UNSAFE = frozenset('"\\;%')


class InvalidFilename(ValueError):
    """The name is missing, malformed, or empty once sanitised. The message never echoes it."""

    def __init__(self) -> None:
        super().__init__("The file name is missing or invalid.")


def decode_filename_header(values: list[str]) -> str:
    """Decode the single ``X-File-Name`` header (percent-encoded UTF-8, strictly)."""
    if len(values) != 1:
        raise InvalidFilename
    raw = values[0]
    # Raw non-ASCII bytes in a header have no agreed encoding, so only percent-encoding is read.
    if not raw or len(raw) > MAX_HEADER_LENGTH or not raw.isascii():
        raise InvalidFilename
    try:
        return unquote(raw, errors="strict")
    except UnicodeDecodeError:
        raise InvalidFilename from None


def _strip_edges(name: str) -> str:
    previous = None
    while previous != name:
        previous = name
        name = name.strip().strip(".")
    return name


def _cap_length(name: str) -> str:
    if len(name) <= MAX_NAME_LENGTH:
        return name
    stem, dot, extension = name.rpartition(".")
    if dot and stem and len(extension) <= _MAX_EXTENSION_LENGTH:
        room = MAX_NAME_LENGTH - len(extension) - 1
        return f"{_strip_edges(stem[:room])}.{extension}"
    return _strip_edges(name[:MAX_NAME_LENGTH])


def _is_reserved_device_name(name: str) -> bool:
    return _RESERVED_DEVICE.fullmatch(name.split(".", 1)[0].rstrip(" ")) is not None


def sanitize_filename(raw: str) -> str:
    """A safe display name, or InvalidFilename.

    Normalises to NFC, keeps only the last path component (split on ``/`` and ``\\``), drops
    control, bidi and other format characters, replaces characters Windows forbids, removes
    leading/trailing spaces and dots, prefixes reserved device names (``CON``, ``NUL``,
    ``COM1`` ...) with ``_`` and caps the length at 255 characters, keeping the extension.
    """
    name = unicodedata.normalize("NFC", raw)
    name = _SEPARATORS.split(name)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch) not in _DROPPED_CATEGORIES)
    name = _strip_edges(name.translate(_ILLEGAL_ON_WINDOWS))
    name = _cap_length(name)
    if not name:
        raise InvalidFilename
    if _is_reserved_device_name(name):
        name = _cap_length(f"_{name}")
    return name


def filename_from_header(values: list[str]) -> str:
    return sanitize_filename(decode_filename_header(values))


def content_disposition(name: str) -> str:
    """``attachment`` header with an ASCII fallback and the exact UTF-8 name (RFC 6266/8187).

    The fallback keeps printable ASCII only: quotes, backslashes, semicolons, percent signs and
    every control character (CR and LF included) become ``_``, so the value cannot break out of
    the quoted string or inject a header.
    """
    fallback = "".join(
        ch if " " <= ch <= "~" and ch not in _FALLBACK_UNSAFE else "_" for ch in name
    )
    encoded = quote(name, safe="", errors="replace")
    return f"attachment; filename=\"{fallback or 'download'}\"; filename*=UTF-8''{encoded}"

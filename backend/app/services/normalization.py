"""Indicator normalization.

Turns whatever an analyst pastes into one canonical, validated indicator, so equivalent
spellings (``HTTP://Example.COM:80/a`` and ``hxxp://example[.]com/a``) land on a single record
and malformed or dangerous input is rejected before it reaches the database or a provider.

Everything here is pure: no network access and no DNS resolution. Error messages describe the
problem without echoing the input, which may be hostile.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import idna

from app.models.enums import IndicatorType

MAX_INDICATOR_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253
_MAX_PORT = 65535

_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_HEX = re.compile(r"[0-9a-fA-F]+")
_UNSUPPORTED_HASH_LENGTHS = frozenset({32, 40, 128})  # MD5, SHA-1, SHA-512
_IPV4_LIKE = re.compile(r"[0-9.]+")
_ASCII_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
_TLD = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")

# Reserved, special-use or conventionally private top-level domains. Nothing under them is
# publicly resolvable, so a lookup could only leak internal naming to third parties.
_NON_PUBLIC_TLDS = frozenset(
    {
        "arpa",
        "corp",
        "example",
        "home",
        "internal",
        "intranet",
        "invalid",
        "lan",
        "local",
        "localhost",
        "private",
        "test",
    }
)

# Common "defanging" used when sharing indicators safely, undone before validation.
_DEFANG_DOTS = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.IGNORECASE)
_DEFANG_SCHEME_SEPARATOR = re.compile(r"\[://\]|\[:\]")
_DEFANG_SCHEME = re.compile(r"^hxxp(s?)(?=://)", re.IGNORECASE)

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_URL_SAFE_CHARACTERS = "/:@!$&'()*+,;=-._~%[]?"


class InvalidIndicatorError(ValueError):
    """The input is not an indicator CipherForge accepts. The message is safe to show users."""


@dataclass(frozen=True, slots=True)
class NormalizedIndicator:
    indicator_type: IndicatorType
    indicator_value: str

    @property
    def target(self) -> str:
        """Stable ``type:value`` form used in audit records."""
        return f"{self.indicator_type.value}:{self.indicator_value}"


def normalize_indicator(raw: str) -> NormalizedIndicator:
    """Validate ``raw`` and return its canonical form, or raise :class:`InvalidIndicatorError`."""
    if not isinstance(raw, str):
        raise InvalidIndicatorError("Indicator must be text.")
    if len(raw) > MAX_INDICATOR_LENGTH:
        raise InvalidIndicatorError(
            f"Indicator is too long (maximum {MAX_INDICATOR_LENGTH} characters)."
        )
    text = raw.strip()
    if not text:
        raise InvalidIndicatorError("Indicator must not be empty.")
    _reject_unsafe_characters(text)
    text = _refang(text)

    if _SHA256.fullmatch(text):
        return NormalizedIndicator(IndicatorType.SHA256, text.lower())
    if len(text) in _UNSUPPORTED_HASH_LENGTHS and _HEX.fullmatch(text):
        raise InvalidIndicatorError(
            "Only SHA-256 file hashes are supported; MD5, SHA-1 and SHA-512 are not."
        )
    if "://" in text:
        return _normalize_url(text)
    if ":" in text or _IPV4_LIKE.fullmatch(text):
        address = _parse_public_ip(text)
        kind = IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6
        return NormalizedIndicator(kind, address.compressed)
    return NormalizedIndicator(IndicatorType.DOMAIN, _normalize_domain(text))


def _reject_unsafe_characters(text: str) -> None:
    for char in text:
        if char.isspace():
            raise InvalidIndicatorError("Indicator must not contain whitespace.")
        # Control, format (zero-width, bidi override), surrogate and private-use characters
        # are invisible or reorder text, which makes look-alike indicators trivial to forge.
        if unicodedata.category(char).startswith("C"):
            raise InvalidIndicatorError(
                "Indicator must not contain control or invisible characters."
            )


def _refang(text: str) -> str:
    text = _DEFANG_DOTS.sub(".", text)
    text = _DEFANG_SCHEME_SEPARATOR.sub(
        lambda match: "://" if match.group(0) == "[://]" else ":", text
    )
    return _DEFANG_SCHEME.sub(lambda match: f"http{match.group(1)}", text)


def _parse_public_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in text:
        raise InvalidIndicatorError("IPv6 scope identifiers are not supported.")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise InvalidIndicatorError("Not a valid IPv4 or IPv6 address.") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not _is_public(address):
        raise InvalidIndicatorError(
            "Private, loopback, link-local, multicast, reserved and other non-public "
            "addresses are not looked up."
        )
    return address


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # ``is_global`` alone still admits multicast, NAT64 and deprecated site-local space.
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    return not (isinstance(address, ipaddress.IPv6Address) and address.is_site_local)


def _normalize_domain(text: str) -> str:
    if any(char in text for char in "/?#\\"):
        raise InvalidIndicatorError(
            "Not a valid domain. If this is a URL, include http:// or https://."
        )
    if "@" in text:
        raise InvalidIndicatorError("Email addresses are not supported indicators.")

    candidate = text
    if not candidate.isascii():
        try:
            # UTS 46 mapping with IDNA 2008 (non-transitional) semantics, e.g. keeps the sharp s.
            candidate = idna.uts46_remap(candidate, std3_rules=False, transitional=False)
        except ValueError:
            raise InvalidIndicatorError(
                "Domain contains characters that are not allowed in internationalized names."
            ) from None
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate:
        raise InvalidIndicatorError("Not a valid domain name.")

    labels = [_to_ascii_label(label) for label in candidate.split(".")]
    domain = ".".join(labels)
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise InvalidIndicatorError(f"Domain is too long (maximum {MAX_DOMAIN_LENGTH} characters).")
    if len(labels) < 2:
        raise InvalidIndicatorError("Domain must be fully qualified, such as example.com.")
    top_level = labels[-1]
    if not _TLD.fullmatch(top_level):
        raise InvalidIndicatorError("Domain does not end in a valid top-level domain.")
    if top_level in _NON_PUBLIC_TLDS:
        raise InvalidIndicatorError(
            "Domains under reserved or private-use top-level domains are not looked up."
        )
    return domain


def _to_ascii_label(label: str) -> str:
    if not label:
        raise InvalidIndicatorError("Domain contains an empty label.")
    if not label.isascii():
        try:
            return idna.encode(label).decode("ascii")
        except ValueError:
            raise InvalidIndicatorError(
                "Domain contains an invalid internationalized label."
            ) from None
    lowered = label.lower()
    if not _ASCII_LABEL.fullmatch(lowered):
        raise InvalidIndicatorError(
            "Domain labels may only contain letters, digits, hyphens and underscores, must be "
            "1-63 characters, and must not start or end with a hyphen."
        )
    if lowered.startswith("xn--"):
        try:
            lowered[4:].encode("ascii").decode("punycode")
        except ValueError:
            raise InvalidIndicatorError(
                "Domain contains an invalid internationalized label."
            ) from None
    return lowered


def _normalize_url(text: str) -> NormalizedIndicator:
    if "\\" in text:
        # Browsers read a backslash as a slash; other parsers do not. Refuse the ambiguity.
        raise InvalidIndicatorError("URLs must not contain backslashes.")
    try:
        parts = urlsplit(text)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise InvalidIndicatorError("Not a valid URL.") from None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidIndicatorError("Only http and https URLs are supported.")
    if "@" in parts.netloc:
        raise InvalidIndicatorError("URLs with embedded credentials are not supported.")
    if not hostname:
        raise InvalidIndicatorError("URL has no host.")
    if port is not None and not 1 <= port <= _MAX_PORT:
        raise InvalidIndicatorError(f"URL port must be between 1 and {_MAX_PORT}.")

    if ":" in hostname:
        address = _parse_public_ip(hostname)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    elif _IPV4_LIKE.fullmatch(hostname):
        host = _parse_public_ip(hostname).compressed
    else:
        host = _normalize_domain(hostname)

    default_port = 443 if scheme == "https" else 80
    authority = host if port in (None, default_port) else f"{host}:{port}"
    path = _clean_url_component(parts.path) or "/"
    query = _clean_url_component(parts.query)
    url = f"{scheme}://{authority}{path}{'?' + query if query else ''}"

    if len(url) > MAX_INDICATOR_LENGTH or not url.isascii():
        raise InvalidIndicatorError(
            f"URL is too long once normalized (maximum {MAX_INDICATOR_LENGTH} characters)."
        )
    return NormalizedIndicator(IndicatorType.URL, url)


def _clean_url_component(value: str) -> str:
    """Percent-encode unsafe characters and canonicalize existing escapes (RFC 3986 6.2.2)."""
    encoded = quote(value, safe=_URL_SAFE_CHARACTERS)
    return _PERCENT_ESCAPE.sub(_canonical_escape, encoded)


def _canonical_escape(match: re.Match[str]) -> str:
    char = chr(int(match.group(1), 16))
    return char if char in _UNRESERVED else match.group(0).upper()

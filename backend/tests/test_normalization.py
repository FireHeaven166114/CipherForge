"""Indicator normalization: canonical forms, rejected input and robustness against hostile text."""

import random
import string

import pytest

from app.models.enums import IndicatorType
from app.services.normalization import (
    MAX_INDICATOR_LENGTH,
    InvalidIndicatorError,
    NormalizedIndicator,
    normalize_indicator,
)

IPV4, IPV6 = IndicatorType.IPV4, IndicatorType.IPV6
DOMAIN, URL, SHA256 = IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.SHA256
HASH = "a" * 32 + "B" * 32

VALID = [
    # IPv4 / IPv6
    ("8.8.8.8", IPV4, "8.8.8.8"),
    ("  8.8.8.8\n", IPV4, "8.8.8.8"),
    ("8[.]8[.]8[.]8", IPV4, "8.8.8.8"),
    ("8(.)8{.}8[dot]8", IPV4, "8.8.8.8"),
    ("::ffff:8.8.8.8", IPV4, "8.8.8.8"),
    ("2606:4700:4700:0000:0000:0000:0000:1111", IPV6, "2606:4700:4700::1111"),
    ("2606:4700:4700::1111", IPV6, "2606:4700:4700::1111"),
    ("2001:4860:4860::8888", IPV6, "2001:4860:4860::8888"),
    ("2A00:1450:4001:81B::200E", IPV6, "2a00:1450:4001:81b::200e"),
    # Domains
    ("example.com", DOMAIN, "example.com"),
    ("Example.COM", DOMAIN, "example.com"),
    ("example.com.", DOMAIN, "example.com"),
    ("evil[.]example[.]org", DOMAIN, "evil.example.org"),
    ("sub_domain.example.org", DOMAIN, "sub_domain.example.org"),
    ("a-b.co.uk", DOMAIN, "a-b.co.uk"),
    ("1234.com", DOMAIN, "1234.com"),
    ("xn--bcher-kva.example.net", DOMAIN, "xn--bcher-kva.example.net"),
    ("b\u00fccher.example.net", DOMAIN, "xn--bcher-kva.example.net"),
    ("B\u00dcCHER.example.net", DOMAIN, "xn--bcher-kva.example.net"),
    ("fa\u00df.de", DOMAIN, "xn--fa-hia.de"),
    ("example\u3002com", DOMAIN, "example.com"),
    # URLs
    ("HTTP://Example.COM:80/a/b?x=1#frag", URL, "http://example.com/a/b?x=1"),
    ("hxxps://evil[.]example[.]com/login", URL, "https://evil.example.com/login"),
    ("hXXp[:]//evil[.]example[.]com/", URL, "http://evil.example.com/"),
    ("http://example.com", URL, "http://example.com/"),
    ("https://example.com:443", URL, "https://example.com/"),
    ("https://example.com:8443/p", URL, "https://example.com:8443/p"),
    ("http://example.com:443/", URL, "http://example.com:443/"),
    ("http://example.com./", URL, "http://example.com/"),
    ("http://8.8.8.8:80/x", URL, "http://8.8.8.8/x"),
    ("http://[2606:4700:4700::1111]:8080/x", URL, "http://[2606:4700:4700::1111]:8080/x"),
    ("http://[::ffff:8.8.8.8]/", URL, "http://8.8.8.8/"),
    ("http://example.com/%7euser/%e4%bd%a0", URL, "http://example.com/~user/%E4%BD%A0"),
    ("http://example.com/caf\u00e9?q=\u00fc", URL, "http://example.com/caf%C3%A9?q=%C3%BC"),
    ("http://example.com/?q=<script>", URL, "http://example.com/?q=%3Cscript%3E"),
    ("http://example.com/a?b[]=1&c=%2F", URL, "http://example.com/a?b[]=1&c=%2F"),
    ("http://b\u00fccher.example.net/", URL, "http://xn--bcher-kva.example.net/"),
    ("http://example.com/#only-fragment", URL, "http://example.com/"),
    # SHA-256
    (HASH, SHA256, HASH.lower()),
    (f"  {HASH}  ", SHA256, HASH.lower()),
]


@pytest.mark.parametrize(("raw", "expected_type", "expected_value"), VALID)
def test_canonical_forms(raw: str, expected_type: IndicatorType, expected_value: str) -> None:
    assert normalize_indicator(raw) == NormalizedIndicator(expected_type, expected_value)


@pytest.mark.parametrize("raw", [case[0] for case in VALID])
def test_normalization_is_idempotent_ascii_and_bounded(raw: str) -> None:
    once = normalize_indicator(raw)

    assert normalize_indicator(once.indicator_value) == once
    assert once.indicator_value.isascii()
    assert len(once.indicator_value) <= MAX_INDICATOR_LENGTH


def test_target_combines_type_and_value() -> None:
    assert normalize_indicator("Example.com").target == "domain:example.com"


REJECTED = [
    # Empty, oversized, whitespace, invisible and control characters
    "",
    "   ",
    "a" * (MAX_INDICATOR_LENGTH + 1),
    "8.8.8.8\x00",
    "8.8.8.8\n1.1.1.1",
    "8.8.8.8 1.1.1.1",
    "exa\u200bmple.com",
    "example.com\u202e",
    "\ufeffexample.com",
    "exa\ud800mple.com",
    # Non-public or malformed IP addresses
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",  # noqa: S104 - an input that must be rejected, not a bind address
    "224.0.0.1",
    "239.255.255.250",
    "240.0.0.1",
    "255.255.255.255",
    "198.18.0.1",
    "192.0.2.1",
    "203.0.113.1",
    "::",
    "::1",
    "fe80::1",
    "fc00::1",
    "fec0::1",
    "ff02::1",
    "ff0e::1",
    "2001:db8::1",
    "2002::1",
    "64:ff9b::808:808",
    "::ffff:10.0.0.1",
    "999.1.1.1",
    "1.2.3",
    "01.2.3.4",
    "1.2.3.4.5",
    "2130706433",
    "8.8.8.8%eth0",
    "8.8.8.8:443",
    "2606:4700:4700::1111%eth0",
    # Unsupported hashes and look-alikes
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "d" * 128,
    "g" * 64,
    # Domains
    "localhost",
    "printer.local",
    "host.internal",
    "intranet",
    "foo",
    "-bad.example.com",
    "bad-.example.com",
    "a..example.com",
    ".example.com",
    "example.com..",
    "ex@mple.com",
    "user@example.com",
    "example.com/path",
    "example.com?x=1",
    "*.example.com",
    "exa mple.com",
    "example.c",
    "example.123",
    "example.co_m",
    f"{'a' * 64}.com",
    ".".join(["a" * 60] * 5) + ".com",
    "\u2603.example.com",
    "xn--.example.com",
    # URLs
    "ftp://example.com/",
    "file:///etc/passwd",
    "javascript://example.com/%0aalert(1)",
    "http://user:pass@example.com/",
    "http://example.com@evil.example.org/",
    "http://example.com\\@evil.example.org/",
    "http:///path",
    "http://example.com:99999/",
    "http://example.com:0/",
    "http://example.com:abc/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://[2606:4700:4700::1111/",
    "http://2130706433/",
    "http://0x7f.1/",
    "http://example.com/" + "a" * MAX_INDICATOR_LENGTH,
    "//example.com/path",
    # Injection and template payloads are just invalid indicators
    "' OR 1=1--",
    "'; DROP TABLE threat_indicators;--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "${jndi:ldap://evil.example.com/a}",
    "{{7*7}}",
    "data:text/html,<script>alert(1)</script>",
]


@pytest.mark.parametrize("raw", REJECTED)
def test_rejected_input_never_echoes_the_input(raw: str) -> None:
    with pytest.raises(InvalidIndicatorError) as excinfo:
        normalize_indicator(raw)

    message = str(excinfo.value)
    assert message
    stripped = raw.strip()
    if len(stripped) >= 4:
        assert stripped not in message


def test_non_text_input_is_rejected() -> None:
    with pytest.raises(InvalidIndicatorError):
        normalize_indicator(b"8.8.8.8")  # type: ignore[arg-type]


def test_unsupported_hash_message_points_to_sha256() -> None:
    with pytest.raises(InvalidIndicatorError, match="SHA-256"):
        normalize_indicator("d41d8cd98f00b204e9800998ecf8427e")


def test_scheme_less_url_gets_a_helpful_message() -> None:
    with pytest.raises(InvalidIndicatorError, match="http://"):
        normalize_indicator("example.com/login")


def test_random_hostile_input_only_ever_raises_the_documented_error() -> None:
    rng = random.Random(20240607)  # noqa: S311 - deterministic fuzzing, not security
    alphabet = (
        string.ascii_letters
        + string.digits
        + ".:/?#[]@%-_\\ \t\n'\"<>{}()&=;,"
        + "\u00fc\u00df\u3002\u200b\u202e\u2603\ud800\U0001f4a9"
    )
    seeds = ["http://", "https://", "xn--", "::", "[", "%", "http://[", "hxxp://", "a.b."]
    for _ in range(4000):
        raw = rng.choice(seeds) + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        try:
            result = normalize_indicator(raw)
        except InvalidIndicatorError:
            continue
        # Whatever is accepted must be stable and safe to store.
        assert result.indicator_value.isascii()
        assert normalize_indicator(result.indicator_value) == result

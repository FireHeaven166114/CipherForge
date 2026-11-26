"""Live checks against the real provider APIs (real network, real API keys).

Skipped unless ``CIPHERFORGE_LIVE_TESTS=1``. Each test spends exactly one request on one
provider, asking about a well-known public resolver address, and is skipped rather than failed
when its key is missing or the provider reports that the quota is used up. Keys come from the
process environment or the git-ignored ``.env`` and are never printed or asserted on.

    $env:CIPHERFORGE_LIVE_TESTS = "1"
    python -m pytest -m live -q -rs
"""

import os
from collections.abc import Callable, Iterator
from typing import Any

import httpx2
import pytest
from dotenv import dotenv_values

from app.collectors.abuseipdb import AbuseIPDBCollector
from app.collectors.base import Collector, ProviderResult, ProviderStatus, Reason
from app.collectors.otx import OTXCollector
from app.collectors.registry import build_http_client
from app.collectors.threatfox import ThreatFoxCollector
from app.collectors.virustotal import VirusTotalCollector
from app.core.config import REPO_ROOT, Settings
from app.services.normalization import normalize_indicator

ENABLED = os.environ.get("CIPHERFORGE_LIVE_TESTS") == "1"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not ENABLED, reason="set CIPHERFORGE_LIVE_TESTS=1 to call real providers"),
]

# The autouse environment isolation clears the key variables before each test, so read them
# once, here, when live tests are enabled.
_FILE_VALUES = dotenv_values(REPO_ROOT / ".env") if ENABLED else {}
_KEYS = {
    name: os.environ.get(name) or _FILE_VALUES.get(name)
    for name in (
        "ABUSEIPDB_API_KEY",
        "OTX_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "THREATFOX_API_KEY",
    )
}

# Google Public DNS: globally routable, benign, and known to every provider.
BENIGN_IP = "8.8.8.8"


def _settings() -> Settings:
    # The database URL is required but never opened: only the provider settings are used.
    return Settings(
        _env_file=None,
        environment="test",
        auth_mode="dev",
        database_url="sqlite+pysqlite:///:memory:",
    )


@pytest.fixture
def http_client() -> Iterator[httpx2.Client]:
    client = build_http_client(_settings())
    try:
        yield client
    finally:
        client.close()


def _lookup(
    variable: str, build: Callable[[str], Collector], value: str = BENIGN_IP
) -> tuple[ProviderResult, str]:
    key = _KEYS[variable]
    if not key:
        pytest.skip(f"{variable} is not configured")
    result = build(key).lookup(normalize_indicator(value))
    if result.status is ProviderStatus.RATE_LIMITED:
        pytest.skip("the provider's rate limit or quota is used up")
    return result, key


def _assert_a_clean_answer(result: ProviderResult, key: str) -> None:
    assert result.status in {ProviderStatus.OK, ProviderStatus.NO_DATA}, (
        result.status,
        result.reason,
        result.message,
    )
    assert result.reason is None and result.message is None
    assert 0.0 <= result.signal <= 1.0
    leaked = key in repr(result)  # kept out of the assert so a failure cannot print the key
    assert not leaked


def test_abuseipdb_answers_a_real_lookup(http_client: httpx2.Client) -> None:
    result, key = _lookup(
        "ABUSEIPDB_API_KEY",
        lambda k: AbuseIPDBCollector(api_key=k, client=http_client, cache_ttl_seconds=0),
    )

    _assert_a_clean_answer(result, key)
    assert result.status is ProviderStatus.OK
    assert isinstance(result.summary.get("confidence_score"), int)


def test_otx_answers_a_real_lookup(http_client: httpx2.Client) -> None:
    result, key = _lookup(
        "OTX_API_KEY",
        lambda k: OTXCollector(api_key=k, client=http_client, cache_ttl_seconds=0),
    )

    _assert_a_clean_answer(result, key)
    assert isinstance(result.summary.get("pulse_count"), int)


def test_virustotal_answers_a_real_lookup(http_client: httpx2.Client) -> None:
    settings = _settings()
    result, key = _lookup(
        "VIRUSTOTAL_API_KEY",
        lambda k: VirusTotalCollector(
            api_key=k,
            client=http_client,
            cache_ttl_seconds=0,
            base_url=settings.virustotal_base_url,
            timeout_seconds=settings.virustotal_timeout_seconds,
            max_retries=0,
        ),
    )

    _assert_a_clean_answer(result, key)
    summary: dict[str, Any] = result.summary
    assert summary["verdict"] in {"malicious", "suspicious", "harmless", "unknown"}
    assert isinstance(summary["engines_total"], int)
    assert summary["provider_link"].startswith("https://www.virustotal.com/gui/ip-address/")


def test_threatfox_answers_a_real_lookup(http_client: httpx2.Client) -> None:
    settings = _settings()
    result, key = _lookup(
        "THREATFOX_API_KEY",
        lambda k: ThreatFoxCollector(
            api_key=k,
            client=http_client,
            cache_ttl_seconds=0,
            base_url=settings.threatfox_base_url,
            timeout_seconds=settings.threatfox_timeout_seconds,
            max_retries=0,
        ),
    )

    if result.reason is Reason.AUTH_FAILED:
        pytest.fail("ThreatFox rejected the configured key")
    _assert_a_clean_answer(result, key)
    assert result.summary["verdict"] in {"malicious", "suspicious", "not_found"}

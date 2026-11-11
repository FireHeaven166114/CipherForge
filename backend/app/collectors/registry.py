"""Builds the HTTP client and the configured set of provider adapters."""

import httpx2

from app import __version__
from app.collectors.abuseipdb import AbuseIPDBCollector
from app.collectors.base import Collector
from app.collectors.otx import OTXCollector
from app.core.config import Settings

CONNECT_TIMEOUT_SECONDS = 5.0


def build_http_client(settings: Settings) -> httpx2.Client:
    """One shared client for every provider.

    Redirects are off so an API key can never be forwarded to another host, TLS verification
    stays on, and the pool is small because lookups are analyst-driven and cached.
    """
    return httpx2.Client(
        timeout=httpx2.Timeout(settings.provider_timeout_seconds, connect=CONNECT_TIMEOUT_SECONDS),
        follow_redirects=False,
        limits=httpx2.Limits(max_connections=10, max_keepalive_connections=5),
        headers={"User-Agent": f"CipherForge/{__version__}"},
    )


def build_collectors(settings: Settings, client: httpx2.Client) -> tuple[Collector, ...]:
    """Adapters in display order. A missing API key leaves the adapter present but inactive."""
    abuseipdb_key = settings.abuseipdb_api_key
    otx_key = settings.otx_api_key
    return (
        AbuseIPDBCollector(
            api_key=abuseipdb_key.get_secret_value() if abuseipdb_key else None,
            client=client,
            cache_ttl_seconds=settings.abuseipdb_cache_ttl_seconds,
        ),
        OTXCollector(
            api_key=otx_key.get_secret_value() if otx_key else None,
            client=client,
            cache_ttl_seconds=settings.otx_cache_ttl_seconds,
        ),
    )

"""Keeps docker-compose.yml and .env.example in step with the application settings.

Settings ignore unknown variables, so a misspelt or forgotten name in a deployment file would
leave a feature silently unconfigured instead of failing. These tests turn that into a failure.
"""

import ipaddress
import re
from typing import Any

import pytest
import yaml

from app.core.config import REPO_ROOT, Settings

COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"

# Read by uvicorn itself: passed to the container, but not an application setting.
UVICORN_VARIABLES = {"FORWARDED_ALLOW_IPS"}
# Not configurable from the environment, or assembled by Compose from the POSTGRES_* values.
NOT_PASSED_THROUGH = {"APP_NAME", "APP_VERSION", "DATABASE_URL"}
PROVIDER_KEYS = {"ABUSEIPDB_API_KEY", "OTX_API_KEY"}
# Secrets that only the API process may receive; the one-shot migration job must not.
BACKEND_ONLY_SECRETS = PROVIDER_KEYS | {
    "VIRUSTOTAL_API_KEY",
    "THREATFOX_API_KEY",
    "CIPHERFORGE_MASTER_KEY",
}
# Fixed to the Compose volume, so it is deliberately not an overridable ${NAME:-default} entry.
FIXED_IN_COMPOSE = {"ENCRYPTED_FILE_STORAGE_PATH"}
# Their defaults (production, Entra) cannot start without real tenant values, so tests pin them.
PINNED_FOR_TESTS = {"ENVIRONMENT", "AUTH_MODE"}
PROVIDER_TUNING = (
    "abuseipdb_cache_ttl_seconds",
    "otx_cache_ttl_seconds",
    "virustotal_cache_ttl_seconds",
    "threatfox_cache_ttl_seconds",
    "provider_timeout_seconds",
    "virustotal_timeout_seconds",
    "threatfox_timeout_seconds",
    "virustotal_max_retries",
    "threatfox_max_retries",
    "investigate_rate_limit_per_minute",
)

FALLBACK = re.compile(r"^\$\{(?P<name>[A-Z][A-Z0-9_]*):-(?P<default>.*)\}$")
DOCUMENTED = re.compile(r"^#?\s*(?P<name>[A-Z][A-Z0-9_]*)=", re.MULTILINE)
SETTING_NAMES = {name.upper() for name in Settings.model_fields}


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def backend_environment(compose: dict[str, Any]) -> dict[str, str]:
    return compose["services"]["backend"]["environment"]


def fallbacks(environment: dict[str, str]) -> dict[str, str]:
    """The ``NAME: ${NAME:-default}`` entries, as {NAME: default}."""
    found: dict[str, str] = {}
    for name, value in environment.items():
        match = FALLBACK.match(str(value))
        if match:
            assert match["name"] == name, f"{name} reads a differently named variable"
            found[name] = match["default"]
    return found


def build_settings() -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        auth_mode="dev",
        database_url="sqlite+pysqlite:///unused.db",
    )


def test_backend_receives_every_setting(backend_environment: dict[str, str]) -> None:
    missing = SETTING_NAMES - NOT_PASSED_THROUGH - set(backend_environment)
    assert not missing, f"docker-compose.yml does not pass {sorted(missing)} to the backend"


def test_backend_receives_only_variables_something_reads(
    backend_environment: dict[str, str],
) -> None:
    unknown = set(backend_environment) - SETTING_NAMES - UVICORN_VARIABLES
    assert not unknown, f"{sorted(unknown)} are not settings, so the API would ignore them"


def test_compose_fallbacks_equal_the_setting_defaults(
    backend_environment: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    values = fallbacks(backend_environment)
    assert PROVIDER_KEYS.issubset(values), "provider keys must default to blank"

    reference = build_settings()
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    configured = build_settings()

    for name, value in values.items():
        field = name.lower()
        if name in UVICORN_VARIABLES:
            continue
        if name in PINNED_FOR_TESTS:
            assert value == Settings.model_fields[field].default, name
        else:
            assert getattr(configured, field) == getattr(reference, field), name


def test_provider_keys_are_not_given_to_the_migration_job(compose: dict[str, Any]) -> None:
    assert not BACKEND_ONLY_SECRETS & set(compose["services"]["migrate"]["environment"])
    assert BACKEND_ONLY_SECRETS.issubset(compose["services"]["backend"]["environment"])


def test_encrypted_files_are_stored_on_a_named_volume(
    compose: dict[str, Any], backend_environment: dict[str, str]
) -> None:
    backend = compose["services"]["backend"]
    path = backend_environment["ENCRYPTED_FILE_STORAGE_PATH"]
    assert not FIXED_IN_COMPOSE & set(fallbacks(backend_environment)), "path must stay fixed"
    assert f"encrypted_files:{path}" in backend["volumes"]
    assert "encrypted_files" in compose["volumes"]
    assert backend["read_only"] is True, "the root file system must stay read-only"


def test_forwarded_headers_are_trusted_only_from_private_networks_by_default(
    backend_environment: dict[str, str],
) -> None:
    default = fallbacks(backend_environment)["FORWARDED_ALLOW_IPS"]
    networks = [ipaddress.ip_network(part.strip()) for part in default.split(",")]
    assert networks
    assert all(network.is_private for network in networks)


def test_env_example_documents_every_variable_compose_passes(
    backend_environment: dict[str, str],
) -> None:
    text = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
    documented = {match["name"] for match in DOCUMENTED.finditer(text)}
    missing = set(backend_environment) - documented
    assert not missing, f".env.example does not document {sorted(missing)}"


def test_env_example_is_a_valid_keyless_configuration() -> None:
    settings = Settings(_env_file=ENV_EXAMPLE_PATH)

    assert settings.abuseipdb_api_key is None
    assert settings.otx_api_key is None
    assert settings.virustotal_api_key is None
    assert settings.threatfox_api_key is None
    assert settings.cipherforge_master_key is None
    for name in PROVIDER_TUNING:
        assert getattr(settings, name) == Settings.model_fields[name].default, name


def test_env_example_matches_every_setting_default() -> None:
    """The template documents the shipped defaults, so a drifting value is a documentation bug."""
    templated = Settings(_env_file=ENV_EXAMPLE_PATH)
    reference = Settings(
        _env_file=None,
        environment="development",
        auth_mode="dev",
        log_format="console",
        database_url=templated.database_url,
    )
    for name in Settings.model_fields:
        assert getattr(templated, name) == getattr(reference, name), name

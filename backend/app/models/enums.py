"""Closed vocabularies shared by the ORM models, normalizer, collectors and API.

Kept free of SQLAlchemy imports so pure modules (normalization, scoring) can use them.
"""

from enum import StrEnum


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"


class IndicatorStatus(StrEnum):
    """Evidence state of an indicator as of its last check.

    ``active``: at least one provider answered freshly. ``stale``: no fresh provider evidence.
    """

    ACTIVE = "active"
    STALE = "stale"


class ObservationStatus(StrEnum):
    """Stored observation outcomes. Failures (errors, rate limits) are never stored."""

    OK = "ok"
    NO_DATA = "no_data"

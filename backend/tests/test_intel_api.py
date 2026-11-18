"""The threat-intelligence HTTP API: authorization, validation, rate limiting and the contract.

Each test drives the real application (middleware, authentication, service, storage and audit
trail) in Entra mode against a migrated database (SQLite and PostgreSQL), with scripted providers
instead of the network.
"""

import hashlib
import json
import logging
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select

from app.collectors.base import ProviderStatus
from app.main import create_app
from app.models.audit import AuditLog
from app.models.threat import ThreatIndicator, ThreatObservation
from app.services.intel_service import IntelService, RequestContext
from tests.conftest import CLIENT_ID, TENANT_ID, TokenFactory
from tests.intel_helpers import (
    MODERATE,
    STRONG,
    ActsWhenAsked,
    Clock,
    FakeAbuse,
    FakeOtx,
    answer,
    failure,
)

INVESTIGATE = "/api/v1/intel/investigate"
INDICATORS = "/api/v1/intel/indicators"
INDICATOR = INDICATORS + "/{indicator_id}"
BULK_DELETE = INDICATORS + "/bulk-delete"
STATS = "/api/v1/intel/stats"
OVERVIEW = "/api/v1/intel/overview"
ROUTES = [
    ("POST", INVESTIGATE),
    ("GET", INDICATOR),
    ("DELETE", INDICATOR),
    ("POST", BULK_DELETE),
    ("GET", INDICATORS),
    ("GET", STATS),
    ("GET", OVERVIEW),
]

IP = "185.220.101.45"
TARGET = f"ipv4:{IP}"
DOMAIN = "evil.example.com"
QUIET_DOMAIN = "quiet.example.org"
UNANSWERED = "unanswered.example.net"
SHA256 = hashlib.sha256(b"cipherforge").hexdigest()
CLIENT_ADDRESS = "203.0.113.7"
ANALYST = "SecurityAnalyst"
XSS = "<img src=x onerror=alert(document.cookie)>"


# --- Harness ------------------------------------------------------------------------------


@dataclass
class Api:
    app: FastAPI
    client: TestClient
    clock: Clock
    abuse: FakeAbuse
    otx: FakeOtx
    tokens: TokenFactory
    analyst: dict[str, str]

    def auth(self, roles: Sequence[str] = (ANALYST,), *, oid: str = "oid-456") -> dict[str, str]:
        token = self.tokens.make({"roles": list(roles), "oid": oid})
        return {"Authorization": f"Bearer {token}"}

    def request(
        self, method: str, path: str, *, headers: dict[str, str] | None = None, **kwargs: Any
    ) -> Response:
        """Send a request as an analyst unless ``headers`` is given (``{}`` is anonymous)."""
        return self.client.request(
            method, path, headers=self.analyst if headers is None else headers, **kwargs
        )

    def investigate(
        self, indicator: str, *, refresh: bool = False, headers: dict[str, str] | None = None
    ) -> Response:
        body = {"indicator": indicator, "refresh": refresh}
        return self.request("POST", INVESTIGATE, json=body, headers=headers)

    def get(self, path: str, *, headers: dict[str, str] | None = None, **params: Any) -> Response:
        return self.request("GET", path, params=params, headers=headers)

    def rows(self, statement: Any) -> list[Any]:
        with self.app.state.session_factory() as session:
            return list(session.scalars(statement))

    @property
    def audit(self) -> list[AuditLog]:
        return self.rows(select(AuditLog).order_by(AuditLog.id))


ApiFactory = Callable[..., Api]


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def build_api(
    make_settings: Callable[..., Any],
    entra_validator: Any,
    tokens: TokenFactory,
    clock: Clock,
    db_url: str,
) -> Iterator[ApiFactory]:
    with ExitStack() as stack:

        def factory(
            *,
            abuse: FakeAbuse | None = None,
            otx: FakeOtx | None = None,
            client_address: str = CLIENT_ADDRESS,
            **settings: Any,
        ) -> Api:
            if abuse is None:
                abuse = FakeAbuse(
                    [answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1), tags=["a"])]
                )
            if otx is None:
                otx = FakeOtx(
                    [answer("otx", signal=MODERATE, evidence_at=clock.ago(days=2), tags=["b"])]
                )
            options = {
                "auth_mode": "entra",
                "entra_tenant_id": TENANT_ID,
                "entra_client_id": CLIENT_ID,
                "database_url": db_url,
                # Keep unrelated tests clear of the budget; the rate-limit tests set their own.
                "investigate_rate_limit_per_minute": 600,
                **settings,
            }
            app = create_app(
                make_settings(**options),
                token_validator=entra_validator,
                intel_service=IntelService([abuse, otx], clock=clock),
            )
            client = stack.enter_context(TestClient(app, client=(client_address, 50000)))
            api = Api(app, client, clock, abuse, otx, tokens, analyst={})
            api.analyst = api.auth()
            return api

        yield factory


@pytest.fixture
def api(build_api: ApiFactory) -> Api:
    return build_api()


@pytest.fixture
def seeded(build_api: ApiFactory, clock: Clock) -> tuple[Api, dict[str, str]]:
    """Four investigated indicators, one second apart, spanning three classifications."""
    abuse = FakeAbuse(
        answers={TARGET: answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1))}
    )
    otx = FakeOtx(
        answers={
            TARGET: answer("otx", signal=MODERATE, evidence_at=clock.ago(days=2)),
            f"domain:{DOMAIN}": answer(
                "otx", signal=STRONG, evidence_at=clock.ago(days=1), tags=["phishing"]
            ),
            f"sha256:{SHA256}": answer("otx", signal=0.2, evidence_at=clock.ago(days=1)),
        }
    )
    api = build_api(abuse=abuse, otx=otx)
    ids: dict[str, str] = {}
    for name, value in (("ip", IP), ("domain", DOMAIN), ("quiet", QUIET_DOMAIN), ("hash", SHA256)):
        response = api.investigate(value)
        assert response.status_code == 200, response.text
        ids[name] = response.json()["indicator"]["indicator_id"]
        clock.advance(seconds=1)
    return api, ids


def call(api: Api, method: str, path: str, *, headers: dict[str, str] | None = None) -> Response:
    """A valid request to any intel route."""
    body: dict[str, Any] | None = None
    if method == "POST":
        body = {"indicator_ids": [str(uuid.uuid4())]} if path == BULK_DELETE else {"indicator": IP}
    return api.request(method, path.format(indicator_id=uuid.uuid4()), headers=headers, json=body)


def values(response: Response) -> list[str]:
    assert response.status_code == 200, response.text
    return [item["indicator_value"] for item in response.json()["items"]]


def untouched(api: Api) -> bool:
    """Nothing was queried, stored or audited."""
    return not (api.abuse.calls or api.otx.calls or api.audit or api.rows(select(ThreatIndicator)))


# --- Authentication and authorization --------------------------------------------------------


def test_the_intel_routes_are_exactly_the_ones_that_are_tested_as_protected(api: Api) -> None:
    paths = api.app.openapi()["paths"]
    operations = {
        (method.upper(), path): operation
        for path, item in paths.items()
        if path.startswith("/api/v1/intel")
        for method, operation in item.items()
    }

    assert set(operations) == set(ROUTES)  # a new route must be added to ROUTES, and so tested
    for operation in operations.values():
        assert {"EntraBearer": []} in operation["security"]


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_anonymous_callers_are_rejected_on_every_route(api: Api, method: str, path: str) -> None:
    response = call(api, method, path, headers={})

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "unauthorized"
    assert untouched(api)


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize("roles", [["User"], [], ["Hacker"]], ids=["user", "no-roles", "unknown"])
def test_callers_without_an_analyst_role_are_forbidden_on_every_route(
    api: Api, method: str, path: str, roles: list[str]
) -> None:
    response = call(api, method, path, headers=api.auth(roles))

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "Insufficient permissions."
    assert untouched(api)


def test_anonymous_callers_get_no_validation_feedback(api: Api) -> None:
    response = api.request("POST", INVESTIGATE, headers={}, json={"unexpected": True})

    assert response.status_code == 401


@pytest.mark.parametrize("flaw", ["expired", "wrong-audience", "alg-none", "hs256-confusion"])
def test_forged_or_expired_tokens_cannot_use_the_intel_api(
    api: Api, tokens: TokenFactory, flaw: str
) -> None:
    token = {
        "expired": lambda: tokens.make({"exp": 1_000_000_000}),
        "wrong-audience": lambda: tokens.make({"aud": "someone-else"}),
        "alg-none": tokens.forge_alg_none,
        "hs256-confusion": tokens.forge_hs256_with_public_key,
    }[flaw]()

    response = api.investigate(IP, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert untouched(api)


@pytest.mark.parametrize("role", [ANALYST, "Admin"])
def test_analysts_and_admins_can_investigate(api: Api, role: str) -> None:
    response = api.investigate(IP, headers=api.auth([role]))

    assert response.status_code == 200


def test_dev_auth_mode_serves_the_local_analyst_without_a_token(build_api: ApiFactory) -> None:
    api = build_api(auth_mode="dev")

    response = api.investigate(IP, headers={})

    assert response.status_code == 200
    assert [audit.actor for audit in api.audit] == ["dev-user"]


# --- Investigating ------------------------------------------------------------------------------


def test_investigating_returns_each_provider_then_the_correlated_score(api: Api) -> None:
    response = api.investigate(IP)

    assert response.status_code == 200
    body = response.json()
    indicator = body["indicator"]
    assert indicator["indicator_type"] == "ipv4"
    assert indicator["indicator_value"] == IP
    assert indicator["risk_score"] == 78
    assert indicator["classification"] == "high"
    assert indicator["confidence"] == 90
    assert indicator["status"] == "active"
    assert indicator["source_count"] == 2
    assert indicator["tags"] == ["a", "b"]

    providers = {provider["provider"]: provider for provider in body["providers"]}
    assert list(providers) == ["abuseipdb", "otx"]
    abuse = providers["abuseipdb"]
    assert abuse["display_name"] == "AbuseIPDB"
    assert (abuse["status"], abuse["freshness"], abuse["from_cache"]) == ("ok", "fresh", False)
    assert abuse["signal"] == STRONG
    assert providers["otx"]["signal"] == MODERATE

    score = body["score"]
    assert score["methodology"] == "intel-risk-v1"
    assert (score["score"], score["classification"], score["confidence"]) == (78, "high", 90)
    assert (score["answered_sources"], score["contributing_sources"]) == (2, 2)
    assert score["factors"]
    assert score["recommended_actions"]
    assert score["scored_at"] == indicator["scored_at"]
    assert body["internal_evidence"]["available"] is False

    [audit] = api.audit
    assert (audit.actor, audit.action, audit.target, audit.result) == (
        "oid-456",
        "IOC_LOOKUP",
        TARGET,
        "success",
    )
    assert audit.source_ip == CLIENT_ADDRESS
    assert audit.correlation_id == response.headers["X-Correlation-ID"]


@pytest.mark.parametrize(
    ("peer", "recorded"),
    [
        ("198.51.100.4", "198.51.100.4"),
        ("2001:db8::7", "2001:db8::7"),
        ("not-an-ip", None),
        ("1.2.3.4, 5.6.7.8", None),
        ("<script>alert(1)</script>", None),
        ("203.0.113.1' OR '1'='1", None),
    ],
)
def test_only_a_valid_address_is_recorded_as_the_source(
    build_api: ApiFactory, peer: str, recorded: str | None
) -> None:
    # uvicorn copies X-Forwarded-For into the client address, unchecked, when the peer is trusted.
    api = build_api(client_address=peer)

    assert api.investigate(IP).status_code == 200

    [audit] = api.audit
    assert audit.source_ip == recorded


def test_repeating_an_investigation_is_served_from_storage(api: Api) -> None:
    first = api.investigate(IP).json()

    second = api.investigate(IP).json()

    assert second["indicator"]["indicator_id"] == first["indicator"]["indicator_id"]
    assert [provider["from_cache"] for provider in second["providers"]] == [True, True]
    assert second["score"]["score"] == first["score"]["score"]
    assert (api.abuse.calls, api.otx.calls) == ([TARGET], [TARGET])
    assert len(api.audit) == 2  # every lookup is audited, cached or not


def test_refresh_is_honoured_but_cannot_be_used_to_hammer_providers(api: Api) -> None:
    api.investigate(IP)

    api.investigate(IP, refresh=True)
    assert len(api.abuse.calls) == 1  # inside the 60 second refresh floor

    api.clock.advance(seconds=61)
    api.investigate(IP)
    assert len(api.abuse.calls) == 1  # still cached
    api.investigate(IP, refresh=True)
    assert len(api.abuse.calls) == 2


def test_equivalent_spellings_resolve_to_one_indicator(api: Api) -> None:
    spellings = [IP, "185[.]220[.]101[.]45", f"  {IP}  "]

    indicators = [api.investigate(spelling).json()["indicator"] for spelling in spellings]

    assert len({indicator["indicator_id"] for indicator in indicators}) == 1
    assert {indicator["indicator_value"] for indicator in indicators} == {IP}
    assert len(api.rows(select(ThreatIndicator))) == 1


REJECTED = {
    "private-address": "10.0.0.1",
    "md5-hash": "d41d8cd98f00b204e9800998ecf8427e",
    "ftp-url": "ftp://example.com/payload",
    "script-tag": "<script>alert(1)</script>",
    "sql-quote": "' OR 1=1 --",
    "stacked-query": "1.2.3.4; DROP TABLE threat_indicators",
    "path-traversal": "../../etc/passwd",
    "javascript-uri": "javascript:alert(1)",
    "url-credentials": "https://user:hunter2@example.com/",
    "nul-byte": "evil.example.com\u0000",
}


@pytest.mark.parametrize("payload", list(REJECTED.values()), ids=list(REJECTED))
def test_invalid_indicators_are_rejected_and_audited_without_being_echoed(
    api: Api, payload: str
) -> None:
    response = api.investigate(payload)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    # JSON escapes control characters, so look for the escaped spelling as well.
    spellings = {payload, json.dumps(payload)[1:-1]}
    assert not any(spelling in response.text for spelling in spellings)
    assert error["correlation_id"] == response.headers["X-Correlation-ID"]
    assert api.abuse.calls == [] and api.otx.calls == []
    assert api.rows(select(ThreatIndicator)) == []
    [audit] = api.audit
    assert (audit.actor, audit.action, audit.result, audit.target) == (
        "oid-456",
        "IOC_LOOKUP",
        "rejected",
        None,
    )
    assert not any(spelling in json.dumps(audit.details) for spelling in spellings)
    assert audit.correlation_id == error["correlation_id"]


@pytest.mark.parametrize(
    ("hostile", "stored"),
    [
        (
            "https://example.com/?q=<script>alert(1)</script>",
            "https://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E",
        ),
        ("https://example.com/?id=1'--", "https://example.com/?id=1'--"),
    ],
    ids=["xss", "sql"],
)
def test_hostile_but_valid_urls_are_stored_and_returned_as_inert_data(
    api: Api, hostile: str, stored: str
) -> None:
    response = api.investigate(hostile)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json()["indicator"]["indicator_value"] == stored
    assert api.rows(select(ThreatIndicator.indicator_value)) == [stored]
    assert api.get(STATS).json()["total_indicators"] == 1  # the tables are intact


MALFORMED_BODIES = {
    "empty-object": {},
    "empty-indicator": {"indicator": ""},
    "number": {"indicator": 123},
    "null": {"indicator": None},
    "list": {"indicator": [IP]},
    "bad-refresh": {"indicator": IP, "refresh": "ECHO-MARKER-123"},
    "unknown-field": {"indicator": IP, "internal_only": True},
    "too-long": {"indicator": "x" * 2049},
}


@pytest.mark.parametrize("body", list(MALFORMED_BODIES.values()), ids=list(MALFORMED_BODIES))
def test_malformed_bodies_are_rejected_before_any_work_is_done(
    api: Api, body: dict[str, Any]
) -> None:
    response = api.request("POST", INVESTIGATE, json=body)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert all(set(detail) == {"loc", "msg", "type"} for detail in error["details"])
    assert "ECHO-MARKER-123" not in response.text
    assert "x" * 20 not in response.text
    assert untouched(api)


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (f'{{"indicator": "{IP}"}}', "text/plain"),
        (f"indicator={IP}", "application/x-www-form-urlencoded"),
        ("{not json", "application/json"),
        (f'["{IP}"]', "application/json"),
        (f'"{IP}"', "application/json"),
    ],
    ids=["text-plain", "form", "broken-json", "json-array", "json-string"],
)
def test_bodies_that_are_not_a_json_object_are_rejected(
    api: Api, content: str, content_type: str
) -> None:
    headers = {**api.analyst, "Content-Type": content_type}

    response = api.request("POST", INVESTIGATE, content=content, headers=headers)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert untouched(api)


def test_a_failing_provider_is_reported_without_failing_the_investigation(
    build_api: ApiFactory,
) -> None:
    api = build_api(otx=FakeOtx([failure(ProviderStatus.RATE_LIMITED, "OTX rate limit reached.")]))

    response = api.investigate(IP)

    assert response.status_code == 200
    body = response.json()
    providers = {provider["provider"]: provider for provider in body["providers"]}
    assert providers["abuseipdb"]["status"] == "ok"
    assert providers["otx"]["status"] == "rate_limited"
    assert providers["otx"]["message"] == "OTX rate limit reached."
    assert providers["otx"]["signal"] is None
    assert body["score"]["score"] == 45  # one source alone is capped well below Critical
    assert [audit.result for audit in api.audit] == ["partial"]


def test_with_no_provider_configured_the_response_says_so(build_api: ApiFactory) -> None:
    api = build_api(abuse=FakeAbuse(api_key=None), otx=FakeOtx(api_key=None))

    response = api.investigate(IP)

    assert response.status_code == 200
    body = response.json()
    assert [provider["status"] for provider in body["providers"]] == [
        "not_configured",
        "not_configured",
    ]
    assert body["indicator"]["risk_score"] == 0
    assert body["indicator"]["classification"] == "informational"
    assert body["score"]["answered_sources"] == 0
    assert body["score"]["uncertainty"]
    assert not any(
        "No action is needed" in action for action in body["score"]["recommended_actions"]
    )
    assert api.abuse.calls == [] and api.otx.calls == []


def test_provider_text_is_returned_verbatim_as_json_data(
    build_api: ApiFactory, clock: Clock
) -> None:
    hostile = answer(
        "otx",
        signal=MODERATE,
        evidence_at=clock.ago(days=1),
        tags=[XSS],
        notes=[XSS],
        summary={"pulse_names": [XSS]},
    )
    api = build_api(otx=FakeOtx([hostile]))

    response = api.investigate(IP)

    assert response.headers["content-type"] == "application/json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    otx = response.json()["providers"][1]
    assert otx["summary"]["pulse_names"] == [XSS]  # escaping is the renderer's job, not ours
    assert XSS in otx["tags"]


# --- Rate limiting ------------------------------------------------------------------------------


def test_the_investigation_budget_is_per_analyst_and_leaves_reads_alone(
    build_api: ApiFactory,
) -> None:
    api = build_api(investigate_rate_limit_per_minute=2)
    assert [api.investigate(IP).status_code for _ in range(2)] == [200, 200]

    limited = api.investigate(IP)

    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 60
    error = limited.json()["error"]
    assert error["code"] == "rate_limited"
    assert error["message"] == "Too many investigations. Try again shortly."
    assert len(api.audit) == 2  # the refused request did no work
    assert api.investigate(IP, headers=api.auth(oid="another-analyst")).status_code == 200
    assert api.get(STATS).status_code == 200


def test_unauthorized_callers_do_not_spend_an_analysts_budget(build_api: ApiFactory) -> None:
    api = build_api(investigate_rate_limit_per_minute=2)
    without_role = api.auth(["User"])  # the same subject as the analyst
    for _ in range(5):
        assert api.investigate(IP, headers={}).status_code == 401
        assert api.investigate(IP, headers=without_role).status_code == 403

    assert [api.investigate(IP).status_code for _ in range(3)] == [200, 200, 429]


def test_rejected_input_still_spends_the_budget(build_api: ApiFactory) -> None:
    api = build_api(investigate_rate_limit_per_minute=2)

    assert [api.investigate("not an indicator").status_code for _ in range(3)] == [422, 422, 429]


# --- Reading stored indicators ---------------------------------------------------------


def test_a_stored_indicator_is_read_back_without_calling_providers(api: Api) -> None:
    posted = api.investigate(IP).json()

    response = api.get(f"{INDICATORS}/{posted['indicator']['indicator_id']}")

    assert response.status_code == 200
    fetched = response.json()
    assert fetched["indicator"] == posted["indicator"]
    assert fetched["score"] == posted["score"]
    assert [provider["from_cache"] for provider in fetched["providers"]] == [True, True]

    def without_cache_flag(providers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{k: v for k, v in provider.items() if k != "from_cache"} for provider in providers]

    assert without_cache_flag(fetched["providers"]) == without_cache_flag(posted["providers"])
    assert (api.abuse.calls, api.otx.calls) == ([TARGET], [TARGET])
    assert len(api.audit) == 1  # lookups are audited; reads of stored indicators are not


def test_an_unknown_indicator_is_a_404(api: Api) -> None:
    response = api.get(f"{INDICATORS}/{uuid.uuid4()}")

    assert response.status_code == 404
    error = response.json()["error"]
    assert (error["code"], error["message"]) == ("not_found", "Indicator not found.")


@pytest.mark.parametrize(
    "bad_id",
    ["not-a-uuid", "' OR 1=1 --", "<img src=x onerror=alert(1)>", "0" * 40],
    ids=["text", "sql", "markup", "too-long"],
)
def test_a_malformed_indicator_id_is_a_422(api: Api, bad_id: str) -> None:
    response = api.get(f"{INDICATORS}/{quote(bad_id, safe='')}")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bad_id not in response.text


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "</script>", "a/b"])
def test_an_id_containing_a_slash_matches_no_route_and_is_not_echoed(api: Api, bad_id: str) -> None:
    response = api.get(f"{INDICATORS}/{quote(bad_id, safe='')}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    assert bad_id not in response.text
    assert untouched(api)


def test_the_list_defaults_to_most_recently_investigated_first(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, ids = seeded

    response = api.get(INDICATORS)

    assert values(response) == [SHA256, QUIET_DOMAIN, DOMAIN, IP]
    page = response.json()
    assert (page["total"], page["limit"], page["offset"]) == (4, 25, 0)
    assert [item["indicator_id"] for item in page["items"]] == [
        ids["hash"],
        ids["quiet"],
        ids["domain"],
        ids["ip"],
    ]


def test_the_list_can_be_ordered_by_risk(seeded: tuple[Api, dict[str, str]]) -> None:
    api, _ = seeded

    response = api.get(INDICATORS, sort="risk")

    assert values(response) == [IP, DOMAIN, SHA256, QUIET_DOMAIN]
    assert [item["risk_score"] for item in response.json()["items"]] == [78, 45, 9, 0]


def test_the_list_filters_combine(seeded: tuple[Api, dict[str, str]]) -> None:
    api, _ = seeded

    assert values(api.get(INDICATORS, type="domain")) == [QUIET_DOMAIN, DOMAIN]
    assert values(api.get(INDICATORS, classification="high")) == [IP]
    assert values(api.get(INDICATORS, classification="informational")) == [SHA256, QUIET_DOMAIN]
    assert values(api.get(INDICATORS, q="EXAMPLE")) == [QUIET_DOMAIN, DOMAIN]
    assert values(api.get(INDICATORS, type="domain", classification="medium")) == [DOMAIN]
    assert values(api.get(INDICATORS, type="ipv6")) == []


def test_a_classification_can_be_repeated_to_match_several_bands(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, _ = seeded

    assert values(api.get(INDICATORS, classification=["high", "medium"])) == [DOMAIN, IP]
    assert values(api.get(INDICATORS, classification=["high", "high"])) == [IP]
    assert values(api.get(INDICATORS, classification=["high", "medium"], type="domain")) == [DOMAIN]


def test_the_list_tells_indicators_a_provider_answered_for_from_those_none_did(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, _ = seeded
    api.otx.answers[f"domain:{UNANSWERED}"] = failure(ProviderStatus.ERROR, "OTX failed.")
    assert api.investigate(UNANSWERED).status_code == 200

    items = api.get(INDICATORS).json()["items"]
    unanswered = [item["indicator_value"] for item in items if item["confidence"] == 0]
    answered = [item["indicator_value"] for item in items if item["confidence"] > 0]
    assert unanswered == [UNANSWERED], "the data must really hold one unassessed indicator"

    assert values(api.get(INDICATORS, assessed="false")) == unanswered
    assert values(api.get(INDICATORS, assessed="true")) == answered
    # It scores 0, which is "informational" by score, but nothing was assessed.
    assert UNANSWERED in values(api.get(INDICATORS, classification="informational"))
    informational = api.get(INDICATORS, classification="informational", assessed="true")
    assert UNANSWERED not in values(informational)
    assert values(api.get(INDICATORS, type="domain", assessed="false")) == unanswered
    assert values(api.get(INDICATORS, type="sha256", assessed="false")) == []


def test_list_pages_are_complete_and_do_not_overlap(seeded: tuple[Api, dict[str, str]]) -> None:
    api, _ = seeded
    everything = values(api.get(INDICATORS))

    first = api.get(INDICATORS, limit=3, offset=0)
    second = api.get(INDICATORS, limit=3, offset=3)

    assert values(first) + values(second) == everything
    assert (first.json()["total"], second.json()["total"]) == (4, 4)
    assert (second.json()["limit"], second.json()["offset"]) == (3, 3)
    assert values(api.get(INDICATORS, offset=4)) == []


BAD_QUERIES = {
    "limit-zero": {"limit": 0},
    "limit-negative": {"limit": -1},
    "limit-too-big": {"limit": 101},
    "limit-text": {"limit": "many"},
    "offset-negative": {"offset": -1},
    "offset-too-big": {"offset": 10_001},
    "unknown-type": {"type": "bogus"},
    "unknown-classification": {"classification": "Severe"},
    "one-unknown-among-valid-classifications": {"classification": ["high", "Severe"]},
    "too-many-classifications": {"classification": ["low"] * 6},
    "unknown-assessed": {"assessed": "maybe"},
    "unknown-sort": {"sort": "random"},
    "long-search": {"q": "a" * 257},
}


@pytest.mark.parametrize("params", list(BAD_QUERIES.values()), ids=list(BAD_QUERIES))
def test_list_parameters_are_bounded(
    seeded: tuple[Api, dict[str, str]], params: dict[str, Any]
) -> None:
    api, _ = seeded

    response = api.get(INDICATORS, **params)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_the_limits_of_the_list_parameters_are_inclusive(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, _ = seeded

    for params in ({"limit": 1}, {"limit": 100}, {"offset": 10_000}, {"q": "a" * 256}):
        assert api.get(INDICATORS, **params).status_code == 200


@pytest.mark.parametrize(
    "text",
    ["' OR '1'='1", "%", "_", "\\", "<script>alert(1)</script>", "1; DROP TABLE threat_indicators"],
    ids=["sql-or", "percent", "underscore", "backslash", "script", "stacked-query"],
)
def test_search_text_is_matched_literally(seeded: tuple[Api, dict[str, str]], text: str) -> None:
    api, _ = seeded

    response = api.get(INDICATORS, q=text)

    assert values(response) == []
    assert response.json()["total"] == 0
    assert api.get(STATS).json()["total_indicators"] == 4


def test_stats_summarise_the_stored_indicators(seeded: tuple[Api, dict[str, str]]) -> None:
    api, _ = seeded
    api.investigate("not an indicator")  # rejected lookups are not counted

    response = api.get(STATS)

    assert response.status_code == 200
    assert response.json() == {
        "total_indicators": 4,
        "by_classification": {
            "informational": 2,
            "low": 0,
            "medium": 1,
            "high": 1,
            "critical": 0,
        },
        "by_type": {"ipv4": 1, "ipv6": 0, "domain": 2, "url": 0, "sha256": 1},
        "lookups_last_24h": 4,
        "providers": [
            {
                "name": "abuseipdb",
                "display_name": "AbuseIPDB",
                "configured": True,
                "supported_types": ["ipv4", "ipv6"],
                "simulated": False,
            },
            {
                "name": "otx",
                "display_name": "AlienVault OTX",
                "configured": True,
                "supported_types": ["domain", "ipv4", "ipv6", "sha256", "url"],
                "simulated": False,
            },
        ],
    }


def test_stats_of_an_empty_database_are_zeros(api: Api) -> None:
    body = api.get(STATS).json()

    assert body["total_indicators"] == 0
    assert body["lookups_last_24h"] == 0
    assert set(body["by_classification"].values()) == {0}
    assert set(body["by_type"].values()) == {0}


def test_the_overview_summarises_the_stored_data(seeded: tuple[Api, dict[str, str]]) -> None:
    api, ids = seeded
    api.investigate("not an indicator")  # a rejected input is not a lookup

    response = api.get(OVERVIEW)

    assert response.status_code == 200
    body = response.json()
    assert body["kpis"]["total_indicators"] == 4
    assert body["kpis"]["lookups_24h"] == 4
    assert body["kpis"]["not_assessed_indicators"] == 0
    assert body["by_classification"] == {
        "informational": 2,
        "low": 0,
        "medium": 1,
        "high": 1,
        "critical": 0,
        "not_assessed": 0,
    }
    assert [row["indicator_type"] for row in body["matrix"]] == [
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "sha256",
    ]
    assert [item["indicator_id"] for item in body["top_risk"]][:2] == [ids["ip"], ids["domain"]]
    assert [item["indicator_id"] for item in body["recent"]] == [
        ids["hash"],
        ids["quiet"],
        ids["domain"],
        ids["ip"],
    ]
    assert len(body["series"]) == 14
    assert sum(point["lookups"] for point in body["series"]) == 4
    assert [provider["simulated"] for provider in body["providers"]] == [False, False]


def test_the_overview_of_an_empty_database_is_complete_and_zeroed(api: Api) -> None:
    body = api.get(OVERVIEW).json()

    assert set(body["kpis"].values()) == {0}
    assert len(body["series"]) == 14
    assert [len(row["hours"]) for row in body["activity"]] == [24] * 7
    assert len(body["matrix"]) == 5
    for facet in ("countries", "malware_families", "attack_techniques", "tags"):
        assert body[facet] == []
    assert body["top_risk"] == [] and body["recent"] == []


# --- Deleting stored indicators ------------------------------------------------------------


def delete(
    api: Api, indicator_id: str | uuid.UUID, *, headers: dict[str, str] | None = None
) -> Response:
    return api.request("DELETE", f"{INDICATORS}/{indicator_id}", headers=headers)


def bulk_delete(
    api: Api, indicator_ids: Sequence[str | uuid.UUID], *, headers: dict[str, str] | None = None
) -> Response:
    body = {"indicator_ids": [str(indicator_id) for indicator_id in indicator_ids]}
    return api.request("POST", BULK_DELETE, json=body, headers=headers)


def deletions(api: Api) -> list[AuditLog]:
    return [entry for entry in api.audit if entry.action == "IOC_DELETE"]


def trail(api: Api) -> list[tuple[Any, ...]]:
    return [
        (e.id, e.timestamp, e.actor, e.action, e.target, e.result, e.source_ip, e.details)
        for e in api.audit
    ]


def test_a_deleted_indicator_is_gone_from_the_database_and_from_every_view(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, ids = seeded
    asked = (len(api.abuse.calls), len(api.otx.calls))

    response = delete(api, ids["ip"])

    assert response.status_code == 200
    assert response.json() == {"deleted": [ids["ip"]], "not_found": [], "observations_removed": 2}
    assert api.get(f"{INDICATORS}/{ids['ip']}").status_code == 404
    assert values(api.get(INDICATORS)) == [SHA256, QUIET_DOMAIN, DOMAIN]
    assert api.get(INDICATORS).json()["total"] == 3
    stats = api.get(STATS).json()
    assert (stats["total_indicators"], stats["by_type"]["ipv4"]) == (3, 0)
    assert stats["by_classification"]["high"] == 0
    overview = api.get(OVERVIEW).json()
    assert overview["kpis"]["total_indicators"] == 3
    shown = {item["indicator_id"] for key in ("top_risk", "recent") for item in overview[key]}
    assert shown == {ids["domain"], ids["quiet"], ids["hash"]}
    # Nothing of it is left in the tables, and the other indicators keep their answers.
    remaining = {ids["domain"], ids["quiet"], ids["hash"]}
    assert {str(row.id) for row in api.rows(select(ThreatIndicator))} == remaining
    assert sorted(str(row.indicator_id) for row in api.rows(select(ThreatObservation))) == sorted(
        remaining
    )
    assert (len(api.abuse.calls), len(api.otx.calls)) == asked  # no provider was asked


def test_an_indicator_can_only_be_deleted_once(seeded: tuple[Api, dict[str, str]]) -> None:
    api, ids = seeded
    assert delete(api, ids["ip"]).status_code == 200
    recorded = len(api.audit)

    again = delete(api, ids["ip"])

    assert again.status_code == 404
    error = again.json()["error"]
    assert (error["code"], error["message"]) == ("not_found", "Indicator not found.")
    assert len(api.audit) == recorded
    assert api.get(STATS).json()["total_indicators"] == 3


def test_a_deletion_leaves_the_audit_trail_alone_and_adds_its_own_record(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, ids = seeded
    before = trail(api)
    assert [row[3] for row in before] == ["IOC_LOOKUP"] * 4

    response = delete(api, ids["ip"], headers={**api.analyst, "X-Correlation-ID": "req-del-0001"})

    assert response.status_code == 200
    after = api.audit
    assert trail(api)[:4] == before  # every earlier record is exactly as it was
    [entry] = after[4:]
    assert (entry.actor, entry.action, entry.target, entry.result) == (
        "oid-456",
        "IOC_DELETE",
        TARGET,
        "success",
    )
    assert entry.source_ip == CLIENT_ADDRESS
    assert entry.correlation_id == "req-del-0001"
    assert entry.details == {"observations_removed": 2}
    # Lookups are counted from the audit trail, which a deletion does not change.
    assert api.get(STATS).json()["lookups_last_24h"] == 4


@pytest.mark.parametrize(
    "bad_id",
    ["not-a-uuid", "' OR 1=1 --", "<img src=x onerror=alert(1)>", "0" * 40],
    ids=["text", "sql", "markup", "too-long"],
)
def test_a_malformed_id_deletes_nothing(seeded: tuple[Api, dict[str, str]], bad_id: str) -> None:
    api, _ = seeded

    response = api.request("DELETE", f"{INDICATORS}/{quote(bad_id, safe='')}")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bad_id not in response.text
    assert api.get(STATS).json()["total_indicators"] == 4
    assert deletions(api) == []


@pytest.mark.parametrize("wildcard", ["*", "%", "all", "null"])
def test_a_wildcard_in_place_of_an_id_does_not_delete_everything(
    seeded: tuple[Api, dict[str, str]], wildcard: str
) -> None:
    api, _ = seeded

    response = api.request("DELETE", f"{INDICATORS}/{quote(wildcard, safe='')}")

    assert response.status_code == 422
    assert api.get(STATS).json()["total_indicators"] == 4
    assert deletions(api) == []


def test_a_selection_is_deleted_in_one_request(seeded: tuple[Api, dict[str, str]]) -> None:
    api, ids = seeded
    chosen = [ids["hash"], ids["domain"], ids["quiet"]]

    response = bulk_delete(api, chosen, headers={**api.analyst, "X-Correlation-ID": "req-bulk-1"})

    assert response.status_code == 200
    # One answer each from OTX for the three, and none from AbuseIPDB, which only knows IPs.
    assert response.json() == {"deleted": chosen, "not_found": [], "observations_removed": 3}
    assert values(api.get(INDICATORS)) == [IP]
    assert api.get(STATS).json()["total_indicators"] == 1
    removed = deletions(api)
    assert {entry.target for entry in removed} == {
        f"sha256:{SHA256}",
        f"domain:{DOMAIN}",
        f"domain:{QUIET_DOMAIN}",
    }
    assert {entry.correlation_id for entry in removed} == {"req-bulk-1"}
    assert {entry.actor for entry in removed} == {"oid-456"}
    assert len(api.audit) == 4 + 3


def test_ids_that_match_nothing_are_reported_and_the_others_are_deleted(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, ids = seeded
    ghost = str(uuid.uuid4())

    response = bulk_delete(api, [ghost, ids["ip"]])

    assert response.status_code == 200
    assert response.json() == {
        "deleted": [ids["ip"]],
        "not_found": [ghost],
        "observations_removed": 2,
    }
    repeated = bulk_delete(api, [ids["ip"], ghost])
    assert repeated.status_code == 200  # a retry is harmless
    assert repeated.json() == {
        "deleted": [],
        "not_found": [ids["ip"], ghost],
        "observations_removed": 0,
    }
    assert len(deletions(api)) == 1  # nothing was deleted the second time, so nothing is recorded


def test_a_repeated_id_is_deleted_and_recorded_once(seeded: tuple[Api, dict[str, str]]) -> None:
    api, ids = seeded

    response = bulk_delete(api, [ids["ip"], ids["ip"]])

    assert response.json() == {"deleted": [ids["ip"]], "not_found": [], "observations_removed": 2}
    assert len(deletions(api)) == 1


BAD_DELETE_BODIES: dict[str, dict[str, Any]] = {
    "empty-object": {},
    "no-ids": {"indicator_ids": []},
    "null": {"indicator_ids": None},
    "text": {"indicator_ids": "everything"},
    "not-an-id": {"indicator_ids": ["ECHO-MARKER-123"]},
    "one-bad-among-good": {"indicator_ids": [str(uuid.uuid4()), "ECHO-MARKER-123"]},
    "too-many": {"indicator_ids": [str(uuid.uuid4()) for _ in range(101)]},
    "unknown-field": {"indicator_ids": [str(uuid.uuid4())], "everything": True},
    "a-filter-instead-of-ids": {"type": "domain", "q": "example"},
}


@pytest.mark.parametrize("body", list(BAD_DELETE_BODIES.values()), ids=list(BAD_DELETE_BODIES))
def test_a_malformed_selection_deletes_nothing(
    seeded: tuple[Api, dict[str, str]], body: dict[str, Any]
) -> None:
    api, _ = seeded

    response = api.request("POST", BULK_DELETE, json=body)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert all(set(detail) == {"loc", "msg", "type"} for detail in error["details"])
    assert "ECHO-MARKER-123" not in response.text
    assert api.get(STATS).json()["total_indicators"] == 4
    assert deletions(api) == []


def test_a_whole_page_of_a_hundred_can_be_deleted_at_once(api: Api) -> None:
    response = bulk_delete(api, [uuid.uuid4() for _ in range(100)])

    assert response.status_code == 200
    assert len(response.json()["not_found"]) == 100


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        ('{"indicator_ids": ["%s"]}', "text/plain"),
        ("indicator_ids=%s", "application/x-www-form-urlencoded"),
    ],
    ids=["text-plain", "form"],
)
def test_a_form_or_plain_text_body_cannot_delete_anything(
    seeded: tuple[Api, dict[str, str]], content: str, content_type: str
) -> None:
    api, ids = seeded
    headers = {**api.analyst, "Content-Type": content_type}

    response = api.request("POST", BULK_DELETE, content=content % ids["ip"], headers=headers)

    assert response.status_code == 422
    assert api.get(STATS).json()["total_indicators"] == 4


@pytest.mark.parametrize("who", ["anonymous", "user", "no-roles"])
def test_only_analysts_and_admins_can_delete_a_stored_indicator(
    seeded: tuple[Api, dict[str, str]], who: str
) -> None:
    api, ids = seeded
    headers = {"anonymous": {}, "user": api.auth(["User"]), "no-roles": api.auth([])}[who]
    expected = 401 if who == "anonymous" else 403
    recorded = trail(api)

    assert delete(api, ids["ip"], headers=headers).status_code == expected
    assert bulk_delete(api, [ids["ip"], ids["domain"]], headers=headers).status_code == expected

    assert api.get(STATS).json()["total_indicators"] == 4
    assert trail(api) == recorded


def test_an_admin_can_delete_an_indicator(seeded: tuple[Api, dict[str, str]]) -> None:
    api, ids = seeded

    assert delete(api, ids["ip"], headers=api.auth(["Admin"])).status_code == 200


def test_a_deleted_indicator_can_be_investigated_again_from_scratch(
    seeded: tuple[Api, dict[str, str]],
) -> None:
    api, ids = seeded
    assert delete(api, ids["ip"]).status_code == 200
    asked = (len(api.abuse.calls), len(api.otx.calls))

    response = api.investigate(IP)

    assert response.status_code == 200
    body = response.json()
    assert body["indicator"]["indicator_id"] != ids["ip"]  # a new indicator, not a revived one
    assert [provider["from_cache"] for provider in body["providers"]] == [False, False]
    assert (len(api.abuse.calls), len(api.otx.calls)) == (asked[0] + 1, asked[1] + 1)
    assert api.get(STATS).json()["total_indicators"] == 4


def test_an_indicator_deleted_while_it_is_being_investigated_is_not_brought_back(
    build_api: ApiFactory, clock: Clock
) -> None:
    holder: list[Api] = []

    def delete_it() -> None:
        # What another analyst's request does while this investigation waits on the providers.
        api = holder[0]
        with api.app.state.session_factory() as session:
            [indicator_id] = session.scalars(select(ThreatIndicator.id))
            api.app.state.intel_service.delete_indicators(
                session, RequestContext(actor="another-analyst"), [indicator_id]
            )

    otx = ActsWhenAsked(delete_it, [answer("otx", signal=MODERATE, evidence_at=clock.ago(days=2))])
    api = build_api(otx=otx)
    holder.append(api)

    response = api.investigate(IP)

    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "conflict"
    assert "deleted while it was being investigated" in error["message"]
    assert api.rows(select(ThreatIndicator)) == []
    assert api.rows(select(ThreatObservation)) == []  # the answers were discarded, not stored
    lookup = [entry for entry in api.audit if entry.action == "IOC_LOOKUP"]
    assert [(entry.actor, entry.target, entry.result) for entry in lookup] == [
        ("oid-456", TARGET, "partial")
    ]
    assert lookup[0].details == {"refresh": False, "discarded": "indicator_deleted"}
    assert [entry.actor for entry in deletions(api)] == ["another-analyst"]
    assert api.investigate(IP).status_code == 200  # and investigating again simply works


def test_deleting_logs_counts_and_never_the_values(
    seeded: tuple[Api, dict[str, str]], caplog: pytest.LogCaptureFixture
) -> None:
    api, ids = seeded
    caplog.set_level(logging.DEBUG)

    assert delete(api, ids["ip"]).status_code == 200
    assert bulk_delete(api, [ids["domain"], ids["hash"]]).status_code == 200

    everything = "\n".join(f"{record.getMessage()} {record.__dict__}" for record in caplog.records)
    assert "request" in everything  # the capture is working
    for needle in (IP, DOMAIN, SHA256, QUIET_DOMAIN):
        assert needle not in everything
    done = [record for record in caplog.records if record.getMessage() == "indicators_deleted"]
    assert [
        (record.deleted, record.not_found, record.observations_removed)  # type: ignore[attr-defined]
        for record in done
    ] == [(1, 0, 2), (2, 0, 2)]


# --- Cross-cutting guarantees ------------------------------------------------------------------


def test_no_endpoint_returns_a_provider_key(build_api: ApiFactory, clock: Clock) -> None:
    secret = "sk-live-0123456789abcdef"
    abuse = FakeAbuse(
        [answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1))], api_key=secret
    )
    api = build_api(abuse=abuse, otx=FakeOtx(api_key=secret))
    posted = api.investigate(IP)
    indicator_id = posted.json()["indicator"]["indicator_id"]

    responses = [
        posted,
        api.investigate("not an indicator"),
        api.get(f"{INDICATORS}/{indicator_id}"),
        api.get(f"{INDICATORS}/{uuid.uuid4()}"),
        api.get(INDICATORS),
        api.get(STATS),
        api.get(OVERVIEW),
    ]

    assert [response.status_code for response in responses] == [200, 422, 200, 404, 200, 200, 200]
    for response in responses:
        assert secret not in response.text
    stored = json.dumps([(row.details, row.target) for row in api.audit])
    assert secret not in stored


def test_responses_are_never_cacheable_or_sniffable(seeded: tuple[Api, dict[str, str]]) -> None:
    api, ids = seeded
    responses = [
        api.investigate(IP),
        api.get(f"{INDICATORS}/{ids['ip']}"),
        api.get(INDICATORS),
        api.get(STATS),
        api.get(OVERVIEW),
        api.get(f"{INDICATORS}/{uuid.uuid4()}"),
        api.investigate(IP, headers={}),
    ]

    assert [response.status_code for response in responses] == [200, 200, 200, 200, 200, 404, 401]
    for response in responses:
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["content-type"] == "application/json"


def test_one_correlation_id_ties_the_response_the_audit_row_and_the_providers(api: Api) -> None:
    accepted_id, rejected_id = "req-7f3a9c1e-0042", "req-7f3a9c1e-0043"

    accepted = api.investigate(IP, headers={**api.analyst, "X-Correlation-ID": accepted_id})
    rejected = api.investigate("10.0.0.1", headers={**api.analyst, "X-Correlation-ID": rejected_id})

    assert accepted.headers["X-Correlation-ID"] == accepted_id
    assert rejected.headers["X-Correlation-ID"] == rejected_id
    assert rejected.json()["error"]["correlation_id"] == rejected_id
    assert [audit.correlation_id for audit in api.audit] == [accepted_id, rejected_id]
    assert api.abuse.correlation_ids == [accepted_id]
    assert api.otx.correlation_ids == [accepted_id]


def test_logs_never_contain_tokens_keys_indicators_or_search_text(
    build_api: ApiFactory, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "sk-live-0123456789abcdef"
    api = build_api(
        abuse=FakeAbuse(
            [answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1))], api_key=secret
        ),
        otx=FakeOtx(api_key=secret),
        investigate_rate_limit_per_minute=2,
    )
    caplog.set_level(logging.DEBUG)
    analyst, without_role = api.analyst, api.auth(["User"])
    typed = "needle-in-the-query"

    responses = [
        api.investigate(IP),
        api.investigate("' OR 1=1 --"),
        api.investigate(IP),  # over the budget of two
        api.get(INDICATORS, q=typed),
        api.investigate(IP, headers={}),
        api.investigate(IP, headers=without_role),
    ]

    assert [response.status_code for response in responses] == [200, 422, 429, 200, 401, 403]
    everything = "\n".join(f"{record.getMessage()} {record.__dict__}" for record in caplog.records)
    assert "request" in everything  # the capture is working
    for needle in (IP, "OR 1=1", typed, secret):
        assert needle not in everything
    for headers in (analyst, without_role):
        assert headers["Authorization"].split()[1] not in everything

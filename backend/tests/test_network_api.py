"""The network-monitoring HTTP API: who may call it, what an upload may be, and who sees what.

Each test drives the real application (middleware, authentication, routing, service, storage and
audit trail) in Entra mode against a migrated database (SQLite and PostgreSQL). The interface
catalog, the packet sources and the intelligence service are doubles; the analysis, the recorder,
the capture thread and the enrichment worker are real.
"""

import asyncio
import json
import logging
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.main import create_app
from app.models.audit import AuditLog
from app.models.network import (
    CaptureSession,
    CaptureSource,
    CaptureStatus,
    NetworkAlert,
    NetworkFlow,
)
from app.network import capture as capture_module
from app.network import enrichment as enrichment_module
from app.network import monitor as monitor_module
from app.network import pcap as pcap_module
from app.network import repository as repository_module
from app.network.analyzer import subject_address
from app.network.errors import ERRORS, message_for
from app.network.pcap import MAX_DISPLAY_NAME, MAX_RAW_NAME, UploadSpool
from app.network.service import NetworkService
from app.security.rate_limit import SlidingWindowRateLimiter
from tests.conftest import CLIENT_ID, TENANT_ID, TokenFactory
from tests.network_helpers import (
    ACTIVE_VALUES,
    DOCUMENTATION,
    HOST,
    OTHER_INTERFACE,
    RESOLVER,
    SCAN_FLOWS,
    SCAN_FRAMES,
    SCANNER,
    SERVER,
    T0,
    TEST_INTERFACE,
    AnalysisGate,
    FakeCatalog,
    FakeClock,
    FakeSource,
    StubIntel,
    ago,
    assert_no_module_threads,
    assert_not_logged,
    backdate,
    classic_pcap,
    hold_analyses,
    logged,
    pcap_record_header,
    pcapng_file,
    provider_view,
    reply,
    scan_capture_files,
    scan_traffic,
    seed_alert,
    seed_flow,
    seed_session,
    wait_until,
)

SessionFactory = sessionmaker[Session]

BASE = "/api/v1/network"
STATUS = f"{BASE}/status"
INTERFACES = f"{BASE}/interfaces"
RULES = f"{BASE}/rules"
START = f"{BASE}/capture/start"
STOP = f"{BASE}/capture/stop"
PCAP = f"{BASE}/pcap"
SESSIONS = f"{BASE}/sessions"
SESSION = SESSIONS + "/{session_id}"
FLOWS = SESSION + "/flows"
ALERTS = SESSION + "/alerts"
ENRICH = BASE + "/alerts/{alert_id}/enrich"
ROUTES = [
    ("GET", STATUS),
    ("GET", INTERFACES),
    ("GET", RULES),
    ("POST", START),
    ("POST", STOP),
    ("POST", PCAP),
    ("GET", SESSIONS),
    ("GET", SESSION),
    ("GET", FLOWS),
    ("GET", ALERTS),
    ("DELETE", SESSION),
    ("POST", ENRICH),
]

OCTET = "application/octet-stream"
ANALYST = "SecurityAnalyst"
ADMIN = "Admin"
CLIENT_ADDRESS = "203.0.113.7"
UNKNOWN = "5b7a9c0e-3f1d-4e8a-9b2c-6d4f8a1e0c37"
# A name nothing else in a response, a log line or an audit entry could contain by chance.
CONFIDENTIAL = "quarterly-incident-review"
CONFIDENTIAL_NAME = f"{CONFIDENTIAL}.pcap"


def url(template: str, identifier: Any = UNKNOWN) -> str:
    return template.format(session_id=identifier, alert_id=identifier)


# --- Harness ------------------------------------------------------------------------------------


class SourceDesk:
    """The service's source factory: the prepared sources first, plain ones after those."""

    def __init__(self) -> None:
        self.prepared: deque[FakeSource] = deque()
        self.sources: list[FakeSource] = []
        self.requested: list[str] = []

    def __call__(self, interface_id: str) -> FakeSource:
        self.requested.append(interface_id)
        source = self.prepared.popleft() if self.prepared else FakeSource()
        self.sources.append(source)
        return source


@dataclass
class Api:
    app: FastAPI
    client: TestClient
    tokens: TokenFactory
    intel: StubIntel
    catalog: FakeCatalog
    desk: SourceDesk
    spool_base: Path
    closer: ExitStack
    # Three callers with their own identities: two analysts, and an administrator.
    alice: dict[str, str] = field(default_factory=dict)
    bob: dict[str, str] = field(default_factory=dict)
    root: dict[str, str] = field(default_factory=dict)

    def auth(self, roles: Sequence[str] = (ANALYST,), *, oid: str = "alice") -> dict[str, str]:
        token = self.tokens.make({"roles": list(roles), "oid": oid})
        return {"Authorization": f"Bearer {token}"}

    # --- Requests ----------------------------------------------------------------------

    def request(
        self, method: str, path: str, *, headers: dict[str, str] | None = None, **kwargs: Any
    ) -> Response:
        """Send a request as Alice unless ``headers`` is given (``{}`` is anonymous)."""
        return self.client.request(
            method, path, headers=self.alice if headers is None else headers, **kwargs
        )

    def get(self, path: str, *, headers: dict[str, str] | None = None, **params: Any) -> Response:
        return self.request("GET", path, params=params, headers=headers)

    def post(self, path: str, *, headers: dict[str, str] | None = None, **kwargs: Any) -> Response:
        return self.request("POST", path, headers=headers, **kwargs)

    def delete(self, path: str, *, headers: dict[str, str] | None = None) -> Response:
        return self.request("DELETE", path, headers=headers)

    def start(self, interface: str = TEST_INTERFACE.id, **options: Any) -> Response:
        return self.post(START, json={"interface": interface}, **options)

    def upload(
        self,
        data: bytes | None,
        *,
        name: str | None = "scan.pcap",
        content_type: str | None = OCTET,
        headers: dict[str, str] | None = None,
        extra: Iterable[tuple[str, str]] = (),
    ) -> Response:
        """Upload a file. ``name`` is percent-encoded; ``extra`` adds raw headers (and so can
        repeat ``X-File-Name``), and ``None`` for the name or the type leaves that header out."""
        sent = list((self.alice if headers is None else headers).items())
        if name is not None:
            sent.append(("X-File-Name", quote(name, safe="")))
        if content_type is not None:
            sent.append(("Content-Type", content_type))
        sent.extend(extra)
        return self.client.post(PCAP, content=data, headers=sent)

    # --- What is stored ----------------------------------------------------------------

    @property
    def factory(self) -> SessionFactory:
        return self.app.state.session_factory

    def rows(self, statement: Any) -> list[Any]:
        with self.factory() as db:
            return list(db.scalars(statement))

    def count(self, model: Any) -> int:
        with self.factory() as db:
            return db.scalar(select(func.count()).select_from(model)) or 0

    def audit(self, action: str | None = None) -> list[AuditLog]:
        query = select(AuditLog).order_by(AuditLog.id)
        if action is not None:
            query = query.where(AuditLog.action == action)
        return self.rows(query)

    def sessions(self) -> list[CaptureSession]:
        return self.rows(select(CaptureSession).order_by(CaptureSession.started_at))

    def stored(self, session_id: str) -> CaptureSession | None:
        with self.factory() as db:
            return db.get(CaptureSession, uuid.UUID(session_id))

    def spool_files(self) -> list[Path]:
        return sorted(path for path in self.spool_base.rglob("*") if path.is_file())

    def seed_session(self, **options: Any) -> uuid.UUID:
        """A stored session of Alice's, started a few minutes ago (retention is judged by now)."""
        options.setdefault("started", ago(minutes=5))
        return seed_session(self.factory, **options)

    # --- Waiting -----------------------------------------------------------------------

    def finished(
        self, session_id: str, *, headers: dict[str, str] | None = None, timeout: float = 10.0
    ) -> dict[str, Any]:
        """Poll the session until it is no longer starting, running or stopping."""

        def ended() -> dict[str, Any] | None:
            body = self.get(url(SESSION, session_id), headers=headers).json()
            return body if body["status"] not in ACTIVE_VALUES else None

        return wait_until(ended, timeout=timeout, interval=0.02, what="the session to end")

    def settle(self) -> None:
        """Wait for the analysis slot to be free. It is released just after the session ends."""
        wait_until(
            lambda: not self.get(STATUS).json()["analysis"]["running"],
            interval=0.02,
            what="the analysis slot to be freed",
        )

    def wait_for_lookups(self, session_id: str, addresses: Iterable[str]) -> dict[str, Any]:
        """Wait until every address has an answer recorded; return the session's enrichment."""
        wanted = set(addresses)

        def answered() -> dict[str, Any] | None:
            row = self.stored(session_id)
            entries = ((row.stats if row else None) or {}).get("enrichment") or {}
            done = wanted <= set(entries) and all(
                entries[address].get("status") != "pending" for address in wanted
            )
            return entries if done else None

        return wait_until(answered, interval=0.02, what="the lookups to be recorded")

    def close(self) -> None:
        """Shut the application down, as the server does when it stops."""
        self.closer.close()


ApiFactory = Callable[..., Api]


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


@pytest.fixture
def build_api(
    make_settings: Callable[..., Settings],
    entra_validator: Any,
    tokens: TokenFactory,
    db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[ApiFactory]:
    monkeypatch.setattr(capture_module, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(enrichment_module, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(monitor_module, "_FINAL_FLUSH_DELAY", 0.0)
    spools: list[Path] = []
    with ExitStack() as stack:

        def factory(
            *, intel: StubIntel | None = None, catalog: FakeCatalog | None = None, **settings: Any
        ) -> Api:
            intel = intel or StubIntel()
            catalog = catalog or FakeCatalog()
            desk = SourceDesk()
            spool_base = tmp_path / f"spool-{len(spools)}"
            spool_base.mkdir()
            spools.append(spool_base)

            def build_service(
                config: Settings, session_factory: SessionFactory, intel_service: Any
            ) -> NetworkService:
                return NetworkService(
                    config,
                    session_factory,
                    intel_service=intel_service,
                    catalog=catalog,
                    source_factory=desk,
                    spool=UploadSpool(spool_base),
                    pacing_interval=0.0,
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
                intel_service=intel,
                network_service_factory=build_service,
            )
            closer = ExitStack()
            stack.callback(closer.close)
            client = closer.enter_context(TestClient(app, client=(CLIENT_ADDRESS, 50000)))
            api = Api(app, client, tokens, intel, catalog, desk, spool_base, closer)
            api.alice = api.auth(oid="alice")
            api.bob = api.auth(oid="bob")
            api.root = api.auth((ADMIN,), oid="root")
            return api

        yield factory
    # Every application is shut down by now: nothing may be left in any of the spools.
    assert [list(base.iterdir()) for base in spools] == [[] for _ in spools]


@pytest.fixture
def api(build_api: ApiFactory) -> Api:
    return build_api()


@pytest.fixture
def prior_run(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    """A session factory over the database, for what an earlier run of the server left in it."""
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


@pytest.fixture(scope="module")
def scan_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    return scan_capture_files(tmp_path_factory.mktemp("scan"))


@pytest.fixture
def hold_analysis(monkeypatch: pytest.MonkeyPatch) -> Iterator[AnalysisGate]:
    gate = hold_analyses(monkeypatch)
    yield gate
    gate.release.set()


def call(api: Api, method: str, path: str, *, headers: dict[str, str]) -> Response:
    """A well-formed request to a route, so that only the caller's rights decide the answer."""
    target = url(path)
    if path == START:
        return api.client.post(target, json={"interface": TEST_INTERFACE.id}, headers=headers)
    if path == PCAP:
        sent = {**headers, "Content-Type": OCTET, "X-File-Name": "a.pcap"}
        return api.client.post(target, content=b"not looked at", headers=sent)
    return api.client.request(method, target, headers=headers)


def untouched(api: Api) -> bool:
    """A refused request changed nothing and started nothing."""
    return (
        api.audit() == []
        and api.sessions() == []
        and api.spool_files() == []
        and api.desk.requested == []
        and api.catalog.refreshes == 0
        and api.intel.calls == []
    )


def error_of(response: Response) -> dict[str, Any]:
    return response.json()["error"]


def refusal_of(response: Response) -> tuple[int, str, str]:
    """What a refusal says to the caller, without the correlation id that differs per request."""
    error = error_of(response)
    return response.status_code, error["code"], error["message"]


# --- Who may call it ----------------------------------------------------------------------------


def test_every_operation_is_documented_and_needs_the_bearer_scheme(api: Api) -> None:
    paths = api.app.openapi()["paths"]
    operations = {
        (method.upper(), path): operation
        for path, item in paths.items()
        if path.startswith(BASE)
        for method, operation in item.items()
    }

    assert set(operations) == set(ROUTES)  # a new route must be added to ROUTES, and so tested
    for operation in operations.values():
        assert {"EntraBearer": []} in operation["security"]


def test_anonymous_callers_are_rejected_on_every_route(api: Api) -> None:
    for method, path in ROUTES:
        response = call(api, method, path, headers={})

        assert response.status_code == 401, (method, path)
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert error_of(response)["code"] == "unauthorized"
    assert untouched(api)


@pytest.mark.parametrize("roles", [["User"], [], ["Hacker"]], ids=["user", "no-roles", "unknown"])
def test_callers_without_an_analyst_role_are_forbidden_on_every_route(
    api: Api, roles: list[str]
) -> None:
    for method, path in ROUTES:
        response = call(api, method, path, headers=api.auth(roles))

        assert response.status_code == 403, (method, path)
        assert error_of(response)["message"] == "Insufficient permissions."
    assert untouched(api)


def test_forged_or_expired_tokens_get_nothing(api: Api, tokens: TokenFactory) -> None:
    forged = {
        "expired": tokens.make({"exp": 1_000_000_000}),
        "wrong-audience": tokens.make({"aud": "someone-else"}),
        "alg-none": tokens.forge_alg_none(),
        "hs256-confusion": tokens.forge_hs256_with_public_key(),
    }

    for flaw, token in forged.items():
        for method, path in [("GET", SESSIONS), ("POST", PCAP), ("POST", START)]:
            response = call(api, method, path, headers={"Authorization": f"Bearer {token}"})

            assert response.status_code == 401, (flaw, path)
    assert untouched(api)


@pytest.mark.parametrize("role", [ANALYST, ADMIN])
def test_analysts_and_admins_can_use_the_api(api: Api, role: str) -> None:
    headers = api.auth([role], oid="someone")

    assert api.get(STATUS, headers=headers).status_code == 200
    assert api.get(SESSIONS, headers=headers).status_code == 200


def test_the_development_mode_serves_the_local_analyst_without_a_token(
    build_api: ApiFactory,
) -> None:
    api = build_api(auth_mode="dev")

    started = api.start(headers={})

    assert started.status_code == 200
    (entry,) = api.audit("NETWORK_CAPTURE_START")
    assert entry.actor == "dev-user"
    assert api.get(SESSIONS, headers={}).json()["total"] == 1


def test_the_development_mode_still_refuses_a_user_without_the_analyst_role(
    build_api: ApiFactory,
) -> None:
    api = build_api(auth_mode="dev", dev_auth_roles="User")

    assert api.get(STATUS, headers={}).status_code == 403
    assert api.start(headers={}).status_code == 403
    assert untouched(api)


# --- Status, interfaces and rules ---------------------------------------------------------------


def test_the_status_of_a_server_that_can_capture(api: Api) -> None:
    response = api.get(STATUS)

    assert response.status_code == 200
    assert response.json() == {
        "state": "ready",
        "backend": {"name": "fakepcap", "available": True},
        "interface": None,
        "session_id": None,
        "error_code": None,
        "message": None,
        "busy": False,
        "analysis": {"running": False, "session_id": None, "max_upload_mb": 50},
        "enrichment_enabled": True,
    }


def test_the_status_reports_the_configured_limits(build_api: ApiFactory) -> None:
    api = build_api(network_max_pcap_size_mb=7, external_enrichment_enabled=False)

    body = api.get(STATUS).json()

    assert body["analysis"]["max_upload_mb"] == 7
    assert body["enrichment_enabled"] is False


def test_without_a_capture_driver_the_api_says_so_and_still_analyses_files(
    build_api: ApiFactory, scan_files: dict[str, bytes]
) -> None:
    api = build_api(catalog=FakeCatalog(available=False))

    status = api.get(STATUS).json()
    listing = api.get(INTERFACES, refresh=True)
    refused = api.start()
    uploaded = api.upload(scan_files["pcap"])

    assert (status["state"], status["error_code"]) == ("not_configured", "capture_backend_missing")
    assert status["message"] == message_for("capture_backend_missing")
    assert listing.json() == {"backend": {"name": "none", "available": False}, "interfaces": []}
    assert refused.status_code == 503
    assert error_of(refused)["code"] == "capture_backend_missing"
    assert error_of(refused)["message"] == ERRORS["capture_backend_missing"].message
    assert api.desk.requested == []
    assert uploaded.status_code == 202
    assert api.finished(uploaded.json()["id"])["status"] == "completed"
    api.settle()


def test_interfaces_are_listed_and_a_refresh_must_be_asked_for(api: Api) -> None:
    listing = api.get(INTERFACES).json()

    assert listing["backend"] == {"name": "fakepcap", "available": True}
    assert listing["interfaces"] == [
        {
            "id": TEST_INTERFACE.id,
            "name": TEST_INTERFACE.name,
            "description": TEST_INTERFACE.description,
            "addresses": list(TEST_INTERFACE.addresses),
        },
        {
            "id": OTHER_INTERFACE.id,
            "name": OTHER_INTERFACE.name,
            "description": OTHER_INTERFACE.description,
            "addresses": [],
        },
    ]
    assert api.catalog.refreshes == 0

    assert api.get(INTERFACES, refresh=True).status_code == 200
    assert api.catalog.refreshes == 1
    assert api.get(INTERFACES, refresh="maybe").status_code == 422
    assert api.catalog.refreshes == 1


def test_the_rules_carry_the_thresholds_this_server_is_configured_with(
    build_api: ApiFactory,
) -> None:
    api = build_api(port_scan_threshold=5, external_enrichment_enabled=False)

    rules = {rule["rule_id"]: rule for rule in api.get(RULES).json()}

    assert sorted(rules) == [f"NET-00{number}" for number in range(1, 8)]
    scan = rules["NET-001"]
    assert (scan["name"], scan["threshold"], scan["window_seconds"]) == ("port_scan", 5.0, 60)
    assert (scan["unit"], scan["severities"]) == ("ports", ["medium", "high", "critical"])
    assert rules["NET-005"]["active"] is False  # a lookup is what raises it
    assert all(rule["active"] for rule_id, rule in rules.items() if rule_id != "NET-005")
    assert (
        rules["NET-006"]["detail"]
        == "Ports: 23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337"
    )


# --- Live capture -------------------------------------------------------------------------------


def target_of(session_id: str | uuid.UUID) -> str:
    return f"network-session:{session_id}"


def test_a_live_capture_runs_from_start_to_stop_and_is_audited(api: Api) -> None:
    started = api.start()

    assert started.status_code == 200
    body = started.json()
    assert (body["state"], body["interface"], body["busy"]) == (
        "running",
        TEST_INTERFACE.name,
        False,
    )
    session_id = body["session_id"]
    assert api.desk.requested == [TEST_INTERFACE.id]
    assert api.get(STATUS).json() == body
    # Someone else sees only that the slot is taken: not whose capture it is, nor where.
    other = api.get(STATUS, headers=api.bob).json()
    assert (other["state"], other["busy"]) == ("ready", True)
    assert (other["session_id"], other["interface"]) == (None, None)

    api.desk.sources[0].emit(*scan_traffic())
    stopped = api.post(STOP)

    assert stopped.status_code == 200
    assert (stopped.json()["state"], stopped.json()["session_id"]) == ("stopped", session_id)
    detail = api.get(url(SESSION, session_id)).json()
    assert (detail["source_kind"], detail["status"]) == ("live", "stopped")
    assert (detail["interface"], detail["source_label"]) == (TEST_INTERFACE.name, None)
    assert (detail["packets_total"], detail["flows_total"]) == (SCAN_FLOWS, SCAN_FLOWS)
    assert (detail["alerts_total"], detail["non_ip_packets"]) == (1, 1)
    assert detail["ended_at"] is not None
    (alert,) = api.get(url(ALERTS, session_id)).json()["items"]
    assert (alert["rule_id"], alert["src_ip"], alert["severity"]) == ("NET-001", SCANNER, "medium")
    (start,) = api.audit("NETWORK_CAPTURE_START")
    assert (start.actor, start.result, start.target) == ("alice", "success", target_of(session_id))
    assert start.source_ip == CLIENT_ADDRESS
    assert start.details == {"interface": TEST_INTERFACE.name}
    (stop,) = api.audit("NETWORK_CAPTURE_STOP")
    assert (stop.actor, stop.result, stop.target) == ("alice", "success", target_of(session_id))
    assert stop.details == {"finished": True}
    assert api.desk.sources[0].stop_calls >= 1


def test_only_one_capture_runs_at_a_time_and_only_its_owner_can_stop_it(api: Api) -> None:
    session_id = api.start().json()["session_id"]

    again = api.start()
    taken = api.start(headers=api.bob)
    stranger = api.post(STOP, headers=api.bob)

    assert [again.status_code, taken.status_code] == [409, 409]
    assert {error_of(again)["code"], error_of(taken)["code"]} == {"capture_already_running"}
    assert (stranger.status_code, error_of(stranger)["code"]) == (409, "capture_not_running")
    assert api.desk.requested == [TEST_INTERFACE.id]  # nobody got a second source
    assert api.get(STATUS).json()["session_id"] == session_id
    assert api.get(STATUS).json()["state"] == "running"
    refused = [entry for entry in api.audit("NETWORK_CAPTURE_START") if entry.result != "success"]
    assert [(entry.actor, entry.result, entry.target) for entry in refused] == [
        ("alice", "rejected", None),
        ("bob", "rejected", None),
    ]
    assert {json.dumps(entry.details) for entry in refused} == {
        json.dumps({"reason": "capture_already_running"})
    }
    assert api.audit("NETWORK_CAPTURE_STOP") == []

    assert api.post(STOP).json()["state"] == "stopped"
    assert api.start(headers=api.bob).status_code == 200  # the slot is free for the next analyst


def test_stopping_without_a_capture_is_refused(api: Api) -> None:
    response = api.post(STOP)

    assert (response.status_code, error_of(response)["code"]) == (409, "capture_not_running")
    assert api.audit() == []


def test_an_unknown_interface_is_not_found_and_not_echoed(api: Api) -> None:
    hostile = '"><script>alert(1)</script>'

    response = api.start(hostile)

    assert response.status_code == 404
    assert error_of(response)["code"] == "interface_not_found"
    assert hostile not in response.text
    assert api.desk.requested == []
    assert api.sessions() == []
    (entry,) = api.audit("NETWORK_CAPTURE_START")
    assert (entry.result, entry.details) == ("rejected", {"reason": "interface_not_found"})
    assert hostile not in json.dumps(entry.details)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({}, id="missing"),
        pytest.param({"interface": ""}, id="empty"),
        pytest.param({"interface": "x" * 513}, id="too-long"),
        pytest.param({"interface": 5}, id="not-text"),
        pytest.param({"interface": None}, id="null"),
        pytest.param({"interface": TEST_INTERFACE.id, "promiscuous": True}, id="extra-field"),
        pytest.param([TEST_INTERFACE.id], id="not-an-object"),
    ],
)
def test_a_malformed_start_request_starts_nothing(api: Api, body: Any) -> None:
    response = api.post(START, json=body)

    assert response.status_code == 422
    assert error_of(response)["code"] == "validation_error"
    assert api.desk.requested == []
    assert api.sessions() == []
    assert api.audit() == []


def test_a_start_request_that_is_not_json_starts_nothing(api: Api) -> None:
    for content, kind in [(b"interface=test-eth0", "text/plain"), (b"{broken", "application/json")]:
        response = api.post(START, content=content, headers={**api.alice, "Content-Type": kind})

        assert response.status_code == 422
    assert api.desk.requested == [] and api.sessions() == []


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (PermissionError("Operation not permitted"), "capture_permission_denied"),
        (OSError("No such device exists"), "interface_unavailable"),
        (RuntimeError("Npcap is not installed"), "capture_backend_missing"),
        (RuntimeError("driver exploded at 0xdeadbeef"), "capture_failed"),
    ],
    ids=["permission", "interface", "driver", "other"],
)
def test_a_capture_that_cannot_start_is_a_503_with_a_fixed_message(
    api: Api, failure: Exception, code: str
) -> None:
    api.desk.prepared.append(FakeSource(start_error=failure))

    response = api.start()

    assert response.status_code == 503
    assert refusal_of(response)[1:] == (code, ERRORS[code].message)
    assert str(failure) not in response.text
    (row,) = api.sessions()
    assert (row.status, row.error_code) == (
        ("permission_denied" if "permission" in code else "failed"),
        code,
    )
    assert row.ended_at is not None
    (entry,) = api.audit("NETWORK_CAPTURE_START")
    assert (entry.result, entry.target) == ("rejected", target_of(row.id))
    assert entry.details == {"reason": code}


def test_a_refused_capture_stays_visible_in_the_status_until_the_next_one_starts(api: Api) -> None:
    api.desk.prepared.append(FakeSource(start_error=PermissionError("Operation not permitted")))
    assert api.start().status_code == 503

    for _ in range(2):
        status = api.get(STATUS).json()

        assert (status["state"], status["error_code"]) == (
            "permission_denied",
            "capture_permission_denied",
        )
        assert status["message"] == ERRORS["capture_permission_denied"].message
        assert (status["busy"], status["interface"]) == (False, TEST_INTERFACE.name)
    (listed,) = api.get(SESSIONS).json()["items"]
    assert listed["status"] == "permission_denied"
    assert listed["message"] == ERRORS["capture_permission_denied"].message
    assert api.get(STATUS, headers=api.bob).json()["state"] == "ready"  # only the caller's own

    assert api.start().json()["state"] == "running"
    assert api.get(STATUS).json()["error_code"] is None


def test_a_capture_whose_source_dies_ends_as_failed_and_frees_the_slot(api: Api) -> None:
    session_id = api.start().json()["session_id"]
    source = api.desk.sources[0]
    source.emit(*scan_traffic()[:5])

    source.die(RuntimeError("secret driver detail"))

    wait_until(lambda: api.get(STATUS).json()["state"] == "failed", what="the failure to show")
    status = api.get(STATUS)
    assert status.json()["error_code"] == "capture_failed"
    assert status.json()["message"] == ERRORS["capture_failed"].message
    assert "secret driver detail" not in status.text
    detail = api.finished(session_id)
    assert (detail["status"], detail["error_code"]) == ("failed", "capture_failed")
    assert detail["packets_total"] == 5  # what arrived before the source died is kept
    assert api.post(STOP).status_code == 409
    assert api.start().status_code == 200


def test_a_running_capture_cannot_be_deleted_until_it_is_stopped(api: Api) -> None:
    session_id = api.start().json()["session_id"]

    running = api.delete(url(SESSION, session_id))

    assert (running.status_code, error_of(running)["code"]) == (409, "session_running")
    assert api.stored(session_id) is not None
    api.post(STOP)
    deleted = api.delete(url(SESSION, session_id))
    assert (deleted.status_code, deleted.content) == (204, b"")
    assert api.stored(session_id) is None


def test_stopping_the_server_ends_a_running_capture_with_its_results(
    build_api: ApiFactory, prior_run: SessionFactory
) -> None:
    api = build_api()
    session_id = api.start().json()["session_id"]
    api.desk.sources[0].emit(*scan_traffic())

    api.close()

    with prior_run() as db:
        row = db.get(CaptureSession, uuid.UUID(session_id))
    assert row is not None
    assert (row.status, row.error_code) == ("stopped", None)
    assert (row.packets_total, row.flows_total) == (SCAN_FLOWS, SCAN_FLOWS)
    assert row.ended_at is not None
    assert api.desk.sources[0].stop_calls >= 1


# --- Analysing an uploaded capture --------------------------------------------------------------


def epoch(value: str) -> float:
    moment = datetime.fromisoformat(value)
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).timestamp()


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_an_uploaded_capture_is_analysed_in_the_background_and_served_afterwards(
    api: Api, scan_files: dict[str, bytes], kind: str
) -> None:
    response = api.upload(scan_files[kind], name=CONFIDENTIAL_NAME)

    # The answer comes before the analysis is done: the new session, still empty.
    assert response.status_code == 202
    accepted = response.json()
    assert (accepted["source_kind"], accepted["status"]) == ("pcap", "running")
    assert (accepted["source_label"], accepted["interface"]) == (CONFIDENTIAL_NAME, None)
    assert [accepted[key] for key in ("packets_total", "flows_total", "alerts_total")] == [0, 0, 0]
    session_id = accepted["id"]

    detail = api.finished(session_id)

    assert (detail["status"], detail["error_code"], detail["message"]) == ("completed", None, None)
    assert (detail["packets_total"], detail["flows_total"]) == (SCAN_FLOWS, SCAN_FLOWS)
    assert (detail["alerts_total"], detail["alerts_by_rule"]) == (1, {"NET-001": 1})
    assert (detail["non_ip_packets"], detail["malformed_packets"], detail["packets_dropped"]) == (
        1,
        0,
        0,
    )
    assert (detail["active_flows"], detail["flows_stored"], detail["flows_not_stored"]) == (
        0,
        SCAN_FLOWS,
        0,
    )
    assert detail["ended_at"] is not None
    # The times are the capture's own, not the moment the file was analysed.
    assert epoch(detail["first_packet_at"]) == pytest.approx(T0, abs=0.01)
    assert epoch(detail["last_packet_at"]) == pytest.approx(T0 + 6, abs=0.01)
    assert {item["protocol"] for item in detail["protocols"]} == {"tcp", "udp"}
    assert (detail["top_sources"][0]["address"], detail["top_sources"][0]["packets"]) == (
        SCANNER,
        30,
    )
    assert (detail["top_destinations"][0]["address"], detail["top_destinations"][0]["packets"]) == (
        SERVER,
        31,
    )
    listed = api.get(SESSIONS).json()
    assert [item["id"] for item in listed["items"]] == [session_id]
    assert listed["items"][0]["status"] == "completed"


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_the_flows_and_alerts_of_an_analysed_capture_are_served_newest_first(
    api: Api, scan_files: dict[str, bytes], kind: str
) -> None:
    session_id = api.upload(scan_files[kind]).json()["id"]
    api.finished(session_id)

    flows = api.get(url(FLOWS, session_id), limit=200).json()

    assert (flows["total"], len(flows["items"])) == (SCAN_FLOWS, SCAN_FLOWS)
    started = [epoch(item["first_seen"]) for item in flows["items"]]
    assert started == sorted(started, reverse=True)
    newest = flows["items"][0]
    assert (newest["src_ip"], newest["dst_ip"], newest["dst_port"]) == (HOST, SERVER, 80)
    assert (newest["protocol"], newest["tcp_flag_names"]) == ("tcp", ["SYN"])
    assert (newest["packets_out"], newest["packets_in"]) == (1, 0)
    assert newest["bytes_out"] > 0 and newest["close_reason"]
    by_port = {item["dst_port"]: item for item in flows["items"] if item["src_ip"] == SCANNER}
    assert sorted(by_port) == list(range(2000, 2030))
    assert {item["dst_ip"] for item in by_port.values()} == {SERVER}
    udp = [item for item in flows["items"] if item["protocol"] == "udp"]
    assert [(item["src_ip"], item["dst_ip"], item["dst_port"]) for item in udp] == [
        (HOST, RESOLVER, 53)
    ]
    assert (udp[0]["tcp_flags"], udp[0]["tcp_flag_names"]) == (None, [])

    alerts = api.get(url(ALERTS, session_id)).json()

    assert (alerts["total"], alerts["limit"], alerts["offset"]) == (1, 50, 0)
    (alert,) = alerts["items"]
    assert (alert["rule_id"], alert["rule_name"], alert["severity"]) == (
        "NET-001",
        "port_scan",
        "medium",
    )
    assert (alert["src_ip"], alert["dst_ip"], alert["session_id"]) == (SCANNER, SERVER, session_id)
    assert (alert["observed_value"], alert["threshold"], alert["unit"]) == (20.0, 20.0, "ports")
    assert alert["window_seconds"] == 60
    assert SCANNER in alert["explanation"]
    assert epoch(alert["first_observed"]) <= epoch(alert["last_observed"])
    assert epoch(alert["first_observed"]) == pytest.approx(T0, abs=0.01)
    assert alert["evidence"]
    api.settle()


def test_only_public_addresses_are_looked_up_and_by_the_monitor_not_the_caller(
    api: Api, scan_files: dict[str, bytes]
) -> None:
    session_id = api.upload(scan_files["pcap"]).json()["id"]
    api.finished(session_id)

    answers = api.wait_for_lookups(session_id, {SCANNER, RESOLVER})

    assert set(answers) == {SCANNER, RESOLVER}
    assert sorted(api.intel.calls) == sorted([SCANNER, RESOLVER])  # once each
    for private in (HOST, SERVER, DOCUMENTATION):
        assert private not in api.intel.calls
    assert {context.actor for context in api.intel.contexts} == {"system:network-monitor"}
    assert api.intel.refresh_flags == [False, False]  # a fresh answer is reused, not asked again
    detail = api.get(url(SESSION, session_id)).json()
    addresses = {item["address"]: item for item in detail["external_ips"]}
    assert set(addresses) == {SCANNER, RESOLVER}
    assert (addresses[SCANNER]["alerted"], addresses[SCANNER]["sent_to"]) == (True, False)
    assert (addresses[RESOLVER]["alerted"], addresses[RESOLVER]["sent_to"]) == (False, True)
    assert addresses[SCANNER]["peers"] == [SERVER]
    assert {item["enrichment"]["status"] for item in addresses.values()} == {"completed"}
    assert detail["enrichment"] == {
        "enabled": True,
        "total": 2,
        "completed": 2,
        "pending": 0,
        "failed": 0,
        "unavailable": 0,
        "skipped": 0,
    }
    (alert,) = api.get(url(ALERTS, session_id)).json()["items"]
    assert alert["enrichment"]["status"] == "completed"  # the alert carries its address's answer
    assert alert["enrichment"]["address"] == SCANNER
    api.settle()


def test_a_known_malicious_address_is_flagged_once_its_lookup_comes_back(
    build_api: ApiFactory, scan_files: dict[str, bytes]
) -> None:
    verdict = reply(provider_view(), score=90, classification="critical")
    api = build_api(intel=StubIntel({SCANNER: verdict}))
    session_id = api.upload(scan_files["pcap"]).json()["id"]
    api.finished(session_id)

    answers = api.wait_for_lookups(session_id, {SCANNER, RESOLVER})

    assert answers[SCANNER]["risk_score"] == 90
    detail = api.get(url(SESSION, session_id)).json()
    listing = api.get(url(ALERTS, session_id)).json()
    assert detail["alerts_total"] == listing["total"] == 2
    assert detail["alerts_by_rule"] == {"NET-001": 1, "NET-005": 1}  # the lookup's alert is counted
    alerts = {item["rule_id"]: item for item in listing["items"]}
    assert set(alerts) == {"NET-001", "NET-005"}  # the harmless resolver raised nothing
    flagged = alerts["NET-005"]
    assert (flagged["src_ip"], flagged["dst_ip"], flagged["severity"]) == (
        SCANNER,
        SERVER,
        "critical",
    )
    assert (flagged["observed_value"], flagged["threshold"]) == (90.0, 61.0)
    assert flagged["evidence"]["address"] == SCANNER
    assert flagged["enrichment"]["status"] == "completed"
    assert flagged["enrichment"]["risk_score"] == 90
    assert alerts["NET-001"]["enrichment"]["risk_score"] == 90
    assert api.intel.calls.count(SCANNER) == 1
    api.settle()


def test_a_low_score_or_a_disabled_lookup_raises_no_known_malicious_alert(
    build_api: ApiFactory, scan_files: dict[str, bytes]
) -> None:
    just_below = reply(provider_view(), score=60, classification="medium")
    quiet = build_api(intel=StubIntel({SCANNER: just_below}))
    off = build_api(external_enrichment_enabled=False)

    session_id = quiet.upload(scan_files["pcap"]).json()["id"]
    quiet.finished(session_id)
    quiet.wait_for_lookups(session_id, {SCANNER, RESOLVER})
    quiet.settle()
    other_id = off.upload(scan_files["pcap"]).json()["id"]
    detail = off.finished(other_id)
    off.settle()

    assert quiet.get(url(ALERTS, session_id)).json()["total"] == 1
    assert quiet.get(url(SESSION, session_id)).json()["alerts_by_rule"] == {"NET-001": 1}
    assert off.intel.calls == []
    assert (detail["alerts_total"], detail["enrichment"]["enabled"]) == (1, False)
    assert {item["enrichment"]["status"] for item in detail["external_ips"]} == {"disabled"}
    (alert,) = off.get(url(ALERTS, other_id)).json()["items"]
    assert alert["enrichment"]["status"] == "disabled"


def test_an_analysis_is_audited_and_neither_the_name_nor_the_file_is_recorded(
    api: Api, scan_files: dict[str, bytes], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    data = scan_files["pcapng"]

    response = api.upload(data, name=CONFIDENTIAL_NAME)
    session_id = response.json()["id"]
    api.finished(session_id)
    api.wait_for_lookups(session_id, {SCANNER, RESOLVER})
    api.settle()

    (entry,) = api.audit()
    assert entry.action == "NETWORK_PCAP_ANALYZE"
    assert (entry.actor, entry.result, entry.target) == ("alice", "success", target_of(session_id))
    assert entry.source_ip == CLIENT_ADDRESS
    assert entry.details == {
        "size_bytes": len(data),
        "format": "pcapng",
        "packets": SCAN_FRAMES,
        "truncated": False,
    }
    assert CONFIDENTIAL not in repr(vars(entry))
    assert CONFIDENTIAL not in str(response.headers)
    assert_not_logged(caplog, CONFIDENTIAL)
    assert api.spool_files() == []  # the upload is gone as soon as it has been read


# --- File names ---------------------------------------------------------------------------------

# A valid file without packets: the quickest one to analyse.
EMPTY_CAPTURE = classic_pcap()
LONG_STEM = "a" * 200
NAMES_AS_SHOWN = {
    "scan.pcap": "scan.pcap",
    "Scan.PCAPNG": "Scan.PCAPNG",
    "old.cap": "old.cap",
    "  padded.pcap  ": "padded.pcap",
    "../../etc/passwd.pcap": "passwd.pcap",
    "..\\..\\windows\\system32\\evil.pcap": "evil.pcap",
    "/etc/cron.d/job.pcap": "job.pcap",
    "C:\\Users\\admin\\capture.pcap": "capture.pcap",
    "a\x00b\r\nc\x1b[31m.pcap": "abc[31m.pcap",
    "invoice\u202efdp.pcap": "invoicefdp.pcap",
    "Cafe\u0301.pcap": "Caf\u00e9.pcap",
    "отчёт-сети.pcap": "отчёт-сети.pcap",
    "日本語 キャプチャ.pcapng": "日本語 キャプチャ.pcapng",
    "<img src=x onerror=alert(1)>.pcap": "<img src=x onerror=alert(1)>.pcap",
    "%2e%2e%2fsecret.pcap": "%2e%2e%2fsecret.pcap",
    LONG_STEM + ".pcap": "a" * (MAX_DISPLAY_NAME - len(".pcap")) + ".pcap",
    "b" * (MAX_RAW_NAME - len(".pcapng")) + ".pcapng": "b" * (MAX_DISPLAY_NAME - 7) + ".pcapng",
}


def test_a_name_is_only_a_label_and_is_cleaned_before_it_is_kept(api: Api, tmp_path: Path) -> None:
    for sent, shown in NAMES_AS_SHOWN.items():
        response = api.upload(EMPTY_CAPTURE, name=sent)

        assert response.status_code == 202, sent
        assert response.json()["source_label"] == shown, sent
        assert api.finished(response.json()["id"])["source_label"] == shown, sent
        api.settle()

    assert sorted(row.source_label for row in api.sessions()) == sorted(NAMES_AS_SHOWN.values())
    items = api.get(SESSIONS, limit=100).json()["items"]
    assert sorted(item["source_label"] for item in items) == sorted(NAMES_AS_SHOWN.values())
    # Nothing was ever made from a name: no file by that name, nowhere a path could point to.
    assert not [path for path in tmp_path.rglob("*") if path.name in {"passwd.pcap", "evil.pcap"}]
    assert api.spool_files() == []


def test_a_name_that_is_encoded_in_the_header_is_decoded_exactly_once(api: Api) -> None:
    sent = [
        ("%C3%A9t%C3%A9.pcap", "été.pcap"),
        ("..%2f..%2fsecret.pcap", "secret.pcap"),  # an encoded slash still ends a path
        ("%252e%252e.pcap", "%2e%2e.pcap"),  # not decoded a second time
    ]
    for header, shown in sent:
        response = api.upload(EMPTY_CAPTURE, name=None, extra=[("X-File-Name", header)])

        assert (response.status_code, response.json()["source_label"]) == (202, shown), header
        api.finished(response.json()["id"])
        api.settle()


def test_a_markup_name_comes_back_as_data_that_a_browser_will_not_run(api: Api) -> None:
    name = "<img src=x onerror=alert(document.cookie)>.pcap"

    response = api.upload(EMPTY_CAPTURE, name=name)

    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.json()["source_label"] == name
    api.finished(response.json()["id"])
    api.settle()


BAD_NAMES = {
    "a text file": "notes.txt",
    "an executable": "scan.pcap.exe",
    "no extension": "scan",
    "only an extension": ".pcap",
    "only control characters": "\x00\x01\x02.pcap",
    "blank": "   ",
    "parent directory": "..",
    "a path to a directory": "../../etc/",
    "one character too long": "c" * (MAX_RAW_NAME - len(".pcap") + 1) + ".pcap",
    "far too long": "d" * 100_000 + ".pcap",
}


def test_a_file_without_a_usable_name_is_refused_before_its_body_is_read(api: Api) -> None:
    for kind, name in BAD_NAMES.items():
        response = api.upload(EMPTY_CAPTURE, name=name)

        assert (response.status_code, error_of(response)["code"]) == (422, "invalid_filename"), kind
    for headers in [
        [],  # no name at all
        [("X-File-Name", "")],
        [("X-File-Name", "%FF%FE.pcap")],  # not UTF-8
        [("X-File-Name", "%E3%81.pcap")],  # cut off in the middle of a character
        [("X-File-Name", "a.pcap"), ("X-File-Name", "b.pcap")],  # which one is meant?
    ]:
        response = api.upload(EMPTY_CAPTURE, name=None, extra=headers)

        assert (response.status_code, error_of(response)["code"]) == (422, "invalid_filename")
    assert (
        api.upload(EMPTY_CAPTURE, name="a.pcap", extra=[("X-File-Name", "b.pcap")]).status_code
        == 422
    )
    assert untouched(api)  # no session, no audit entry, no spool file: the body was never read
    assert api.get(STATUS).json()["analysis"]["running"] is False
    assert api.upload(EMPTY_CAPTURE).status_code == 202  # and the next valid upload goes through
    api.settle()


# --- Uploads that must be refused ---------------------------------------------------------------

MEGABYTE = 1024 * 1024


@dataclass
class Driven:
    status: int
    body: Any
    consumed: int  # how many times the application asked for more of the request


def drive(
    api: Api,
    chunks: Iterable[bytes],
    *,
    name: str = "scan.pcap",
    hang_up: bool = False,
    headers: Iterable[tuple[str, str]] = (),
) -> Driven:
    """POST a body straight to the application as Alice, one chunk for each read it makes.

    The test client hands a body over in one piece. This is how a slow or hostile client looks to
    the server: it shows when the server stops reading, and lets the client hang up half way.
    """
    sent = [
        ("host", "testserver"),
        ("authorization", api.alice["Authorization"]),
        ("content-type", OCTET),
        ("x-file-name", quote(name, safe="")),
        *headers,
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": PCAP,
        "raw_path": PCAP.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(key.encode("latin-1"), value.encode("latin-1")) for key, value in sent],
        "client": (CLIENT_ADDRESS, 50000),
        "server": ("testserver", 80),
    }
    messages: deque[dict[str, Any]] = deque(
        {"type": "http.request", "body": chunk, "more_body": True} for chunk in chunks
    )
    messages.append(
        {"type": "http.disconnect"}
        if hang_up
        else {"type": "http.request", "body": b"", "more_body": False}
    )
    reads = 0
    answer: dict[str, Any] = {"body": b""}

    async def receive() -> dict[str, Any]:
        nonlocal reads
        reads += 1
        return messages.popleft() if messages else {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            answer["status"] = message["status"]
        elif message["type"] == "http.response.body":
            answer["body"] += message.get("body", b"")

    asyncio.run(api.app(scope, receive, send))
    return Driven(answer["status"], json.loads(answer["body"]) if answer["body"] else None, reads)


def chunks_of(data: bytes, size: int) -> list[bytes]:
    return [data[start : start + size] for start in range(0, len(data), size)]


def assert_nothing_left(api: Api) -> None:
    """A refused upload leaves no session and no file in the spool, and the analysis slot free."""
    assert api.sessions() == []
    assert api.spool_files() == []
    assert api.get(STATUS).json()["analysis"]["running"] is False


NOT_CAPTURES = {
    "text": b"GET /etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n",
    "too short for a header": b"\xd4\xc3\xb2\xa1\x02\x00",
    "zeros": bytes(4096),
    "an archive": b"PK\x03\x04" + bytes(200),
    "a record claiming two gigabytes": classic_pcap() + pcap_record_header(0x7FFFFFFF),
    "a pcapng file cut inside its header": pcapng_file()[:20],
}


def test_bytes_that_are_not_a_capture_are_refused_and_each_refusal_is_audited(api: Api) -> None:
    for kind, data in NOT_CAPTURES.items():
        response = api.upload(data, name=CONFIDENTIAL_NAME)

        assert refusal_of(response) == (
            422,
            "invalid_capture_file",
            ERRORS["invalid_capture_file"].message,
        ), kind
        assert CONFIDENTIAL not in response.text
    entries = api.audit()
    assert [(e.action, e.actor, e.result, e.target) for e in entries] == [
        ("NETWORK_PCAP_ANALYZE", "alice", "rejected", None)
    ] * len(NOT_CAPTURES)
    assert [e.details for e in entries] == [
        {"reason": "invalid_capture_file", "size_bytes": len(data)}
        for data in NOT_CAPTURES.values()
    ]
    assert {e.source_ip for e in entries} == {CLIENT_ADDRESS}
    assert CONFIDENTIAL not in "".join(repr(vars(e)) for e in entries)
    assert_nothing_left(api)
    assert api.upload(EMPTY_CAPTURE).status_code == 202  # a refusal does not block the next one
    api.settle()


def test_an_empty_upload_is_refused(api: Api) -> None:
    for body in (b"", None):
        response = api.upload(body)

        assert refusal_of(response) == (422, "invalid_capture_file", "The upload is empty.")
    assert untouched(api)
    assert api.get(STATUS).json()["analysis"]["running"] is False


def test_only_the_raw_bytes_of_a_capture_are_accepted_as_the_body(
    api: Api, scan_files: dict[str, bytes]
) -> None:
    form = (
        b'--x\r\nContent-Disposition: form-data; name="file"; filename="a.pcap"\r\n\r\n'
        + scan_files["pcap"]
        + b"\r\n--x--\r\n"
    )
    wrong_types = {
        "multipart": "multipart/form-data; boundary=x",
        "json": "application/json",
        "text": "text/plain",
        "form": "application/x-www-form-urlencoded",
        "look-alike": "application/octet-streams",
        "none": None,
    }
    for kind, content_type in wrong_types.items():
        response = api.upload(form, content_type=content_type)

        assert (response.status_code, error_of(response)["code"]) == (
            415,
            "unsupported_media_type",
        ), kind
        assert error_of(response)["message"] == (
            "Upload the raw capture file as application/octet-stream."
        )
    # The type is judged first: a request of the wrong type does not get as far as its name.
    assert api.upload(form, name=None, content_type="text/plain").status_code == 415
    assert untouched(api)

    for content_type in [
        "application/octet-stream; charset=binary",
        "APPLICATION/OCTET-STREAM",
        "  application/octet-stream  ",
    ]:
        response = api.upload(EMPTY_CAPTURE, content_type=content_type)

        assert response.status_code == 202, content_type
        api.finished(response.json()["id"])
        api.settle()


def test_a_declared_length_that_cannot_be_true_is_refused_before_the_body_is_read(api: Api) -> None:
    def declaring(length: str) -> Response:
        return api.upload(EMPTY_CAPTURE, headers={**api.alice, "Content-Length": length})

    for declared in ["abc", "-5", "1e3", "+5", "", " ", "12 34", "0x10", "1,000", "5.0"]:
        response = declaring(declared)

        assert (response.status_code, error_of(response)["code"]) == (
            400,
            "invalid_content_length",
        ), declared
    for declared in [str(50 * MEGABYTE + 1), "9" * 16, "9" * 400]:
        response = declaring(declared)

        assert (response.status_code, error_of(response)["code"]) == (413, "file_too_large")
        assert error_of(response)["message"] == "The capture file is larger than the 50 MB limit."
    assert untouched(api)
    assert declaring(str(50 * MEGABYTE)).status_code == 202  # the limit itself is allowed
    api.settle()


def test_the_size_limit_is_exact(build_api: ApiFactory) -> None:
    api = build_api(network_max_pcap_size_mb=1)
    exact = classic_pcap([(T0, bytes(MEGABYTE - 24 - 16))])
    assert len(exact) == MEGABYTE

    accepted = api.upload(exact)

    assert accepted.status_code == 202
    assert api.finished(accepted.json()["id"])["status"] == "completed"
    api.settle()
    over = exact + b"\x00"
    declared = api.upload(over)
    streamed = drive(api, chunks_of(over, 64 * 1024))  # no declared length at all
    for status, body in [(declared.status_code, declared.json()), (streamed.status, streamed.body)]:
        assert (status, body["error"]["code"]) == (413, "file_too_large")
        assert body["error"]["message"] == "The capture file is larger than the 1 MB limit."
    assert len(api.sessions()) == 1  # only the file that fitted
    assert api.spool_files() == []
    assert api.get(STATUS).json()["analysis"]["running"] is False


def test_reading_stops_as_soon_as_the_limit_is_crossed(build_api: ApiFactory) -> None:
    api = build_api(network_max_pcap_size_mb=1)
    block = bytes(256 * 1024)

    honest = drive(api, [block] * 8)
    lying = drive(api, [block] * 8, headers=[("content-length", "10")])

    for refused in (honest, lying):
        assert (refused.status, refused.body["error"]["code"]) == (413, "file_too_large")
        assert refused.consumed == 5  # four blocks fit exactly, the fifth is too much, no more
    assert untouched(api)
    assert api.get(STATUS).json()["analysis"]["running"] is False


def test_a_client_that_hangs_up_mid_upload_leaves_nothing_behind(
    api: Api, scan_files: dict[str, bytes]
) -> None:
    data = scan_files["pcap"]

    for chunks in ([], [data[:100]], [data[:100], data[100:2000]]):
        hung_up = drive(api, chunks, hang_up=True)

        assert (hung_up.status, hung_up.body["error"]["code"]) == (400, "upload_interrupted")
        assert hung_up.body["error"]["message"] == "The request body was not received completely."
    assert untouched(api)
    assert api.get(STATUS).json()["analysis"]["running"] is False
    assert api.upload(data).status_code == 202
    api.settle()


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_a_capture_that_arrives_in_small_pieces_is_the_same_capture(
    api: Api, scan_files: dict[str, bytes], kind: str
) -> None:
    whole = api.finished(api.upload(scan_files[kind]).json()["id"])
    api.settle()

    pieces = drive(api, chunks_of(scan_files[kind], 97))
    assert pieces.status == 202
    in_pieces = api.finished(pieces.body["id"])
    api.settle()

    keys = ("status", "packets_total", "bytes_total", "flows_total", "alerts_total", "protocols")
    assert {key: in_pieces[key] for key in keys} == {key: whole[key] for key in keys}
    assert whole["packets_total"] == SCAN_FLOWS


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_a_capture_cut_short_is_analysed_as_far_as_it_goes(
    api: Api, scan_files: dict[str, bytes], kind: str
) -> None:
    response = api.upload(scan_files[kind][:-7])

    assert response.status_code == 202
    detail = api.finished(response.json()["id"])
    api.settle()
    assert (detail["status"], detail["error_code"]) == ("completed", "capture_truncated")
    assert detail["message"] == ERRORS["capture_truncated"].message
    assert (detail["packets_total"], detail["flows_total"], detail["alerts_total"]) == (
        SCAN_FLOWS,
        SCAN_FLOWS,
        1,
    )
    (entry,) = api.audit("NETWORK_PCAP_ANALYZE")
    assert entry.result == "success"
    assert (entry.details["truncated"], entry.details["packets"]) == (True, SCAN_FLOWS)


def test_a_disk_that_fails_during_an_upload_is_a_plain_500_and_changes_nothing(
    api: Api, monkeypatch: pytest.MonkeyPatch, scan_files: dict[str, bytes]
) -> None:
    def refuse(_path: Path) -> Any:
        raise OSError(28, "no space left: disk-detail-xyz")

    with monkeypatch.context() as patch:
        patch.setattr(pcap_module, "_open_exclusive", refuse)
        response = api.upload(scan_files["pcap"])

    assert refusal_of(response) == (500, "internal_error", "An internal error occurred.")
    assert "disk-detail-xyz" not in response.text
    assert untouched(api)
    assert api.get(STATUS).json()["analysis"]["running"] is False
    assert api.upload(scan_files["pcap"]).status_code == 202  # the next one works
    api.settle()


def test_a_database_that_fails_as_the_session_is_created_leaves_nothing_running(
    api: Api, monkeypatch: pytest.MonkeyPatch, scan_files: dict[str, bytes]
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise OperationalError("INSERT", {}, Exception("database-detail-xyz"))

    with monkeypatch.context() as patch:
        patch.setattr(repository_module, "new_session", broken)
        response = api.upload(scan_files["pcap"])

    assert refusal_of(response) == (500, "internal_error", "An internal error occurred.")
    assert "database-detail-xyz" not in response.text
    assert untouched(api)
    assert api.get(STATUS).json()["analysis"]["running"] is False
    assert api.upload(scan_files["pcap"]).status_code == 202
    api.settle()


def test_a_second_analysis_is_refused_before_its_body_is_read(
    api: Api, scan_files: dict[str, bytes], hold_analysis: AnalysisGate
) -> None:
    data = scan_files["pcap"]
    first_id = api.upload(data).json()["id"]
    wait_until(hold_analysis.entered.is_set, what="the analysis to start")

    owner = api.get(STATUS).json()["analysis"]
    other = api.get(STATUS, headers=api.bob).json()["analysis"]
    early = drive(api, [data])
    bobs = api.upload(data, headers=api.bob)

    assert owner == {"running": True, "session_id": first_id, "max_upload_mb": 50}
    assert other == {"running": True, "session_id": None, "max_upload_mb": 50}  # whose is private
    assert (early.status, early.body["error"]["code"]) == (409, "analysis_already_running")
    assert early.consumed == 0  # not a byte of the second file was asked for
    assert (bobs.status_code, error_of(bobs)["code"]) == (409, "analysis_already_running")
    assert len(api.spool_files()) == 1  # the running analysis' file, and no other
    assert [e.target for e in api.audit("NETWORK_PCAP_ANALYZE")] == [target_of(first_id)]
    assert api.delete(url(SESSION, first_id)).status_code == 409
    assert api.get(url(SESSION, first_id)).json()["status"] == "running"

    hold_analysis.release.set()
    assert api.finished(first_id)["status"] == "completed"
    api.settle()
    assert api.spool_files() == []
    assert api.upload(data, headers=api.bob).status_code == 202  # the slot is free for anyone
    api.settle()


def test_two_uploads_that_both_passed_the_early_check_cannot_both_analyse(
    api: Api,
    scan_files: dict[str, bytes],
    hold_analysis: AnalysisGate,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = scan_files["pcap"]
    first_id = api.upload(data).json()["id"]
    wait_until(hold_analysis.entered.is_set, what="the analysis to start")
    # As if this one had been let in before the first took the slot.
    monkeypatch.setattr(api.app.state.network_service, "ensure_analysis_idle", lambda: None)

    late = api.upload(data, headers=api.bob)

    assert (late.status_code, error_of(late)["code"]) == (409, "analysis_already_running")
    assert len(api.spool_files()) == 1  # the late file was removed again
    (rejected,) = [e for e in api.audit("NETWORK_PCAP_ANALYZE") if e.result == "rejected"]
    assert (rejected.actor, rejected.target) == ("bob", None)
    assert rejected.details == {"reason": "analysis_already_running"}
    assert [row.owner for row in api.sessions()] == ["alice"]
    hold_analysis.release.set()
    assert api.finished(first_id)["status"] == "completed"
    api.settle()


def test_a_live_capture_and_a_file_analysis_run_side_by_side(
    api: Api, scan_files: dict[str, bytes]
) -> None:
    live_id = api.start().json()["session_id"]
    file_id = api.upload(scan_files["pcap"]).json()["id"]
    analysed = api.finished(file_id)
    api.settle()

    api.desk.sources[0].emit(*scan_traffic()[:3])
    api.post(STOP)

    live = api.get(url(SESSION, live_id)).json()
    assert (live["source_kind"], live["status"], live["packets_total"]) == ("live", "stopped", 3)
    assert (analysed["source_kind"], analysed["packets_total"]) == ("pcap", SCAN_FLOWS)


# --- Listings: pages, filters and what is not a valid request -----------------------------------


def ids_of(page: dict[str, Any]) -> list[str]:
    return [item["id"] for item in page["items"]]


def is_utc(stamp: str) -> bool:
    return datetime.fromisoformat(stamp).utcoffset() == timedelta(0)


def test_sessions_are_listed_newest_first_one_page_at_a_time(api: Api) -> None:
    newest_first = [
        str(api.seed_session(started=ago(minutes=10 + number), label=f"{number}.pcap"))
        for number in range(7)
    ]
    # Sessions that began in the same instant are put in the order of their ids, so no page repeats.
    instant = ago(minutes=30)
    tied = sorted(str(api.seed_session(started=instant)) for _ in range(4))
    everything = newest_first + tied
    theirs = str(api.seed_session(owner="bob", started=ago(minutes=1)))

    page = api.get(SESSIONS).json()

    assert (page["total"], page["limit"], page["offset"]) == (11, 25, 0)
    assert ids_of(page) == everything
    assert {"owner", "stats"}.isdisjoint(page["items"][0])
    assert is_utc(page["items"][0]["started_at"]) and is_utc(page["items"][0]["ended_at"])
    pieces: list[str] = []
    for offset in range(0, 12, 4):
        piece = api.get(SESSIONS, limit=4, offset=offset).json()
        assert (piece["total"], piece["limit"], piece["offset"]) == (11, 4, offset)
        pieces += ids_of(piece)
    assert pieces == everything  # each session on exactly one page
    assert api.get(SESSIONS, limit=4, offset=11).json() == {
        "items": [],
        "total": 11,
        "limit": 4,
        "offset": 11,
    }
    # The ends of the ranges that are allowed.
    assert ids_of(api.get(SESSIONS, limit=1).json()) == everything[:1]
    assert ids_of(api.get(SESSIONS, limit=100).json()) == everything
    furthest = api.get(SESSIONS, limit=100, offset=1_000_000)
    assert (furthest.status_code, furthest.json()["items"], furthest.json()["total"]) == (
        200,
        [],
        11,
    )
    # Everyone lists their own sessions only; an administrator has none, and is given no more.
    assert ids_of(api.get(SESSIONS, headers=api.bob).json()) == [theirs]
    assert api.get(SESSIONS, headers=api.root).json()["total"] == 0


def test_flows_are_listed_newest_first_and_no_page_repeats_one(api: Api) -> None:
    session_id = api.seed_session()
    start = ago(minutes=20)
    later = [
        seed_flow(
            api.factory, session_id, dport=1000 + number, first=start + timedelta(seconds=number)
        )
        for number in range(6)
    ]
    # Flows that began in the same instant: the later one is shown first, whatever the page size.
    tied = [
        seed_flow(api.factory, session_id, dport=2000 + number, first=start - timedelta(seconds=5))
        for number in range(4)
    ]
    expected = [*reversed(later), *reversed(tied)]
    seed_flow(api.factory, api.seed_session())  # another session of the same analyst
    seed_flow(api.factory, api.seed_session(owner="bob"))

    flows = api.get(url(FLOWS, session_id)).json()

    assert (flows["total"], flows["limit"], flows["offset"]) == (10, 50, 0)
    assert [item["id"] for item in flows["items"]] == expected
    pieces: list[int] = []
    for offset in range(0, 12, 4):
        piece = api.get(url(FLOWS, session_id), limit=4, offset=offset).json()
        assert (piece["total"], piece["limit"], piece["offset"]) == (10, 4, offset)
        pieces += [item["id"] for item in piece["items"]]
    assert pieces == expected
    furthest = api.get(url(FLOWS, session_id), limit=200, offset=1_000_000)
    assert (furthest.status_code, furthest.json()["items"], furthest.json()["total"]) == (
        200,
        [],
        10,
    )
    assert len(api.get(url(FLOWS, session_id), limit=200).json()["items"]) == 10


def test_a_flow_is_described_whatever_its_protocol(api: Api) -> None:
    session_id = api.seed_session()
    start = ago(minutes=20)
    seed_flow(
        api.factory,
        session_id,
        first=start,
        last=start + timedelta(seconds=2.5),
        close_reason="idle",
    )
    seed_flow(api.factory, session_id, protocol="udp", dport=53, first=start - timedelta(seconds=1))
    seed_flow(
        api.factory,
        session_id,
        protocol="icmp",
        sport=None,
        dport=None,
        first=start - timedelta(seconds=2),
    )

    tcp, udp, icmp = api.get(url(FLOWS, session_id)).json()["items"]

    assert (tcp["protocol"], tcp["src_port"], tcp["dst_port"]) == ("tcp", 40000, 80)
    assert (tcp["tcp_flags"], tcp["tcp_flag_names"], tcp["close_reason"]) == (2, ["SYN"], "idle")
    assert tcp["duration_seconds"] == pytest.approx(2.5)
    assert (tcp["packets_out"], tcp["packets_in"], tcp["bytes_out"], tcp["bytes_in"]) == (
        1,
        1,
        60,
        60,
    )
    assert is_utc(tcp["first_seen"]) and is_utc(tcp["last_seen"])
    assert (udp["protocol"], udp["dst_port"], udp["tcp_flags"], udp["tcp_flag_names"]) == (
        "udp",
        53,
        None,
        [],
    )
    assert (icmp["protocol"], icmp["src_port"], icmp["dst_port"]) == ("icmp", None, None)
    assert udp["duration_seconds"] == icmp["duration_seconds"] == 0.0
    assert set(tcp) == {
        "id",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "first_seen",
        "last_seen",
        "duration_seconds",
        "packets_out",
        "packets_in",
        "bytes_out",
        "bytes_in",
        "tcp_flags",
        "tcp_flag_names",
        "close_reason",
    }


ALERTS_RAISED = [  # from the oldest to the newest
    ("NET-001", "medium"),
    ("NET-002", "high"),
    ("NET-003", "critical"),
    ("NET-006", "low"),
    ("NET-001", "high"),
    ("NET-007", "medium"),
]


def test_alerts_are_filtered_by_severity_and_rule_and_the_total_follows_the_filter(
    api: Api,
) -> None:
    session_id = api.seed_session()
    start = ago(minutes=30)
    numbered = {
        str(
            seed_alert(
                api.factory,
                session_id,
                rule_id=rule,
                severity=severity,
                created=start + timedelta(seconds=number),
            )
        ): number
        for number, (rule, severity) in enumerate(ALERTS_RAISED)
    }
    # Alerts of other sessions, the analyst's own included, never turn up in this one.
    elsewhere = api.seed_session()
    seed_alert(api.factory, elsewhere, severity="high")
    seed_alert(api.factory, api.seed_session(owner="bob"), severity="high")
    path = url(ALERTS, session_id)

    def listed(**params: Any) -> tuple[list[int], int]:
        response = api.get(path, **params)
        assert response.status_code == 200, response.text
        page = response.json()
        return [numbered[item["id"]] for item in page["items"]], page["total"]

    assert listed() == ([5, 4, 3, 2, 1, 0], 6)
    assert listed(severity="high") == ([4, 1], 2)
    assert listed(severity=["high", "critical"]) == ([4, 2, 1], 3)
    assert listed(severity=["high", "high"]) == ([4, 1], 2)
    assert listed(severity=["low", "medium", "high", "critical"]) == ([5, 4, 3, 2, 1, 0], 6)
    assert listed(rule="NET-001") == ([4, 0], 2)
    assert listed(rule="NET-001", severity="high") == ([4], 1)
    assert listed(rule="NET-001", severity="critical") == ([], 0)
    assert listed(rule="NET-004") == ([], 0)  # a rule that did not fire
    # The pages are cut from the filtered list, and its total is the filtered total.
    assert listed(severity=["medium", "high"], limit=2, offset=1) == ([4, 1], 4)
    assert listed(severity=["medium", "high"], limit=2, offset=4) == ([], 4)
    rules = {rule["rule_id"]: rule for rule in api.get(RULES).json()}
    for item in api.get(path).json()["items"]:
        rule = rules[item["rule_id"]]
        assert (item["title"], item["unit"]) == (rule["title"], rule["unit"])
        assert is_utc(item["created_at"]) and is_utc(item["first_observed"])


def test_alerts_raised_at_the_same_moment_are_paged_without_repeats(api: Api) -> None:
    session_id = api.seed_session()
    moment = ago(minutes=30)
    raised = sorted(
        str(seed_alert(api.factory, session_id, created=moment, dst_port=1000 + number))
        for number in range(12)
    )

    pieces: list[str] = []
    for offset in range(0, 15, 5):
        piece = api.get(url(ALERTS, session_id), limit=5, offset=offset).json()
        assert piece["total"] == 12
        pieces += ids_of(piece)

    assert pieces == raised  # in the order of their ids, each on one page only


HOSTILE = "<script>alert(document.cookie)</script>"
TOO_MANY = "99999999999999999999"
PAGED = [
    (SESSIONS, 100),
    (FLOWS, 200),
    (ALERTS, 200),
]


def test_a_page_that_cannot_exist_is_refused_before_anything_is_read(api: Api) -> None:
    session_id = api.seed_session()
    for template, largest in PAGED:
        path = url(template, session_id)
        bad = {
            "limit": ["0", "-1", str(largest + 1), "abc", "1.5", "", TOO_MANY, HOSTILE],
            "offset": ["-1", "1000001", "abc", "1.5", "", TOO_MANY, HOSTILE],
        }
        for name, values in bad.items():
            for value in values:
                response = api.get(path, **{name: value})

                assert response.status_code == 422, (path, name, value)
                assert error_of(response)["code"] == "validation_error"
                assert error_of(response)["details"][0]["loc"] == ["query", name]
                assert HOSTILE not in response.text and TOO_MANY not in response.text
        accepted = api.get(path, limit=largest, offset=1_000_000)
        assert accepted.status_code == 200, (path, accepted.text)
    assert api.audit() == []


def test_a_filter_that_names_no_severity_or_rule_is_refused(api: Api) -> None:
    path = url(ALERTS, api.seed_session())

    for value in ["urgent", "HIGH", "High", "info", "", "high,critical", "high;low", HOSTILE]:
        response = api.get(path, severity=value)
        assert response.status_code == 422, value
        assert error_of(response)["details"][0]["loc"][:2] == ["query", "severity"]
        assert HOSTILE not in response.text
    assert api.get(path, severity=["high", "urgent"]).status_code == 422
    for value in [
        "NET-1",
        "NET-0010",
        "net-001",
        "NET-00A",
        "NET_001",
        " NET-001",
        "NET-001 ",
        "NET-001\n",  # a line break must not slip past the end of the pattern
        "NET-\u0660\u0660\u0661",  # digits of another script
        "",
        "'; DROP TABLE network_alerts;--",
        HOSTILE,
    ]:
        response = api.get(path, rule=value)
        assert response.status_code == 422, repr(value)
        assert error_of(response)["details"][0]["loc"] == ["query", "rule"]
        assert HOSTILE not in response.text
    assert api.get(path, rule="NET-001").status_code == 200
    assert api.count(NetworkAlert) == 0 and api.count(CaptureSession) == 1  # nothing was damaged


ID_ROUTES = [(method, path) for method, path in ROUTES if "{" in path]


def test_an_identifier_that_is_not_a_uuid_is_invalid_and_an_unknown_one_is_not_found(
    api: Api,
) -> None:
    for method, template in ID_ROUTES:
        for bad in [
            "not-a-uuid",
            "123",
            "%00",
            "1' OR '1'='1",
            UNKNOWN[:-1],
            UNKNOWN + "0",
            "null",
        ]:
            response = api.request(method, url(template, bad))

            assert response.status_code == 422, (method, template, bad)
            assert error_of(response)["code"] == "validation_error"
            assert error_of(response)["details"][0]["loc"][0] == "path"
        response = api.request(method, url(template))
        wanted = "alert_not_found" if template == ENRICH else "session_not_found"
        assert (response.status_code, error_of(response)["code"]) == (404, wanted)
    assert api.audit() == []
    assert api.intel.calls == []


# --- Whose sessions they are --------------------------------------------------------------------


@dataclass
class Stock:
    """A finished session of an analyst with its flows and alerts, and the id of one alert."""

    session: str
    alert: str


def stock(api: Api, owner: str = "alice") -> Stock:
    session_id = api.seed_session(owner=owner, flows=3, alerts=2)
    for number in range(3):
        began = ago(minutes=9) + timedelta(seconds=number)
        seed_flow(api.factory, session_id, dport=80 + number, first=began)
    failed = {"status": "failed", "address": SCANNER, "error_code": "lookup_failed"}
    alert = seed_alert(api.factory, session_id, severity="high", enrichment=failed)
    seed_alert(api.factory, session_id, rule_id="NET-002", severity="low", enrichment=failed)
    return Stock(str(session_id), str(alert))


def blind(response: Response) -> tuple[int, Any]:
    """An answer without its correlation id, which differs for every request."""
    body = response.json() if response.content else None
    if body is not None:
        body["error"].pop("correlation_id")
    return response.status_code, body


LOOK_ALIKES = ["ALICE", "alice ", "alic%", "al_ce", "alice2", "alice*"]


def test_a_session_and_all_that_is_in_it_belong_to_one_analyst_only(api: Api) -> None:
    mine = stock(api)
    running = api.start().json()["session_id"]
    theirs = stock(api, "bob")
    audited = [entry.id for entry in api.audit()]
    callers = {
        "another analyst": api.bob,
        "an administrator": api.root,
        **{repr(name): api.auth(oid=name) for name in LOOK_ALIKES},
    }
    probes = [
        ("GET", SESSION, mine.session),
        ("GET", FLOWS, mine.session),
        ("GET", ALERTS, mine.session),
        ("DELETE", SESSION, mine.session),
        ("POST", ENRICH, mine.alert),
        ("GET", SESSION, running),
        ("GET", FLOWS, running),
        ("GET", ALERTS, running),
        ("DELETE", SESSION, running),  # "still running" is for its owner to hear, not a stranger
    ]

    for who, headers in callers.items():
        for method, template, identifier in probes:
            foreign = api.request(method, url(template, identifier), headers=headers)
            unknown = api.request(method, url(template), headers=headers)

            assert foreign.status_code == 404, (who, method, template)
            assert blind(foreign) == blind(unknown), (who, method, template)
        assert ids_of(api.get(SESSIONS, headers=headers).json()) == (
            [theirs.session] if who == "another analyst" else []
        ), who

    # Nothing of Alice's was read, changed or looked up on a stranger's behalf.
    assert [entry.id for entry in api.audit()] == audited
    assert api.intel.calls == []
    assert (api.count(CaptureSession), api.count(NetworkFlow), api.count(NetworkAlert)) == (3, 6, 4)
    assert api.get(STATUS).json()["state"] == "running"
    for template in (SESSION, FLOWS, ALERTS):
        assert api.get(url(template, mine.session)).status_code == 200
    # Ownership follows who is signed in, not their role: an administrator who is Alice is Alice.
    admin_alice = api.get(url(SESSION, mine.session), headers=api.auth((ADMIN,), oid="alice"))
    assert admin_alice.status_code == 200


def test_deleting_a_session_takes_its_flows_and_alerts_and_nothing_else(api: Api) -> None:
    doomed, kept, theirs = stock(api), stock(api), stock(api, "bob")

    response = api.delete(url(SESSION, doomed.session))

    assert (response.status_code, response.content) == (204, b"")
    for template in (SESSION, FLOWS, ALERTS):
        assert api.get(url(template, doomed.session)).status_code == 404
    assert api.post(url(ENRICH, doomed.alert)).status_code == 404
    assert (api.count(CaptureSession), api.count(NetworkFlow), api.count(NetworkAlert)) == (2, 6, 4)
    assert ids_of(api.get(SESSIONS).json()) == [kept.session]
    assert api.get(url(FLOWS, kept.session)).json()["total"] == 3
    assert api.get(url(ALERTS, kept.session)).json()["total"] == 2
    assert api.get(url(FLOWS, theirs.session), headers=api.bob).json()["total"] == 3
    (entry,) = api.audit("NETWORK_SESSION_DELETE")
    assert (entry.actor, entry.result, entry.target) == (
        "alice",
        "success",
        target_of(doomed.session),
    )
    assert entry.source_ip == CLIENT_ADDRESS
    assert entry.details == {"source": "pcap", "flows": 3, "alerts": 2}

    again = api.delete(url(SESSION, doomed.session))

    assert refusal_of(again) == (404, "session_not_found", "Monitoring session not found.")
    assert len(api.audit("NETWORK_SESSION_DELETE")) == 1


# --- Looking an alert's address up --------------------------------------------------------------


def an_alert(
    api: Api, *, src: str | None = SCANNER, dst: str | None = SERVER, owner: str = "alice"
) -> tuple[str, str]:
    """An alert nobody has looked up yet, in a session of its own: (session id, alert id)."""
    session_id = api.seed_session(owner=owner)
    waiting = {"status": "not_looked_up", "address": subject_address(src, dst)}
    alert_id = seed_alert(api.factory, session_id, src=src, dst=dst, enrichment=waiting)
    return str(session_id), str(alert_id)


def test_an_alerts_address_is_looked_up_for_the_caller_and_the_answer_is_kept(
    build_api: ApiFactory,
) -> None:
    answer = reply(
        provider_view("abuseipdb", "ok", verdict="suspicious"),
        provider_view("otx", "no_data", verdict=None),
        score=30,
        classification="low",
    )
    api = build_api(intel=StubIntel({SCANNER: answer}))
    session_id, alert_id = an_alert(api)

    response = api.post(url(ENRICH, alert_id))

    assert response.status_code == 200
    shown = response.json()
    assert (shown["id"], shown["session_id"]) == (alert_id, session_id)
    found = shown["enrichment"]
    assert (found["status"], found["address"], found["error_code"]) == ("completed", SCANNER, None)
    assert (found["risk_score"], found["classification"], found["assessed"]) == (30, "low", True)
    assert [(item["provider"], item["status"], item["verdict"]) for item in found["providers"]] == [
        ("abuseipdb", "ok", "suspicious"),
        ("otx", "no_data", None),
    ]
    # Asked as Alice, from where she is, and without forcing the providers past their caches.
    assert api.intel.calls == [SCANNER]
    (context,) = api.intel.contexts
    assert (context.actor, context.source_ip) == ("alice", CLIENT_ADDRESS)
    assert api.intel.refresh_flags == [False]
    (listed,) = api.get(url(ALERTS, session_id)).json()["items"]
    assert listed["enrichment"] == found
    assert api.stored(session_id).stats["enrichment"][SCANNER]["status"] == "completed"
    (entry,) = api.audit("NETWORK_ENRICH")
    assert (entry.actor, entry.result, entry.target) == (
        "alice",
        "success",
        f"network-alert:{alert_id}",
    )
    assert entry.source_ip == CLIENT_ADDRESS
    assert entry.details == {"status": "completed", "error_code": None}


def test_an_address_no_provider_knows_is_looked_up_without_a_score(build_api: ApiFactory) -> None:
    # The intelligence service scores an address nobody has evidence on as 0, informational.
    answer = reply(
        provider_view("abuseipdb", "no_data", verdict=None),
        provider_view("otx", "no_data", verdict=None),
        score=0,
        classification="informational",
    )
    api = build_api(intel=StubIntel({SCANNER: answer}))
    session_id, alert_id = an_alert(api)

    response = api.post(url(ENRICH, alert_id))

    assert response.status_code == 200
    found = response.json()["enrichment"]
    assert (found["status"], found["assessed"]) == ("completed", False)
    assert (found["risk_score"], found["classification"]) == (None, None)
    assert found["message"] == (
        "No provider returned evidence for this address. That does not mean it is safe."
    )
    (listed,) = api.get(url(ALERTS, session_id)).json()["items"]
    assert listed["enrichment"] == found


def test_a_lookup_that_fails_is_reported_as_failed_and_does_not_say_why(
    build_api: ApiFactory, caplog: pytest.LogCaptureFixture
) -> None:
    api = build_api(intel=StubIntel({SCANNER: RuntimeError(CONFIDENTIAL)}))
    caplog.set_level(logging.DEBUG)
    _, alert_id = an_alert(api)

    response = api.post(url(ENRICH, alert_id))

    assert response.status_code == 200
    found = response.json()["enrichment"]
    assert (found["status"], found["error_code"], found["risk_score"]) == (
        "failed",
        "lookup_failed",
        None,
    )
    assert CONFIDENTIAL not in response.text
    assert_not_logged(caplog, CONFIDENTIAL)
    (entry,) = api.audit("NETWORK_ENRICH")
    assert entry.result == "partial"
    assert entry.details == {"status": "failed", "error_code": "lookup_failed"}


def test_an_alert_without_a_public_address_has_nothing_to_look_up(api: Api) -> None:
    for src, dst in [
        (HOST, SERVER),
        (DOCUMENTATION, "198.51.100.7"),
        ("100.64.0.1", "169.254.1.1"),
        ("::1", "2001:db8::1"),
        (None, None),
    ]:
        _, alert_id = an_alert(api, src=src, dst=dst)

        assert refusal_of(api.post(url(ENRICH, alert_id))) == (
            422,
            "address_not_public",
            "The alert involves no public address, so there is nothing to look up.",
        )
    assert (api.intel.calls, api.audit()) == ([], [])


def test_nothing_is_looked_up_while_enrichment_is_switched_off(build_api: ApiFactory) -> None:
    api = build_api(external_enrichment_enabled=False)
    _, public = an_alert(api)
    _, private = an_alert(api, src=HOST, dst=SERVER)

    for alert_id in (public, private):  # the switch is read before the address is
        assert refusal_of(api.post(url(ENRICH, alert_id))) == (
            409,
            "enrichment_disabled",
            "External enrichment is switched off on this server.",
        )
    assert api.post(url(ENRICH)).status_code == 404
    assert (api.intel.calls, api.audit()) == ([], [])


# --- Rate limiting -------------------------------------------------------------------------------


def test_uploads_lookups_and_interface_refreshes_share_one_budget_for_each_analyst(
    build_api: ApiFactory,
) -> None:
    api = build_api(investigate_rate_limit_per_minute=2)
    session_id, alert_id = an_alert(api)
    assert api.get(INTERFACES, refresh=True).status_code == 200
    assert api.upload(EMPTY_CAPTURE).status_code == 202
    api.settle()

    turned_away = [
        api.post(url(ENRICH, alert_id)),
        api.get(INTERFACES, refresh=True),
        api.upload(EMPTY_CAPTURE),
    ]

    for response in turned_away:
        assert refusal_of(response) == (
            429,
            "rate_limited",
            "Too many investigations. Try again shortly.",
        )
        assert 1 <= int(response.headers["Retry-After"]) <= 60
    unread = drive(api, [EMPTY_CAPTURE])
    assert (unread.status, unread.body["error"]["code"], unread.consumed) == (
        429,
        "rate_limited",
        0,
    )
    assert api.catalog.refreshes == 1
    assert api.intel.calls == []
    assert len(api.sessions()) == 2  # the seeded one, and the one file that was accepted
    assert len(api.audit()) == 1 and api.spool_files() == []
    # Looking is free, and every analyst has a budget of their own.
    for path in (STATUS, INTERFACES, RULES, SESSIONS, *(url(t, session_id) for t in LISTED)):
        assert api.get(path).status_code == 200, path
    assert api.get(INTERFACES, refresh=True, headers=api.bob).status_code == 200
    assert api.get(INTERFACES, refresh=True, headers=api.root).status_code == 200
    assert api.post(url(ENRICH, alert_id), headers=api.bob).status_code == 404


LISTED = (SESSION, FLOWS, ALERTS)


def test_a_refused_request_still_costs_budget_but_one_turned_away_at_the_door_does_not(
    build_api: ApiFactory,
) -> None:
    api = build_api(investigate_rate_limit_per_minute=2)
    without_the_role = api.auth(("User",), oid="alice")
    for _ in range(5):
        assert call(api, "POST", PCAP, headers={}).status_code == 401
        assert call(api, "POST", PCAP, headers=without_the_role).status_code == 403

    assert api.upload(EMPTY_CAPTURE, content_type="text/plain").status_code == 415
    assert api.upload(EMPTY_CAPTURE, name=None).status_code == 422
    third = api.upload(EMPTY_CAPTURE)

    assert (third.status_code, error_of(third)["code"]) == (429, "rate_limited")
    assert untouched(api)


def test_the_budget_comes_back_as_the_window_moves_on(api: Api) -> None:
    clock = FakeClock(100.0)
    api.app.state.rate_limiter = SlidingWindowRateLimiter(2, clock=clock)

    def refresh() -> Response:
        return api.get(INTERFACES, refresh=True)

    assert [refresh().status_code for _ in range(2)] == [200, 200]
    denied = refresh()
    assert (denied.status_code, denied.headers["Retry-After"]) == (429, "60")
    clock.advance(25)
    assert refresh().headers["Retry-After"] == "35"  # asking again did not move the date back
    clock.advance(35)
    assert [refresh().status_code for _ in range(3)] == [200, 200, 429]


# --- Starting and stopping the server -----------------------------------------------------------


def test_a_server_that_starts_again_ends_what_the_one_before_left_running(
    build_api: ApiFactory, prior_run: SessionFactory
) -> None:
    waiting = {"status": "pending", "address": SCANNER}
    answered = {"status": "failed", "address": SCANNER, "error_code": "rate_limited"}
    live = {"source": CaptureSource.LIVE, "interface": TEST_INTERFACE.name, "label": None}
    unfinished = {
        "live": seed_session(prior_run, status=CaptureStatus.RUNNING, started=ago(hours=1), **live),
        "analysing": seed_session(prior_run, status=CaptureStatus.RUNNING, started=ago(minutes=20)),
        "stopping": seed_session(
            prior_run, owner="bob", status=CaptureStatus.STOPPING, started=ago(minutes=10), **live
        ),
        "starting": seed_session(
            prior_run, owner="carol", status=CaptureStatus.STARTING, started=ago(minutes=1), **live
        ),
    }
    finished = seed_session(prior_run, started=ago(minutes=40), flows=1, alerts=2)
    expired = seed_session(prior_run, started=ago(days=4), flows=1, alerts=1)
    seed_flow(prior_run, finished, first=ago(minutes=39))
    seed_flow(prior_run, expired, first=ago(days=4))
    cut_off = seed_alert(prior_run, unfinished["live"], enrichment=waiting)
    forgotten = seed_alert(prior_run, finished, enrichment=waiting)
    kept = seed_alert(prior_run, finished, rule_id="NET-002", enrichment=answered)
    seed_alert(prior_run, expired, enrichment=waiting)

    api = build_api()

    for name, session_id in unfinished.items():
        row = api.stored(str(session_id))
        assert row is not None, name
        assert (row.status, row.error_code) == ("failed", "interrupted"), name
        assert row.ended_at is not None and row.ended_at >= row.started_at, name
    survivor = api.stored(str(finished))
    assert survivor is not None
    assert (survivor.status, survivor.error_code) == ("completed", None)
    assert api.stored(str(expired)) is None  # past its retention, and gone with what it held
    assert (api.count(NetworkFlow), api.count(NetworkAlert)) == (1, 3)
    unavailable = {"status": "unavailable", "address": SCANNER, "error_code": "interrupted"}
    assert {str(row.id): row.enrichment for row in api.rows(select(NetworkAlert))} == {
        str(cut_off): unavailable,
        str(forgotten): unavailable,
        str(kept): answered,  # an answer is not touched, only a wait that nothing will end
    }
    # What the people it belonged to are told.
    status = api.get(STATUS).json()
    assert (status["state"], status["session_id"]) == ("failed", str(unfinished["live"]))
    assert (status["error_code"], status["message"]) == ("interrupted", message_for("interrupted"))
    assert status["interface"] == TEST_INTERFACE.name
    assert api.get(STATUS, headers=api.bob).json()["state"] == "failed"
    detail = api.get(url(SESSION, unfinished["live"])).json()
    assert (detail["status"], detail["error_code"]) == ("failed", "interrupted")
    assert detail["message"] == message_for("interrupted") and detail["ended_at"] is not None
    (alert,) = api.get(url(ALERTS, unfinished["live"])).json()["items"]
    assert (alert["enrichment"]["status"], alert["enrichment"]["error_code"]) == (
        "unavailable",
        "interrupted",
    )
    # Recovery looks nothing up and starts nothing, and nothing is left holding a slot.
    assert (api.desk.requested, api.intel.calls, api.audit()) == ([], [], [])
    assert api.get(STATUS).json()["analysis"]["running"] is False
    for name in ("live", "analysing"):  # they are no longer "still running"
        assert api.delete(url(SESSION, unfinished[name])).status_code == 204, name
    assert api.start().status_code == 200


def test_a_server_whose_database_is_not_migrated_still_starts_and_clears_its_uploads(
    make_settings: Callable[..., Settings],
    entra_validator: Any,
    tokens: TokenFactory,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    spool_base = tmp_path / "spool"
    spool_base.mkdir()
    left_behind = spool_base / "cipherforge-pcap-left-by-a-crash"
    left_behind.mkdir()
    (left_behind / "old.upload").write_bytes(b"x")
    backdate(left_behind, 3 * 24 * 3600)

    def build_service(
        config: Settings, session_factory: SessionFactory, intel_service: Any
    ) -> NetworkService:
        return NetworkService(
            config,
            session_factory,
            intel_service=intel_service,
            catalog=FakeCatalog(),
            source_factory=SourceDesk(),
            spool=UploadSpool(spool_base),
            pacing_interval=0.0,
        )

    app = create_app(
        # The default database is one nobody has migrated.
        make_settings(auth_mode="entra", entra_tenant_id=TENANT_ID, entra_client_id=CLIENT_ID),
        token_validator=entra_validator,
        intel_service=StubIntel(),
        network_service_factory=build_service,
    )
    caplog.set_level(logging.INFO)
    token = tokens.make({"roles": [ANALYST], "oid": "alice"})
    headers = {"Authorization": f"Bearer {token}"}

    with TestClient(app, client=(CLIENT_ADDRESS, 50000)) as client:
        rules = client.get(RULES, headers=headers)
        interfaces = client.get(INTERFACES, headers=headers)
        listing = client.get(SESSIONS, headers=headers)
        anonymous = client.get(RULES)

    assert (rules.status_code, len(rules.json())) == (200, 7)  # nothing here needs the database
    assert interfaces.status_code == 200
    assert refusal_of(listing) == (500, "internal_error", "An internal error occurred.")
    assert "no such table" not in listing.text
    assert anonymous.status_code == 401
    (skipped,) = logged(caplog, "network_startup_skipped")
    assert skipped.error == "OperationalError"
    assert not left_behind.exists()
    assert list(spool_base.iterdir()) == []  # and the server's own folder went when it stopped


def test_stopping_the_server_while_a_file_is_analysed_ends_the_analysis_and_clears_the_spool(
    build_api: ApiFactory, hold_analysis: AnalysisGate, scan_files: dict[str, bytes]
) -> None:
    api = build_api()
    session_id = api.upload(scan_files["pcap"], name=CONFIDENTIAL_NAME).json()["id"]
    wait_until(hold_analysis.entered.is_set, what="the analysis to start")
    assert len(api.spool_files()) == 1  # the file is kept for as long as it is read, and no longer

    api.close()

    row = api.stored(session_id)
    assert row is not None
    assert (row.status, row.error_code) == ("failed", "interrupted")
    assert row.ended_at is not None and row.ended_at >= row.started_at
    assert (row.packets_total, row.flows_total) == (0, 0)
    assert api.spool_files() == []
    (entry,) = api.audit("NETWORK_PCAP_ANALYZE")  # it was accepted, and the trail says so
    assert (entry.result, entry.target) == ("success", target_of(session_id))


# --- What a browser is allowed to see --------------------------------------------------------


ORIGIN = "http://localhost:5173"


def values_of(response: Response, name: str) -> set[str]:
    """The comma-separated values of a header, in lower case."""
    return {item.strip().lower() for item in response.headers[name].split(",")}


def test_the_dashboard_may_call_the_api_from_its_own_origin_and_no_other(
    build_api: ApiFactory,
) -> None:
    api = build_api(cors_origins=ORIGIN)
    ask = {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, content-type, x-file-name",
    }

    preflight = api.client.options(PCAP, headers=ask)

    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == ORIGIN
    sent = {"authorization", "content-type", "x-file-name"}
    assert sent <= values_of(preflight, "access-control-allow-headers")
    assert {"get", "post", "delete"} <= values_of(preflight, "access-control-allow-methods")
    assert "access-control-allow-credentials" not in preflight.headers
    assert untouched(api)  # the browser's question is answered without signing in or doing anything
    for what, changed in {
        "an origin that is not the dashboard": {"Origin": "https://evil.example"},
        "a header nobody offered": {"Access-Control-Request-Headers": "authorization, x-api-key"},
        "a method nobody offered": {"Access-Control-Request-Method": "PUT"},
    }.items():
        refused = api.client.options(PCAP, headers={**ask, **changed})

        assert refused.status_code == 400, what
        assert "disallowed" in refused.text.lower(), what
        if "Origin" in changed:  # a stranger is not even told what the dashboard may do
            assert "access-control-allow-origin" not in refused.headers
    assert untouched(api)

    # Every answer to the dashboard, an error included, says that the dashboard may read it.
    answers = [
        api.get(STATUS, headers={"Origin": ORIGIN}),
        api.get(STATUS, headers={**api.alice, "Origin": ORIGIN}),
        api.upload(
            EMPTY_CAPTURE, headers={**api.alice, "Origin": ORIGIN}, content_type="text/plain"
        ),
    ]
    assert [response.status_code for response in answers] == [401, 200, 415]
    for response in answers:
        assert response.headers["access-control-allow-origin"] == ORIGIN
        assert "x-correlation-id" in values_of(response, "access-control-expose-headers")
        assert "access-control-allow-credentials" not in response.headers
    stranger = api.get(STATUS, headers={**api.alice, "Origin": "https://evil.example"})
    assert stranger.status_code == 200 and "access-control-allow-origin" not in stranger.headers


def test_without_configured_origins_no_browser_is_given_access(api: Api) -> None:
    for answer in (
        api.get(STATUS, headers={**api.alice, "Origin": ORIGIN}),
        api.client.options(
            PCAP, headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST"}
        ),
    ):
        assert not [name for name in answer.headers if name.startswith("access-control-")]


def test_every_answer_is_uncacheable_and_can_be_traced(
    api: Api, scan_files: dict[str, bytes]
) -> None:
    session_id = api.upload(scan_files["pcap"]).json()["id"]
    api.finished(session_id)
    api.settle()
    answers = [
        api.get(STATUS),
        api.get(INTERFACES),
        api.get(RULES),
        api.get(SESSIONS),
        api.get(url(SESSION, session_id)),
        api.get(url(FLOWS, session_id)),
        api.get(url(ALERTS, session_id)),
        api.get(url(SESSION)),  # 404
        api.get(SESSIONS, limit=0),  # 422
        api.get(STATUS, headers={}),  # 401
        api.get(STATUS, headers=api.auth(("User",))),  # 403
        api.post(STOP),  # 409
        api.upload(EMPTY_CAPTURE, content_type="text/plain"),  # 415
        api.delete(url(SESSION, session_id)),  # 204
    ]

    assert [answer.status_code for answer in answers] == [
        *[200] * 7,
        *[404, 422, 401, 403, 409, 415, 204],
    ]
    for answer in answers:
        assert answer.headers["cache-control"] == "no-store", answer.request.url
        assert answer.headers["x-content-type-options"] == "nosniff", answer.request.url
        assert answer.headers["x-correlation-id"], answer.request.url
        if answer.status_code >= 400:  # an error says which request it answers
            assert error_of(answer)["correlation_id"] == answer.headers["x-correlation-id"]


# --- What the API says about itself --------------------------------------------------------------


def test_the_documentation_tells_a_client_how_to_upload_how_to_page_and_what_can_go_wrong(
    api: Api,
) -> None:
    paths = api.app.openapi()["paths"]

    def parameters(route: str, method: str = "get") -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in paths[route][method]["parameters"]}

    def bounds(route: str, name: str) -> tuple[Any, Any, Any]:
        schema = parameters(route)[name]["schema"]
        return schema["minimum"], schema["maximum"], schema["default"]

    upload = paths[PCAP]["post"]
    (header,) = [item for item in upload["parameters"] if item["name"] == "X-File-Name"]
    assert (header["in"], header["required"], header["schema"]["maxLength"]) == (
        "header",
        True,
        MAX_RAW_NAME,  # the limit it documents is the limit it enforces
    )
    assert upload["requestBody"]["required"] is True
    assert upload["requestBody"]["content"] == {
        OCTET: {"schema": {"type": "string", "format": "binary"}}
    }
    assert bounds(SESSIONS, "limit") == (1, 100, 25)
    assert bounds(SESSIONS, "offset") == (0, 1_000_000, 0)
    for route in (FLOWS, ALERTS):
        assert bounds(route, "limit") == (1, 200, 50)
        assert bounds(route, "offset") == (0, 1_000_000, 0)
    severities = parameters(ALERTS)["severity"]["schema"]["anyOf"][0]
    assert (severities["type"], severities["items"]["enum"]) == (
        "array",
        ["low", "medium", "high", "critical"],
    )
    assert parameters(ALERTS)["rule"]["schema"]["anyOf"][0]["pattern"] == "^NET-[0-9]{3}$"
    assert parameters(INTERFACES)["refresh"]["schema"]["type"] == "boolean"
    # Every answer a client can be given has a place in the documentation.
    documented = {
        ("GET", INTERFACES): {"200", "422", "429"},
        ("POST", START): {"200", "404", "409", "422", "503"},
        ("POST", STOP): {"200", "409"},
        ("POST", PCAP): {"202", "400", "409", "413", "415", "422", "429"},
        ("GET", SESSION): {"200", "404", "422"},
        ("DELETE", SESSION): {"204", "404", "409", "422"},
        ("POST", ENRICH): {"200", "404", "409", "422", "429"},
    }
    for (method, route), codes in documented.items():
        assert set(paths[route][method.lower()]["responses"]) == codes, (method, route)


# --- What is kept private ----------------------------------------------------------------------


def test_no_file_name_token_or_adapter_address_reaches_a_log_the_audit_trail_or_the_stats(
    api: Api, scan_files: dict[str, bytes], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    token = api.alice["Authorization"].removeprefix("Bearer ")
    secrets = [CONFIDENTIAL, token, *TEST_INTERFACE.addresses]
    good = api.upload(scan_files["pcap"], name=CONFIDENTIAL_NAME).json()["id"]
    api.finished(good)
    api.settle()
    cut = api.upload(scan_files["pcap"][:-7], name=CONFIDENTIAL_NAME).json()["id"]
    api.finished(cut)
    api.settle()
    api.upload(b"not a capture", name=CONFIDENTIAL_NAME)
    api.upload(EMPTY_CAPTURE, name=CONFIDENTIAL_NAME, content_type="text/plain")
    api.upload(EMPTY_CAPTURE, name=f"..\\{CONFIDENTIAL}.txt")
    api.start()
    api.desk.sources[0].emit(*scan_traffic()[:5])
    api.post(STOP)
    for path in (INTERFACES, RULES, SESSIONS, url(SESSION, good), url(FLOWS, good)):
        api.get(path)
    api.get(url(ALERTS, good))
    api.delete(url(SESSION, good))

    assert len(logged(caplog, "request")) >= 17  # the log was read at all
    for secret in secrets:
        assert_not_logged(caplog, secret)
    entries = api.audit()
    assert len(entries) >= 6
    for text in (repr(vars(entry)) for entry in entries):
        assert not [secret for secret in secrets if secret in text]
    for row in api.sessions():
        assert not [secret for secret in secrets if secret in json.dumps(row.stats)]
    labels = {row.source_label for row in api.sessions()}
    assert CONFIDENTIAL_NAME in labels  # kept for its owner, as the label of the session

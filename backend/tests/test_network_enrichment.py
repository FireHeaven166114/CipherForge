"""EnrichmentWorker: which addresses reach a provider, how an answer is recorded, and NET-005."""

import contextlib
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models.audit import AuditLog
from app.models.enums import CaptureSource, CaptureStatus
from app.models.network import CaptureSession, NetworkAlert
from app.network import enrichment as enrichment_module
from app.network import monitor as monitor_module
from app.network import views
from app.network.analyzer import ExternalPeer
from app.network.enrichment import (
    PRIORITY_ALERT,
    PRIORITY_TALKER,
    SYSTEM_ACTOR,
    EnrichmentRequest,
    EnrichmentWorker,
    summarize,
)
from app.network.recorder import EnrichmentStatus
from app.services.audit import IOC_LOOKUP
from app.services.intel_service import IndicatorDeletedError, IntelService, RequestContext
from app.services.normalization import InvalidIndicatorError
from tests.intel_helpers import STRONG, Clock, FakeAbuse, answer
from tests.network_helpers import (
    HOST,
    RESOLVER,
    SCANNER,
    SERVER,
    T0,
    FlakyFactory,
    MonitorRig,
    StubIntel,
    assert_no_module_threads,
    build_rig,
    module_threads,
    packet,
    provider_view,
    reply,
    scan_packets,
    seed_alert,
    seed_session,
    wait_until,
)

SessionFactory = sessionmaker[Session]

# Public addresses that stand in for the internet. Nothing here is ever contacted.
PUBLIC = [f"{50 + index}.1.2.3" for index in range(12)]
PUBLIC_FORMS = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "93.184.216.34",
    "45.33.32.156",
    "2001:4860:4860::8888",
]
# Private, reserved, documentation and malformed addresses: none of them may leave the process.
NOT_PUBLIC = [
    "10.1.2.3",
    "172.16.5.4",
    "192.168.1.5",
    "100.64.0.1",
    "169.254.10.10",
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104
    "224.0.0.1",
    "255.255.255.255",
    "192.0.2.77",
    "198.51.100.9",
    "203.0.113.9",
    "198.18.0.1",
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:10.0.0.1",
    "not-an-ip",
    "",
    "999.1.1.1",
    "example.com",
    "8.8.8.8/24",
    " 8.8.8.8",
    "8.8.8.8:80",
]
ANALYST = RequestContext(actor="analyst-1", source_ip="203.0.113.9")


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


@pytest.fixture
def new_worker(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[..., EnrichmentWorker]]:
    """Workers that need no database unless given a session factory; all are stopped afterwards."""
    workers: list[EnrichmentWorker] = []
    gates: list[threading.Event] = []
    # The idle worker wakes this often to look for a stop request; keep teardown quick.
    monkeypatch.setattr(enrichment_module, "_POLL_SECONDS", 0.02)

    def build(
        intel: Any = None,
        *,
        session_factory: Any = contextlib.nullcontext,
        pacing: float | None = 0.0,
        lock: Any = None,
        queue_size: int | None = None,
        settings: Settings | None = None,
        **overrides: Any,
    ) -> EnrichmentWorker:
        intel = intel if intel is not None else StubIntel()
        if queue_size is not None:
            monkeypatch.setattr(enrichment_module, "_MAX_QUEUE", queue_size)
        if getattr(intel, "gate", None) is not None:
            gates.append(intel.gate)
        worker = EnrichmentWorker(
            intel_service=intel,
            session_factory=session_factory,
            settings=settings or make_settings(**overrides),
            stats_lock=lock or threading.Lock(),
            pacing_interval=pacing,
        )
        workers.append(worker)
        return worker

    yield build
    for gate in gates:
        gate.set()
    for worker in workers:
        worker.stop()


@pytest.fixture
def make_worker(
    new_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> Callable[..., EnrichmentWorker]:
    """Workers on the test database."""

    def build(intel: Any = None, **options: Any) -> EnrichmentWorker:
        options.setdefault("session_factory", factory)
        return new_worker(intel, **options)

    return build


def gated(stub: StubIntel) -> StubIntel:
    """Hold every lookup until the test sets ``stub.gate``."""
    stub.gate = threading.Event()
    return stub


def request(
    address: str, *, priority: int = PRIORITY_ALERT, facts: dict[str, Any] | None = None
) -> EnrichmentRequest:
    return EnrichmentRequest(
        address, priority, facts if facts is not None else {"address": address}
    )


def running_session(factory: SessionFactory, **options: Any) -> uuid.UUID:
    return seed_session(
        factory,
        status=CaptureStatus.RUNNING,
        source=CaptureSource.LIVE,
        interface="Test Ethernet",
        label=None,
        **options,
    )


def pending_for(address: str) -> dict[str, Any]:
    return {"status": "pending", "address": address}


def facts_for(address: str, **overrides: Any) -> dict[str, Any]:
    """What the monitor hands over about a public address (the form kept in the session stats)."""
    peer = ExternalPeer(
        address=address,
        first_seen=T0,
        last_seen=T0 + 30,
        packets=12,
        bytes=3400,
        sent_to=True,
        peers=[HOST],
        ports=[443],
        protocols=["tcp"],
    )
    return replace(peer, **overrides).as_facts()


def completed_summary(
    address: str = SCANNER,
    *,
    score: int = 75,
    classification: str = "high",
    statuses: tuple[str, ...] = ("ok",),
) -> dict[str, Any]:
    views_ = [provider_view(f"provider{index}", status) for index, status in enumerate(statuses)]
    return summarize(address, reply(*views_, score=score, classification=classification))


def stored_stats(factory: SessionFactory, session_id: uuid.UUID) -> dict[str, Any]:
    with factory() as db:
        row = db.get(CaptureSession, session_id)
        assert row is not None
        return dict(row.stats)


def stored_total(factory: SessionFactory, session_id: uuid.UUID) -> int:
    with factory() as db:
        row = db.get(CaptureSession, session_id)
        assert row is not None
        return row.alerts_total


def stored_alerts(factory: SessionFactory, session_id: uuid.UUID) -> list[NetworkAlert]:
    with factory() as db:
        return list(
            db.scalars(
                select(NetworkAlert)
                .where(NetworkAlert.session_id == session_id)
                .order_by(NetworkAlert.rule_id, NetworkAlert.created_at)
            )
        )


def known_malicious(factory: SessionFactory, session_id: uuid.UUID) -> list[NetworkAlert]:
    return [row for row in stored_alerts(factory, session_id) if row.rule_id == "NET-005"]


def alert_state(factory: SessionFactory, alert_id: uuid.UUID) -> dict[str, Any]:
    with factory() as db:
        row = db.get(NetworkAlert, alert_id)
        assert row is not None
        return dict(row.enrichment)


def answer_for(factory: SessionFactory, session_id: uuid.UUID, address: str) -> Any:
    return (stored_stats(factory, session_id).get("enrichment") or {}).get(address)


def counted_by_rule(factory: SessionFactory, session_id: uuid.UUID) -> dict[str, int]:
    """The alerts per rule that the session's detail shows."""
    with factory() as db:
        row = db.get(CaptureSession, session_id)
        assert row is not None
        shown = views.session_detail(
            row, now=datetime.now(UTC), enrichment_enabled=True, is_pending=lambda _: False
        )
    return shown.alerts_by_rule


def drain(worker: EnrichmentWorker) -> None:
    wait_until(lambda: worker.pending_count() == 0, what="the worker to empty its queue")


def not_applicable(address: str) -> dict[str, Any]:
    return {"status": "not_applicable", "address": address}


# --- Which addresses are looked up ------------------------------------------------------------


def test_addresses_that_are_not_public_never_reach_a_provider(
    new_worker: Callable[..., EnrichmentWorker],
) -> None:
    stub = StubIntel()
    worker = new_worker(stub)

    outcomes = {address: worker.lookup(address) for address in NOT_PUBLIC}

    wrong = {a: o for a, o in outcomes.items() if o != (not_applicable(a), False)}
    assert wrong == {}
    assert stub.calls == []


def test_a_public_address_is_looked_up_as_the_system_and_may_use_the_cache(
    new_worker: Callable[..., EnrichmentWorker],
) -> None:
    stub = StubIntel()
    worker = new_worker(stub)

    outcomes = [worker.lookup(address) for address in PUBLIC_FORMS]

    assert [(o[0]["status"], o[0]["address"], o[1]) for o in outcomes] == [
        ("completed", address, True) for address in PUBLIC_FORMS
    ]
    assert stub.calls == PUBLIC_FORMS
    assert SYSTEM_ACTOR == "system:network-monitor"
    assert stub.contexts == [RequestContext(actor=SYSTEM_ACTOR)] * len(PUBLIC_FORMS)
    # A cached answer is reused: forcing a refresh would spend provider quota on every address.
    assert stub.refresh_flags == [False] * len(PUBLIC_FORMS)


def test_nothing_is_looked_up_while_external_enrichment_is_off(
    new_worker: Callable[..., EnrichmentWorker],
) -> None:
    stub = StubIntel()
    worker = new_worker(stub, external_enrichment_enabled=False)

    assert worker.lookup(SCANNER) == ({"status": "disabled", "address": SCANNER}, False)
    assert worker.lookup(HOST) == ({"status": "disabled", "address": HOST}, False)
    assert stub.calls == []


def test_a_lookup_for_a_caller_is_recorded_under_the_caller(
    new_worker: Callable[..., EnrichmentWorker],
) -> None:
    stub = StubIntel()

    new_worker(stub).lookup(SCANNER, context=ANALYST)

    assert stub.contexts == [ANALYST]


# --- What a lookup records --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("views_", "status", "error_code", "assessed", "contacted"),
    [
        pytest.param(["ok"], "completed", None, True, True, id="answer"),
        pytest.param(["ok", "error"], "completed", None, True, True, id="answer-and-failure"),
        pytest.param(["ok", "not_configured"], "completed", None, True, True, id="answer-and-gap"),
        pytest.param(["no_data"], "completed", None, False, True, id="no-data"),
        pytest.param(
            ["no_data", "rate_limited"], "completed", None, False, True, id="no-data+limit"
        ),
        pytest.param(["rate_limited"], "failed", "rate_limited", False, True, id="rate-limited"),
        pytest.param(
            ["rate_limited", "error"], "failed", "rate_limited", False, True, id="limit>error"
        ),
        pytest.param(["error"], "failed", "provider_error", False, True, id="error"),
        pytest.param(
            ["error", "not_configured"], "failed", "provider_error", False, True, id="error+gap"
        ),
        pytest.param(
            ["not_configured"], "unavailable", "no_provider_available", False, False, id="no-key"
        ),
        pytest.param(
            ["unsupported", "not_configured"],
            "unavailable",
            "no_provider_available",
            False,
            False,
            id="unsupported",
        ),
        pytest.param(
            ["not_queried"], "unavailable", "no_provider_available", False, False, id="not-queried"
        ),
        pytest.param([], "unavailable", "no_provider_available", False, False, id="no-providers"),
        pytest.param(["ok:cached"], "completed", None, True, False, id="cached-answer"),
        pytest.param(
            ["ok:cached", "no_data"], "completed", None, True, True, id="cached+fresh-lookup"
        ),
    ],
)
def test_the_providers_outcomes_decide_the_status_that_is_recorded(
    new_worker: Callable[..., EnrichmentWorker],
    views_: list[str],
    status: str,
    error_code: str | None,
    assessed: bool,
    contacted: bool,
) -> None:
    built = []
    for index, spec in enumerate(views_):
        name, _, cached = spec.partition(":")
        built.append(provider_view(f"provider{index}", name, cached=bool(cached)))
    answer_ = reply(*built, score=77, classification="high")
    answer_.providers = built
    worker = new_worker(StubIntel(default=answer_))

    summary, was_contacted = worker.lookup(SCANNER)

    assert summary["status"] == status
    assert summary.get("error_code") == error_code
    assert summary["assessed"] is assessed
    assert was_contacted is contacted
    if status == "completed":
        # A score with no evidence behind it ("no data" is not "safe") is not kept at all:
        # ``assessed`` is the only thing the summary says about such an answer.
        if assessed:
            assert (summary["risk_score"], summary["classification"]) == (77, "high")
        else:
            assert "risk_score" not in summary
            assert "classification" not in summary
    else:
        assert "risk_score" not in summary
        assert "classification" not in summary
    assert ("error_code" in summary) is (error_code is not None)


def test_the_summary_keeps_what_the_alert_view_needs_and_nothing_else(
    new_worker: Callable[..., EnrichmentWorker],
) -> None:
    indicator_id = uuid.uuid4()
    stub = StubIntel(
        default=reply(
            provider_view("abuseipdb", "ok", verdict="malicious", display_name="AbuseIPDB"),
            provider_view("otx", "no_data", verdict=None, display_name="AlienVault OTX"),
            score=64,
            classification="high",
            indicator_id=indicator_id,
        )
    )

    summary, _ = new_worker(stub).lookup(SCANNER)

    completed_at = datetime.fromisoformat(summary.pop("completed_at"))
    assert completed_at.tzinfo is not None
    assert (datetime.now(UTC) - completed_at).total_seconds() < 60
    assert summary == {
        "status": "completed",
        "address": SCANNER,
        "indicator_id": str(indicator_id),
        "providers": [
            {
                "provider": "abuseipdb",
                "display_name": "AbuseIPDB",
                "status": "ok",
                "verdict": "malicious",
            },
            {
                "provider": "otx",
                "display_name": "AlienVault OTX",
                "status": "no_data",
                "verdict": None,
            },
        ],
        "assessed": True,
        "risk_score": 64,
        "classification": "high",
    }
    json.dumps(summary)


@pytest.mark.parametrize(
    ("failure", "expected", "contacted"),
    [
        pytest.param(
            InvalidIndicatorError("The value is not a valid indicator."),
            {"status": "not_applicable"},
            False,
            id="invalid-indicator",
        ),
        pytest.param(
            IndicatorDeletedError(),
            {"status": "unavailable", "error_code": "indicator_deleted"},
            False,
            id="indicator-deleted",
        ),
        pytest.param(
            RuntimeError("provider said 203.0.113.9 and sk-secret-token"),
            {"status": "failed", "error_code": "lookup_failed"},
            True,
            id="crash",
        ),
        pytest.param(
            OperationalError("SELECT 1", {}, Exception("password=hunter2")),
            {"status": "failed", "error_code": "lookup_failed"},
            True,
            id="database",
        ),
        pytest.param(
            TimeoutError("slow"),
            {"status": "failed", "error_code": "lookup_failed"},
            True,
            id="timeout",
        ),
    ],
)
def test_a_failed_lookup_is_recorded_without_its_details(
    new_worker: Callable[..., EnrichmentWorker],
    caplog: pytest.LogCaptureFixture,
    failure: Exception,
    expected: dict[str, str],
    contacted: bool,
) -> None:
    worker = new_worker(StubIntel({SCANNER: failure}))

    with caplog.at_level(logging.DEBUG):
        summary, was_contacted = worker.lookup(SCANNER)

    assert summary == {"address": SCANNER, **expected}
    assert was_contacted is contacted
    logged = caplog.text + json.dumps([record.__dict__.get("error") for record in caplog.records])
    assert "secret" not in logged
    assert "hunter2" not in logged


# --- The worker thread ------------------------------------------------------------------------


def test_the_worker_starts_on_first_use_and_leaves_no_thread_behind(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker(StubIntel())
    session_id = running_session(factory)
    assert worker.running is False

    assert worker.submit(session_id, []) == []
    assert worker.running is False

    assert worker.submit(session_id, [request(SCANNER)]) == []
    assert worker.running is True
    assert [thread.name for thread in module_threads()] == ["cipherforge-network-enrichment"]
    drain(worker)

    worker.stop()
    assert worker.running is False
    assert module_threads() == []
    worker.stop()


def test_a_submitted_address_is_recorded_on_the_session_and_its_alerts(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=42, classification="medium")})
    worker = make_worker(stub)
    session_id = running_session(factory, stats={"protocols": [{"protocol": "tcp"}]})
    waiting = seed_alert(factory, session_id, src=SCANNER, enrichment=pending_for(SCANNER))
    other = seed_alert(
        factory, session_id, rule_id="NET-002", src=HOST, enrichment=not_applicable(HOST)
    )

    assert worker.submit(session_id, [request(SCANNER)]) == []
    drain(worker)

    stats = stored_stats(factory, session_id)
    recorded = stats["enrichment"][SCANNER]
    assert (recorded["status"], recorded["risk_score"], recorded["classification"]) == (
        "completed",
        42,
        "medium",
    )
    assert alert_state(factory, waiting) == recorded
    assert alert_state(factory, other) == not_applicable(HOST)
    assert stats["protocols"] == [{"protocol": "tcp"}]
    assert stub.calls == [SCANNER]
    assert stub.contexts == [RequestContext(actor=SYSTEM_ACTOR)]


def test_addresses_that_are_part_of_an_alert_are_looked_up_before_talkers(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = gated(StubIntel())
    worker = make_worker(stub)
    session_id = running_session(factory)
    worker.submit(session_id, [request(PUBLIC[0], priority=PRIORITY_TALKER)])
    assert stub.entered.wait(5)  # the worker is inside its first lookup

    worker.submit(
        session_id,
        [
            request(PUBLIC[1], priority=PRIORITY_TALKER),
            request(PUBLIC[2], priority=PRIORITY_ALERT),
            request(PUBLIC[3], priority=PRIORITY_TALKER),
            request(PUBLIC[4], priority=PRIORITY_ALERT),
        ],
    )
    stub.gate.set()
    drain(worker)

    assert stub.calls == [PUBLIC[0], PUBLIC[2], PUBLIC[4], PUBLIC[1], PUBLIC[3]]


def test_an_address_is_queued_once_per_session_but_once_for_each_session(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = gated(StubIntel())
    worker = make_worker(stub)
    first, second = running_session(factory), running_session(factory)
    worker.submit(first, [request(PUBLIC[0])])
    assert stub.entered.wait(5)

    assert worker.submit(first, [request(PUBLIC[1]), request(PUBLIC[1])]) == []
    assert worker.submit(first, [request(PUBLIC[1])]) == []
    assert worker.submit(second, [request(PUBLIC[1])]) == []

    assert worker.pending_count() == 3
    assert worker.is_pending(first, PUBLIC[1]) and worker.is_pending(second, PUBLIC[1])
    assert not worker.is_pending(second, PUBLIC[0])
    stub.gate.set()
    drain(worker)

    assert stub.calls == [PUBLIC[0], PUBLIC[1], PUBLIC[1]]
    assert answer_for(factory, first, PUBLIC[1]) is not None
    assert answer_for(factory, second, PUBLIC[1]) is not None
    assert worker.pending_count() == 0
    assert not worker.is_pending(first, PUBLIC[1])


def test_lookups_that_reach_a_provider_are_spaced_out(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel()
    worker = make_worker(stub, pacing=0.15)
    session_id = running_session(factory)

    worker.submit(session_id, [request(address) for address in PUBLIC[:3]])
    drain(worker)

    gaps = [later - earlier for earlier, later in zip(stub.times, stub.times[1:], strict=False)]
    assert len(gaps) == 2
    # Windows' monotonic clock ticks every 15.6 ms.
    assert min(gaps) >= 0.15 - 0.03


def test_answers_that_cost_nothing_are_not_delayed(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    cached = reply(provider_view(cached=True), score=5)
    stub = StubIntel(default=cached)
    worker = make_worker(stub, pacing=60.0)  # a paced lookup would take a minute
    session_id = running_session(factory)

    worker.submit(session_id, [request(address) for address in [*PUBLIC[:4], HOST, SERVER]])
    drain(worker)

    assert stub.calls == PUBLIC[:4]
    assert answer_for(factory, session_id, HOST)["status"] == "not_applicable"


def test_stopping_does_not_wait_out_the_pacing_interval(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel()
    worker = make_worker(stub, pacing=None)  # four lookups a minute: 15 s between them
    session_id = running_session(factory)
    worker.submit(session_id, [request(PUBLIC[0]), request(PUBLIC[1])])
    wait_until(lambda: answer_for(factory, session_id, PUBLIC[0]), what="the first answer")
    time.sleep(0.2)
    assert stub.calls == [PUBLIC[0]]  # the second lookup is waiting for its turn

    started = time.monotonic()
    worker.stop()

    assert time.monotonic() - started < 3
    assert worker.running is False
    assert stub.calls == [PUBLIC[0]]
    assert answer_for(factory, session_id, PUBLIC[1]) is None


def test_a_full_queue_hands_back_what_it_could_not_take(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = gated(StubIntel())
    worker = make_worker(stub, queue_size=2)
    session_id = running_session(factory)
    worker.submit(session_id, [request(PUBLIC[0])])
    assert stub.entered.wait(5)
    batch = [request(address) for address in PUBLIC[1:6]]

    rejected = worker.submit(session_id, batch)

    assert rejected == batch[2:]
    assert [worker.is_pending(session_id, item.address) for item in batch] == [
        True,
        True,
        False,
        False,
        False,
    ]
    stub.gate.set()
    drain(worker)
    assert stub.calls == PUBLIC[:3]
    # Nothing was left marked as queued, so the same addresses can be offered again.
    for item in rejected:
        assert worker.submit(session_id, [item]) == []
        drain(worker)
    assert stub.calls == PUBLIC[:6]


def test_nothing_is_queued_once_the_worker_is_stopped(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel()
    worker = make_worker(stub)
    session_id = running_session(factory)
    worker.stop()
    batch = [request(PUBLIC[0]), request(PUBLIC[1])]

    assert worker.submit(session_id, batch) == batch

    assert worker.running is False
    assert worker.pending_count() == 0
    assert stub.calls == []


def test_a_deleted_sessions_queued_lookups_are_dropped_and_only_its_own(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = gated(StubIntel())
    worker = make_worker(stub)
    doomed, other = running_session(factory), running_session(factory)
    worker.discard(other)  # nothing is queued for it: this must not mark it
    worker.submit(doomed, [request(PUBLIC[0])])
    assert stub.entered.wait(5)
    worker.submit(doomed, [request(PUBLIC[1]), request(PUBLIC[2])])
    worker.submit(other, [request(PUBLIC[3])])

    worker.discard(doomed)
    stub.gate.set()
    drain(worker)

    assert stub.calls == [PUBLIC[0], PUBLIC[3]]
    # The mark goes away with the queue: a session id that comes back is served normally.
    worker.submit(doomed, [request(PUBLIC[4])])
    worker.submit(other, [request(PUBLIC[5])])
    drain(worker)
    assert stub.calls == [PUBLIC[0], PUBLIC[3], PUBLIC[4], PUBLIC[5]]


def test_a_failing_lookup_does_not_end_the_worker(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel({PUBLIC[0]: RuntimeError("the provider exploded")})
    worker = make_worker(stub)
    session_id = running_session(factory)

    worker.submit(session_id, [request(PUBLIC[0]), request(PUBLIC[1])])
    drain(worker)

    answers = stored_stats(factory, session_id)["enrichment"]
    assert answers[PUBLIC[0]] == {
        "status": "failed",
        "address": PUBLIC[0],
        "error_code": "lookup_failed",
    }
    assert answers[PUBLIC[1]]["status"] == "completed"
    assert worker.running is True


def test_an_unexpected_error_while_recording_does_not_end_the_worker(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    class Unreachable:
        """A session factory that raises something that is not a database error."""

        def __init__(self, failures: int) -> None:
            self.failures = failures

        def __call__(self) -> Session:
            if self.failures > 0:
                self.failures -= 1
                raise RuntimeError("the pool exploded")
            return factory()

    stub = StubIntel()
    worker = make_worker(stub, session_factory=Unreachable(2))
    session_id = running_session(factory)

    worker.submit(session_id, [request(PUBLIC[0]), request(PUBLIC[1])])
    drain(worker)

    assert answer_for(factory, session_id, PUBLIC[1])["status"] == "completed"
    assert worker.running is True


def test_several_threads_may_submit_at_once(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel()
    worker = make_worker(stub)
    sessions = [running_session(factory) for _ in range(3)]
    errors: list[BaseException] = []

    def submit(session_id: uuid.UUID, index: int) -> None:
        try:
            for step in range(15):
                worker.submit(session_id, [request(f"{60 + index}.0.0.{step}")])
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=submit, args=(session_id, index), name=f"test-submit-{index}")
        for index, session_id in enumerate(sessions)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    drain(worker)

    assert errors == []
    assert sorted(stub.calls) == sorted(f"{60 + i}.0.0.{s}" for i in range(3) for s in range(15))
    for index, session_id in enumerate(sessions):
        assert len(stored_stats(factory, session_id)["enrichment"]) == 15, index


# --- Recording an answer ----------------------------------------------------------------------


def test_apply_updates_the_session_and_only_the_alerts_that_wait_for_that_address(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    earlier = {"status": "completed", "address": RESOLVER, "risk_score": 3}
    session_id = running_session(
        factory, stats={"protocols": [{"protocol": "udp"}], "enrichment": {RESOLVER: earlier}}
    )
    scan = seed_alert(factory, session_id, src=SCANNER, enrichment=pending_for(SCANNER))
    rate = seed_alert(
        factory, session_id, rule_id="NET-002", src=SCANNER, enrichment=pending_for(SCANNER)
    )
    other = seed_alert(factory, session_id, src=RESOLVER, enrichment=earlier)
    # The same address, but the alert was never meant to carry an answer.
    bare = seed_alert(factory, session_id, rule_id="NET-003", src=SCANNER, enrichment={})
    summary = completed_summary(score=20, classification="low")

    worker.apply(session_id, SCANNER, summary, facts=facts_for(SCANNER))

    stats = stored_stats(factory, session_id)
    assert stats["enrichment"] == {RESOLVER: earlier, SCANNER: summary}
    assert stats["protocols"] == [{"protocol": "udp"}]
    assert alert_state(factory, scan) == summary
    assert alert_state(factory, rate) == summary
    assert alert_state(factory, other) == earlier
    assert alert_state(factory, bare) == {}
    assert stored_total(factory, session_id) == 0


def test_apply_for_a_session_that_is_gone_does_nothing(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id = running_session(factory)
    alert = seed_alert(factory, session_id, enrichment=pending_for(SCANNER))
    missing = uuid.uuid4()

    worker.apply(missing, SCANNER, completed_summary(score=99), facts=facts_for(SCANNER))

    assert alert_state(factory, alert) == pending_for(SCANNER)
    assert known_malicious(factory, missing) == []


def test_a_database_failure_while_recording_is_swallowed_and_loses_nothing_else(
    factory: SessionFactory, new_worker: Callable[..., EnrichmentWorker]
) -> None:
    flaky = FlakyFactory(factory, failures=1)
    worker = new_worker(StubIntel(), session_factory=flaky)
    session_id = running_session(factory)
    alert = seed_alert(factory, session_id, enrichment=pending_for(SCANNER))
    summary = completed_summary(score=99)

    worker.apply(session_id, SCANNER, summary, facts=facts_for(SCANNER))

    assert answer_for(factory, session_id, SCANNER) is None
    assert alert_state(factory, alert) == pending_for(SCANNER)
    assert known_malicious(factory, session_id) == []
    assert stored_total(factory, session_id) == 0
    assert "enrichment_alerts" not in stored_stats(factory, session_id)
    # The lock was released: the next answer is recorded.
    worker.apply(session_id, SCANNER, summary, facts=facts_for(SCANNER))
    assert answer_for(factory, session_id, SCANNER) == summary
    assert len(known_malicious(factory, session_id)) == 1
    assert stored_stats(factory, session_id)["enrichment_alerts"] == {"NET-005": 1}


def test_recording_waits_for_the_stats_lock_the_recorder_shares(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    lock = threading.Lock()
    worker = make_worker(lock=lock)
    session_id = running_session(factory)
    done = threading.Event()

    def record() -> None:
        worker.apply(session_id, SCANNER, completed_summary(score=1), facts=None)
        done.set()

    thread = threading.Thread(target=record, name="test-apply")
    with lock:
        thread.start()
        assert not done.wait(0.2)
        assert stored_stats(factory, session_id) == {}
    assert done.wait(5)
    thread.join(5)
    assert answer_for(factory, session_id, SCANNER) is not None


# --- NET-005 ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("summary", "raised"),
    [
        pytest.param(completed_summary(score=61), True, id="at-the-minimum"),
        pytest.param(completed_summary(score=100, classification="critical"), True, id="top"),
        pytest.param(completed_summary(score=60), False, id="just-below"),
        pytest.param(completed_summary(score=0), False, id="clean"),
        pytest.param(
            completed_summary(score=100, statuses=("no_data",)), False, id="nothing-assessed"
        ),
        pytest.param({**completed_summary(score=95), "status": "failed"}, False, id="failed"),
        pytest.param({**completed_summary(score=95), "risk_score": 95.0}, False, id="float-score"),
        pytest.param(
            {k: v for k, v in completed_summary(score=95).items() if k != "risk_score"},
            False,
            id="no-score",
        ),
        pytest.param({"status": "disabled", "address": SCANNER}, False, id="disabled"),
    ],
)
def test_an_assessed_score_at_the_minimum_raises_the_known_malicious_alert(
    make_worker: Callable[..., EnrichmentWorker],
    factory: SessionFactory,
    summary: dict[str, Any],
    raised: bool,
) -> None:
    worker = make_worker()
    session_id = running_session(factory)

    worker.apply(session_id, SCANNER, summary, facts=facts_for(SCANNER))

    assert len(known_malicious(factory, session_id)) == int(raised)
    assert stored_total(factory, session_id) == int(raised)
    assert answer_for(factory, session_id, SCANNER) == summary
    assert stored_stats(factory, session_id).get("enrichment_alerts") == (
        {"NET-005": 1} if raised else None
    )


def test_the_minimum_score_comes_from_the_settings(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker(known_malicious_min_score=40)
    session_id = running_session(factory)

    worker.apply(session_id, SCANNER, completed_summary(score=39), facts=facts_for(SCANNER))
    assert known_malicious(factory, session_id) == []
    worker.apply(session_id, RESOLVER, completed_summary(RESOLVER, score=40), facts=None)
    assert known_malicious(factory, session_id) == []  # no traffic details to explain it with
    worker.apply(session_id, SCANNER, completed_summary(score=40), facts=facts_for(SCANNER))

    (row,) = known_malicious(factory, session_id)
    assert (row.observed_value, row.threshold) == (40, 40)


@pytest.mark.parametrize(
    ("classification", "severity"),
    [("critical", "critical"), ("high", "high"), ("medium", "high"), ("low", "high")],
)
def test_the_known_malicious_alert_is_critical_only_for_a_critical_address(
    make_worker: Callable[..., EnrichmentWorker],
    factory: SessionFactory,
    classification: str,
    severity: str,
) -> None:
    worker = make_worker(known_malicious_min_score=1)
    session_id = running_session(factory)

    worker.apply(
        session_id,
        SCANNER,
        completed_summary(score=90, classification=classification),
        facts=facts_for(SCANNER),
    )

    (row,) = known_malicious(factory, session_id)
    assert row.severity == severity


def test_the_known_malicious_alert_describes_the_address_and_the_traffic(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id = running_session(factory, alerts=2)
    summary = completed_summary(score=88, classification="critical")
    sent_to = facts_for(SCANNER)
    received_from = facts_for(
        RESOLVER,
        sent_to=False,
        peers=[SERVER, HOST],
        ports=[22, 80],
        protocols=["udp", "tcp"],
        packets=40,
        bytes=5000,
    )

    worker.apply(session_id, SCANNER, summary, facts=sent_to)
    worker.apply(session_id, RESOLVER, {**summary, "address": RESOLVER}, facts=received_from)

    out, back = known_malicious(factory, session_id)
    by_address = {row.evidence["address"]: row for row in (out, back)}
    sent, received = by_address[SCANNER], by_address[RESOLVER]
    # Monitored hosts sent traffic to the address: the host is the source.
    assert (sent.src_ip, sent.dst_ip, sent.dst_port, sent.protocol) == (HOST, SCANNER, 443, "tcp")
    # They only received traffic from it: the address is the source.
    assert (received.src_ip, received.dst_ip, received.dst_port) == (RESOLVER, SERVER, None)
    assert received.protocol == "udp"
    for row in (sent, received):
        assert (row.rule_id, row.rule_name, row.severity) == (
            "NET-005",
            "known_malicious_ip",
            "critical",
        )
        assert (row.observed_value, row.threshold, row.window_seconds) == (88, 61, None)
        assert row.evidence["risk_score"] == 88
        assert row.evidence["classification"] == "critical"
        assert [item["status"] for item in row.evidence["providers"]] == ["ok"]
        assert row.evidence["address"] in row.explanation
        assert "88/100" in row.explanation
        assert row.first_observed == datetime.fromtimestamp(T0, tz=UTC)
        assert row.last_observed == datetime.fromtimestamp(T0 + 30, tz=UTC)
        assert row.enrichment["status"] == "completed"
    assert received.evidence["peers"] == [SERVER, HOST]
    assert received.evidence["ports"] == [22, 80]
    assert received.evidence["protocols"] == ["udp", "tcp"]
    assert (received.evidence["packets"], received.evidence["bytes"]) == (40, 5000)
    assert stored_total(factory, session_id) == 4


def test_the_known_malicious_alert_is_raised_once_for_each_address(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id = running_session(factory)
    summary = completed_summary(score=90)

    for _ in range(3):
        worker.apply(session_id, SCANNER, summary, facts=facts_for(SCANNER))
    assert len(known_malicious(factory, session_id)) == 1
    assert stored_total(factory, session_id) == 1
    assert stored_stats(factory, session_id)["enrichment_alerts"] == {"NET-005": 1}

    worker.apply(
        session_id, RESOLVER, completed_summary(RESOLVER, score=90), facts=facts_for(RESOLVER)
    )
    assert sorted(row.evidence["address"] for row in known_malicious(factory, session_id)) == [
        SCANNER,
        RESOLVER,
    ]
    assert stored_total(factory, session_id) == 2
    assert stored_stats(factory, session_id)["enrichment_alerts"] == {"NET-005": 2}

    # Another session that saw the same address is a separate story.
    other = running_session(factory)
    worker.apply(other, SCANNER, summary, facts=facts_for(SCANNER))
    assert len(known_malicious(factory, other)) == 1
    assert len(known_malicious(factory, session_id)) == 2
    assert stored_stats(factory, other)["enrichment_alerts"] == {"NET-005": 1}
    assert stored_stats(factory, session_id)["enrichment_alerts"] == {"NET-005": 2}


def test_traffic_details_come_from_the_stored_peer_list_when_none_are_given(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    stored_facts = facts_for(SCANNER, peers=[SERVER], ports=[8080])
    session_id = running_session(factory, stats={"external_peers": [stored_facts, "damaged"]})
    unknown = running_session(factory, stats={"external_peers": [facts_for(RESOLVER)]})
    summary = completed_summary(score=90)

    worker.apply(session_id, SCANNER, summary, facts=None)
    worker.apply(unknown, SCANNER, summary, facts=None)

    (row,) = known_malicious(factory, session_id)
    assert row.evidence["peers"] == [SERVER]
    assert row.dst_port == 8080
    # Without anything known about the traffic the answer is kept, but no alert can be raised.
    assert known_malicious(factory, unknown) == []
    assert answer_for(factory, unknown, SCANNER) == summary
    assert stored_total(factory, unknown) == 0
    assert "enrichment_alerts" not in stored_stats(factory, unknown)


def test_the_alert_that_asked_for_an_address_and_the_new_one_both_carry_the_answer(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id = running_session(factory, alerts=1)
    scan = seed_alert(factory, session_id, src=SCANNER, enrichment=pending_for(SCANNER))
    summary = completed_summary(score=90)

    worker.apply(session_id, SCANNER, summary, facts=facts_for(SCANNER))

    (row,) = known_malicious(factory, session_id)
    assert alert_state(factory, scan) == summary
    assert row.enrichment == summary
    assert stored_total(factory, session_id) == 2


# --- Marking alerts that will not be looked up -------------------------------------------------


def test_mark_changes_only_waiting_alerts_of_that_session_for_those_addresses(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id, other_session = running_session(factory), running_session(factory)
    first = seed_alert(factory, session_id, src=SCANNER, enrichment=pending_for(SCANNER))
    second = seed_alert(
        factory, session_id, rule_id="NET-002", src=SCANNER, enrichment=pending_for(SCANNER)
    )
    different = seed_alert(factory, session_id, src=RESOLVER, enrichment=pending_for(RESOLVER))
    answered = {"status": "completed", "address": SCANNER, "risk_score": 5}
    done = seed_alert(factory, session_id, rule_id="NET-003", src=SCANNER, enrichment=answered)
    private = seed_alert(
        factory, session_id, rule_id="NET-004", src=HOST, enrichment=not_applicable(HOST)
    )
    foreign = seed_alert(factory, other_session, src=SCANNER, enrichment=pending_for(SCANNER))

    changed = worker.mark(session_id, {SCANNER}, EnrichmentStatus.FAILED, error_code="queue_full")

    assert changed == 2
    expected = {"status": "failed", "address": SCANNER, "error_code": "queue_full"}
    assert alert_state(factory, first) == expected
    assert alert_state(factory, second) == expected
    assert alert_state(factory, different) == pending_for(RESOLVER)
    assert alert_state(factory, done) == answered
    assert alert_state(factory, private) == not_applicable(HOST)
    assert alert_state(factory, foreign) == pending_for(SCANNER)
    assert worker.mark(session_id, {SCANNER}, EnrichmentStatus.SKIPPED_BUDGET) == 0
    parsed = views.parse_enrichment(alert_state(factory, first))
    assert (parsed.status, parsed.error_code) == ("failed", "queue_full")
    assert parsed.message == views.ENRICHMENT_MESSAGES["queue_full"]


def test_mark_without_a_code_records_the_status_alone(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id = running_session(factory)
    alert = seed_alert(factory, session_id, enrichment=pending_for(SCANNER))

    assert worker.mark(session_id, [SCANNER], EnrichmentStatus.SKIPPED_BUDGET) == 1

    assert alert_state(factory, alert) == {"status": "skipped_budget", "address": SCANNER}
    assert views.parse_enrichment(alert_state(factory, alert)).status == "skipped_budget"


def test_settle_gives_up_on_waiting_alerts_that_nobody_queued(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    worker = make_worker()
    session_id, other_session = running_session(factory), running_session(factory)
    queued = seed_alert(factory, session_id, src=RESOLVER, enrichment=pending_for(RESOLVER))
    forgotten = seed_alert(factory, session_id, src=SCANNER, enrichment=pending_for(SCANNER))
    third = seed_alert(
        factory, session_id, rule_id="NET-002", src=PUBLIC[0], enrichment=pending_for(PUBLIC[0])
    )
    answered = {"status": "completed", "address": PUBLIC[1]}
    done = seed_alert(factory, session_id, rule_id="NET-003", src=PUBLIC[1], enrichment=answered)
    foreign = seed_alert(factory, other_session, src=SCANNER, enrichment=pending_for(SCANNER))

    assert worker.settle(session_id, {RESOLVER}) == 2

    assert alert_state(factory, queued) == pending_for(RESOLVER)
    skipped = {"status": "skipped_budget", "address": SCANNER}
    assert alert_state(factory, forgotten) == skipped
    assert alert_state(factory, third) == {"status": "skipped_budget", "address": PUBLIC[0]}
    assert alert_state(factory, done) == answered
    assert alert_state(factory, foreign) == pending_for(SCANNER)


def test_mark_and_settle_report_nothing_changed_when_the_database_fails(
    factory: SessionFactory, new_worker: Callable[..., EnrichmentWorker]
) -> None:
    flaky = FlakyFactory(factory, failures=2)
    worker = new_worker(session_factory=flaky)
    session_id = running_session(factory)
    alert = seed_alert(factory, session_id, enrichment=pending_for(SCANNER))

    assert worker.mark(session_id, {SCANNER}, EnrichmentStatus.SKIPPED_BUDGET) == 0
    assert worker.settle(session_id, set()) == 0

    assert alert_state(factory, alert) == pending_for(SCANNER)
    assert worker.settle(session_id, set()) == 1


# --- A lookup on request ----------------------------------------------------------------------


def test_refresh_looks_up_as_the_caller_and_records_the_answer_at_once(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=30, classification="low")})
    worker = make_worker(stub, pacing=60.0)  # a request from a person is never queued behind this
    session_id = running_session(factory)
    alert = seed_alert(
        factory, session_id, src=SCANNER, enrichment={"status": "failed", "address": SCANNER}
    )

    summary = worker.refresh(session_id, SCANNER, ANALYST)

    assert summary["status"] == "completed"
    assert stub.contexts == [ANALYST]
    assert stub.refresh_flags == [False]
    assert answer_for(factory, session_id, SCANNER) == summary
    assert alert_state(factory, alert) == summary
    assert worker.running is False
    assert known_malicious(factory, session_id) == []


def test_refresh_raises_the_known_malicious_alert_from_the_stored_traffic_details(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=95, classification="critical")})
    worker = make_worker(stub)
    session_id = running_session(factory, stats={"external_peers": [facts_for(SCANNER)]})
    seed_alert(
        factory, session_id, src=SCANNER, enrichment={"status": "failed", "address": SCANNER}
    )

    worker.refresh(session_id, SCANNER, ANALYST)
    worker.refresh(session_id, SCANNER, ANALYST)

    (row,) = known_malicious(factory, session_id)
    assert row.severity == "critical"
    assert stored_total(factory, session_id) == 1
    assert stub.calls == [SCANNER, SCANNER]


@pytest.mark.parametrize(
    ("address", "settings", "status"),
    [
        (HOST, {}, "not_applicable"),
        ("192.0.2.1", {}, "not_applicable"),
        (SCANNER, {"external_enrichment_enabled": False}, "disabled"),
    ],
)
def test_refresh_never_asks_about_what_it_must_not(
    make_worker: Callable[..., EnrichmentWorker],
    factory: SessionFactory,
    address: str,
    settings: dict[str, Any],
    status: str,
) -> None:
    stub = StubIntel()
    worker = make_worker(stub, **settings)
    session_id = running_session(factory)

    summary = worker.refresh(session_id, address, ANALYST)

    assert summary["status"] == status
    assert stub.calls == []


# --- What the rest of the module reads --------------------------------------------------------


def test_every_answer_the_worker_can_record_is_understood_by_the_views(
    new_worker: Callable[..., EnrichmentWorker],
) -> None:
    answers = {
        PUBLIC[0]: reply(provider_view("a", "ok"), score=70, classification="high"),
        PUBLIC[1]: reply(provider_view("a", "no_data"), score=0, classification="low"),
        PUBLIC[2]: reply(provider_view("a", "rate_limited")),
        PUBLIC[3]: reply(provider_view("a", "error")),
        PUBLIC[4]: reply(provider_view("a", "not_configured")),
        PUBLIC[5]: IndicatorDeletedError(),
        PUBLIC[6]: RuntimeError("boom"),
        PUBLIC[7]: InvalidIndicatorError("bad"),
    }
    worker = new_worker(StubIntel(answers))
    summaries = [worker.lookup(address)[0] for address in [*answers, HOST]]
    summaries.append(new_worker(external_enrichment_enabled=False).lookup(SCANNER)[0])

    for summary in summaries:
        parsed = views.parse_enrichment(summary)
        assert (parsed.status, parsed.address, parsed.error_code) == (
            summary["status"],
            summary["address"],
            summary.get("error_code"),
        ), summary
        assert parsed.risk_score == summary.get("risk_score")
        assert parsed.assessed == summary.get("assessed")
        if parsed.status != "completed":
            assert parsed.message, summary
    assert {s["status"] for s in summaries} == {
        "completed",
        "failed",
        "unavailable",
        "not_applicable",
        "disabled",
    }
    assert {s.get("error_code") for s in summaries} >= {
        "rate_limited",
        "provider_error",
        "no_provider_available",
        "lookup_failed",
        "indicator_deleted",
    }


def test_the_real_intel_service_answers_in_the_shape_the_worker_summarizes(
    make_worker: Callable[..., EnrichmentWorker], factory: SessionFactory
) -> None:
    clock = Clock()
    abuse = FakeAbuse([answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1))])
    with contextlib.closing(IntelService([abuse], clock=clock)) as intel:
        worker = make_worker(intel)
        first, first_contacted = worker.lookup(SCANNER)
        again, again_contacted = worker.lookup(SCANNER)
        with factory() as db:
            direct = intel.investigate(db, ANALYST, SCANNER)

    assert (first["status"], first["assessed"], first_contacted) == ("completed", True, True)
    assert first["providers"] == [
        {
            "provider": "abuseipdb",
            "display_name": "AbuseIPDB",
            "status": "ok",
            "verdict": getattr(direct.providers[0].verdict, "value", direct.providers[0].verdict),
        }
    ]
    assert first["indicator_id"] == str(direct.indicator.indicator_id)
    assert first["risk_score"] == direct.indicator.risk_score
    assert first["classification"] == getattr(
        direct.indicator.classification, "value", direct.indicator.classification
    )
    assert isinstance(first["risk_score"], int)
    assert 0 <= first["risk_score"] <= 100
    json.dumps(first)
    # The second answer came from the intelligence cache: no call to the provider, no pacing.
    assert (again["risk_score"], again_contacted) == (first["risk_score"], False)
    assert abuse.calls == [f"ipv4:{SCANNER}"]
    with factory() as db:
        audited = db.scalars(select(AuditLog).where(AuditLog.actor == SYSTEM_ACTOR)).all()
    assert [(row.action, row.target) for row in audited] == [(IOC_LOOKUP, f"ipv4:{SCANNER}")] * 2


# --- The monitor, the recorder and the worker together ----------------------------------------


@dataclass
class Pipeline:
    rig: MonitorRig
    worker: EnrichmentWorker
    stub: StubIntel

    def run(self, packets: Any = None, *, settle: bool = True) -> None:
        """Feed the packets, store the results, let the lookups finish, and end the session."""
        self.rig.monitor.process_batch(packets if packets is not None else scan_packets())
        self.rig.monitor.flush(force=True)
        if settle:
            drain(self.worker)
        self.rig.monitor.finish(CaptureStatus.COMPLETED)


@pytest.fixture
def make_pipeline(
    factory: SessionFactory,
    make_settings: Callable[..., Settings],
    db_url: str,
    new_worker: Callable[..., EnrichmentWorker],
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., Pipeline]:
    monkeypatch.setattr(monitor_module, "_FINAL_FLUSH_DELAY", 0.0)

    def build(stub: StubIntel | None = None, **overrides: Any) -> Pipeline:
        settings = make_settings(database_url=db_url, **overrides)
        lock = threading.Lock()
        stub = stub or StubIntel()
        worker = new_worker(stub, session_factory=factory, settings=settings, lock=lock)
        rig = build_rig(factory, settings, stream_time=True, worker=worker, stats_lock=lock)
        return Pipeline(rig, worker, stub)

    return build


def test_a_port_scan_alert_is_enriched_with_the_scanners_answer(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=35, classification="medium")})
    pipeline = make_pipeline(stub)

    pipeline.run()

    (alert,) = pipeline.rig.alerts()
    assert alert.rule_id == "NET-001"
    assert (alert.enrichment["status"], alert.enrichment["address"]) == ("completed", SCANNER)
    assert alert.enrichment["risk_score"] == 35
    stats = pipeline.rig.row().stats
    assert stats["enrichment"][SCANNER] == alert.enrichment
    # The scanned server is private: only the scanner was ever asked about.
    assert stub.calls == [SCANNER]
    assert pipeline.rig.row().alerts_total == 1


def test_a_known_malicious_address_raises_one_extra_alert(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=90, classification="critical")})
    pipeline = make_pipeline(stub)

    pipeline.run()
    pipeline.rig.monitor.flush(force=True)

    by_rule = {row.rule_id: row for row in pipeline.rig.alerts()}
    assert sorted(by_rule) == ["NET-001", "NET-005"]
    malicious = by_rule["NET-005"]
    assert malicious.severity == "critical"
    assert (malicious.src_ip, malicious.dst_ip) == (SCANNER, SERVER)
    assert malicious.evidence["address"] == SCANNER
    assert malicious.evidence["peers"] == [SERVER]
    assert pipeline.rig.row().alerts_total == 2
    assert pipeline.rig.row().stats["enrichment_alerts"] == {"NET-005": 1}
    assert counted_by_rule(pipeline.rig.factory, pipeline.rig.session_id) == {
        "NET-001": 1,
        "NET-005": 1,
    }
    assert stub.calls == [SCANNER]


def test_a_low_score_raises_no_known_malicious_alert(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=60, classification="high")})
    pipeline = make_pipeline(stub)

    pipeline.run()

    assert [row.rule_id for row in pipeline.rig.alerts()] == ["NET-001"]
    assert pipeline.rig.row().alerts_total == 1
    assert "enrichment_alerts" not in pipeline.rig.row().stats
    assert counted_by_rule(pipeline.rig.factory, pipeline.rig.session_id) == {"NET-001": 1}


def test_the_alerts_a_lookup_raised_stay_counted_through_the_recorders_later_flushes(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    stub = StubIntel({SCANNER: reply(provider_view(), score=90, classification="critical")})
    pipeline = make_pipeline(stub)
    monitor, factory = pipeline.rig.monitor, pipeline.rig.factory
    session_id = pipeline.rig.session_id
    monitor.process_batch(scan_packets())
    monitor.flush(force=True)
    drain(pipeline.worker)

    assert pipeline.rig.row().alerts_total == 2
    assert counted_by_rule(factory, session_id) == {"NET-001": 1, "NET-005": 1}

    # The recorder rewrites its statistics with every flush; the lookup's count must outlive that.
    monitor.process_batch(scan_packets(src="10.0.0.77", start=T0 + 120))
    monitor.flush(force=True)
    monitor.finish(CaptureStatus.COMPLETED)

    row = pipeline.rig.row()
    assert row.alerts_total == len(pipeline.rig.alerts()) == 3
    assert row.stats["alerts_by_rule"] == {"NET-001": 2}  # what the monitor itself raised
    assert row.stats["enrichment_alerts"] == {"NET-005": 1}
    shown = counted_by_rule(factory, session_id)
    assert shown == {"NET-001": 2, "NET-005": 1}
    assert sum(shown.values()) == row.alerts_total


def test_traffic_between_private_hosts_never_reaches_a_provider(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    pipeline = make_pipeline()

    pipeline.run(scan_packets(src="10.0.0.77", dst=SERVER))

    (alert,) = pipeline.rig.alerts()
    assert alert.enrichment == {"status": "not_applicable"}
    assert pipeline.stub.calls == []
    assert pipeline.worker.running is False
    assert not pipeline.rig.row().stats.get("enrichment")


def test_alerts_are_not_looked_up_while_enrichment_is_off(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    pipeline = make_pipeline(external_enrichment_enabled=False)

    pipeline.run()

    (alert,) = pipeline.rig.alerts()
    assert (alert.enrichment["status"], alert.enrichment.get("address")) == ("disabled", SCANNER)
    assert pipeline.stub.calls == []
    assert pipeline.worker.running is False


def test_addresses_beyond_the_lookup_budget_are_marked_in_their_alerts(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    pipeline = make_pipeline(network_enrichment_max_ips=1)
    second_scanner = "45.33.32.157"
    packets = [
        *scan_packets(),
        *scan_packets(src=second_scanner, start=T0 + 0.05),
    ]
    packets.sort(key=lambda item: item.timestamp)

    pipeline.run(packets)

    states = {row.src_ip: row.enrichment for row in pipeline.rig.alerts()}
    assert sorted(states) == [SCANNER, second_scanner]
    assert states[SCANNER]["status"] == "completed"
    assert states[second_scanner] == {"status": "skipped_budget", "address": second_scanner}
    assert pipeline.stub.calls == [SCANNER]


def test_a_session_that_ends_with_lookups_queued_leaves_them_pending_until_answered(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    stub = gated(StubIntel({SCANNER: reply(provider_view(), score=20)}))
    pipeline = make_pipeline(stub)

    pipeline.run(settle=False)

    assert stub.entered.wait(5)
    (alert,) = pipeline.rig.alerts()
    assert pipeline.rig.row().status == "completed"
    assert alert.enrichment == pending_for(SCANNER)
    stub.gate.set()
    drain(pipeline.worker)
    (alert,) = pipeline.rig.alerts()
    assert (alert.enrichment["status"], alert.enrichment["risk_score"]) == ("completed", 20)


def start_feeding(monitor: Any, errors: list[BaseException]) -> threading.Thread:
    """Store 25 seconds of quiet traffic, one flush a second, from a thread of its own."""

    def feed() -> None:
        try:
            for index in range(25):
                monitor.process_batch(
                    [
                        packet(
                            T0 + index,
                            HOST,
                            SERVER,
                            protocol="udp",
                            sport=40000 + index,
                            dport=9,
                            length=100,
                        )
                    ]
                )
                monitor.flush(force=True)
        except BaseException as exc:
            errors.append(exc)

    feeder = threading.Thread(target=feed, name="test-feeder")
    feeder.start()
    return feeder


def test_answers_and_stored_results_never_overwrite_each_other(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    pipeline = make_pipeline()
    errors: list[BaseException] = []

    feeder = start_feeding(pipeline.rig.monitor, errors)
    for address in PUBLIC:
        pipeline.worker.refresh(pipeline.rig.session_id, address, ANALYST)
    feeder.join(30)

    assert errors == []
    assert not feeder.is_alive()
    row = pipeline.rig.row()
    assert sorted(row.stats["enrichment"]) == sorted(PUBLIC)
    assert row.packets_total == 25


def test_every_alert_a_lookup_raises_is_counted_while_the_recorder_stores_the_session(
    make_pipeline: Callable[..., Pipeline],
) -> None:
    pipeline = make_pipeline()
    session_id = pipeline.rig.session_id
    errors: list[BaseException] = []

    feeder = start_feeding(pipeline.rig.monitor, errors)
    for address in PUBLIC:
        summary = completed_summary(address, score=90)
        pipeline.worker.apply(session_id, address, summary, facts=facts_for(address))
    feeder.join(30)

    assert errors == []
    assert not feeder.is_alive()
    factory = pipeline.rig.factory
    row = pipeline.rig.row()
    assert row.packets_total == 25
    assert row.alerts_total == len(known_malicious(factory, session_id)) == len(PUBLIC)
    assert row.stats["enrichment_alerts"] == {"NET-005": len(PUBLIC)}
    assert sorted(row.stats["enrichment"]) == sorted(PUBLIC)
    assert counted_by_rule(factory, session_id) == {"NET-005": len(PUBLIC)}

"""One investigation across all four real provider adapters, wired to canned HTTP exchanges.

The adapters, the registry, the service and a migrated database are real; only the network is
canned, so nothing here needs an API key or spends a provider quota.
"""

import json
import threading
from collections.abc import Callable, Iterator
from typing import Any

import httpx2
import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import ProviderFailure, ProviderStatus, Reason
from app.collectors.registry import build_collectors
from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models.audit import AuditLog
from app.models.threat import ThreatObservation
from app.schemas.intel import InvestigationResponse, ProviderView
from app.services import intel_service
from app.services.intel_service import IntelService, RequestContext
from tests.intel_helpers import MODERATE, Clock, FakeAbuse, FakeOtx, answer
from tests.provider_helpers import Script, Wire, assert_nothing_sensitive_logged
from tests.test_collectors import abuse_payload, otx_payload, otx_pulse
from tests.test_threatfox import entry, found
from tests.test_virustotal import vt_payload

IP = "8.8.8.8"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CONTEXT = RequestContext(actor="analyst-1", source_ip="203.0.113.9")

PROVIDERS = ("abuseipdb", "otx", "virustotal", "threatfox")
KEYS = {
    "abuseipdb": "abuse-key-1111",
    "otx": "otx-key-2222",
    "virustotal": "vt-key-3333",
    "threatfox": "tf-key-4444",
}
HOSTS = {
    "api.abuseipdb.com": "abuseipdb",
    "otx.alienvault.com": "otx",
    "www.virustotal.com": "virustotal",
    "threatfox-api.abuse.ch": "threatfox",
}


class Network:
    """The four providers' canned answers, routed by host. Replace a wire to change one."""

    def __init__(self) -> None:
        self.wires: dict[str, Any] = {
            "abuseipdb": Wire(body=abuse_payload()),
            "otx": Wire(body=otx_payload([otx_pulse()])),
            "virustotal": Wire(body=vt_payload()),
            "threatfox": Wire(body=found(entry())),
        }

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        return self.wires[HOSTS[request.url.host]](request)

    def calls(self, provider: str) -> list[httpx2.Request]:
        return self.wires[provider].calls

    def call_counts(self) -> list[int]:
        return [len(self.calls(name)) for name in PROVIDERS]


@pytest.fixture
def network() -> Network:
    return Network()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def engine(make_settings: Callable[..., Settings], db_url: str) -> Iterator[Engine]:
    engine = build_engine(make_settings(database_url=db_url))
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return build_session_factory(engine)


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as db:
        yield db


@pytest.fixture
def service(
    make_settings: Callable[..., Settings], network: Network, clock: Clock
) -> Iterator[IntelService]:
    settings = make_settings(
        abuseipdb_api_key=KEYS["abuseipdb"],
        otx_api_key=KEYS["otx"],
        virustotal_api_key=KEYS["virustotal"],
        threatfox_api_key=KEYS["threatfox"],
        # No waiting between attempts: the adapters' own retry behaviour is tested elsewhere.
        virustotal_max_retries=0,
        threatfox_max_retries=0,
    )
    client = httpx2.Client(transport=httpx2.MockTransport(network), follow_redirects=False)
    built = IntelService(
        build_collectors(settings, client),
        http_client=client,
        clock=clock,
        provider_timeout_seconds=settings.provider_timeout_seconds,
    )
    yield built
    built.close()


def by_provider(response: InvestigationResponse) -> dict[str, ProviderView]:
    return {view.provider: view for view in response.providers}


def audits(session_factory: sessionmaker[Session]) -> list[AuditLog]:
    with session_factory() as reader:
        return list(reader.scalars(select(AuditLog).order_by(AuditLog.id)))


def observation_count(session_factory: sessionmaker[Session]) -> int:
    with session_factory() as reader:
        return len(reader.scalars(select(ThreatObservation)).all())


# --- One investigation, four providers -----------------------------------------------------


def test_all_four_providers_answer_one_investigation_and_stay_separate(
    session: Session,
    session_factory: sessionmaker[Session],
    service: IntelService,
    network: Network,
) -> None:
    response = service.investigate(session, CONTEXT, IP)

    views = by_provider(response)
    assert list(views) == list(PROVIDERS), "display order, one card per provider"
    assert {view.status for view in views.values()} == {"ok"}
    assert all(view.message is None and view.reason is None for view in views.values())
    assert all(view.fetched_at is not None and view.freshness == "fresh" for view in views.values())
    assert views["virustotal"].verdict == "malicious"
    assert views["threatfox"].verdict == "malicious"
    assert views["abuseipdb"].verdict is None and views["otx"].verdict is None
    assert views["virustotal"].summary["malicious"] == 12
    assert views["threatfox"].summary["matches"][0]["confidence_level"] == 75
    assert response.score.methodology == "intel-risk-v1"
    assert response.score.answered_sources == 4
    assert observation_count(session_factory) == 4
    [audit] = audits(session_factory)
    assert (audit.action, audit.result) == ("IOC_LOOKUP", "success")
    assert audit.details["providers"] == {
        name: {"status": "ok", "cache": "miss"} for name in PROVIDERS
    }
    assert network.call_counts() == [1, 1, 1, 1]


def test_each_key_goes_only_to_its_own_provider_and_only_in_a_header(
    session: Session, service: IntelService, network: Network
) -> None:
    service.investigate(session, CONTEXT, IP)

    headers = {
        "abuseipdb": "key",
        "otx": "x-otx-api-key",
        "virustotal": "x-apikey",
        "threatfox": "auth-key",
    }
    for provider, header in headers.items():
        (request,) = network.calls(provider)
        assert request.headers[header] == KEYS[provider]
        for other, key in KEYS.items():
            assert key not in str(request.url)
            assert key.encode() not in request.content
            if other != provider:
                assert key not in " ".join(request.headers.values())


def test_virustotal_and_threatfox_are_asked_at_the_same_time(
    session: Session, service: IntelService, network: Network
) -> None:
    meeting = threading.Barrier(2, timeout=5)

    def meet() -> None:
        # Each call waits for the other: they can only both finish if they overlap.
        meeting.wait()

    network.wires["virustotal"] = Wire(body=vt_payload(), before=meet)
    network.wires["threatfox"] = Wire(body=found(entry()), before=meet)

    views = by_provider(service.investigate(session, CONTEXT, IP))

    assert (views["virustotal"].status, views["threatfox"].status) == ("ok", "ok")


# --- One provider failing ------------------------------------------------------------------


def test_a_failed_provider_keeps_the_others_answers_and_is_retried_alone(
    session: Session,
    session_factory: sessionmaker[Session],
    service: IntelService,
    network: Network,
) -> None:
    network.wires["virustotal"] = Script(Wire(503), Wire(body=vt_payload()))

    first = by_provider(service.investigate(session, CONTEXT, IP))

    failed = first["virustotal"]
    assert (failed.status, failed.reason, failed.verdict) == ("error", "unavailable", None)
    assert failed.message == "VirusTotal returned an unexpected HTTP status (503)."
    assert (failed.fetched_at, failed.signal, failed.freshness) == (None, None, None)
    assert [name for name, view in first.items() if view.status == "ok"] == [
        "abuseipdb",
        "otx",
        "threatfox",
    ]
    assert observation_count(session_factory) == 3, "a failure is never stored"
    [audit] = audits(session_factory)
    assert audit.result == "partial"
    assert audit.details["providers"]["virustotal"] == {
        "status": "error",
        "cache": "miss",
        "reason": "unavailable",
    }

    # Investigating again (no refresh) asks only the provider that has no answer yet.
    second_response = service.investigate(session, CONTEXT, IP)

    second = by_provider(second_response)
    assert {view.status for view in second.values()} == {"ok"}
    assert [second[name].from_cache for name in PROVIDERS] == [True, True, False, True]
    assert network.call_counts() == [1, 1, 2, 1]
    assert second_response.score.answered_sources == 4
    assert audits(session_factory)[-1].result == "success"
    assert observation_count(session_factory) == 4


def test_every_failure_carries_its_own_reason_and_the_other_answers_survive(
    session: Session, service: IntelService, network: Network
) -> None:
    network.wires["otx"] = Wire(error=httpx2.ReadTimeout("slow"))
    network.wires["virustotal"] = Wire(429)
    network.wires["threatfox"] = Wire(401)

    response = service.investigate(session, CONTEXT, IP)

    assert {
        name: (view.status, view.reason, view.message is not None)
        for name, view in by_provider(response).items()
    } == {
        "abuseipdb": ("ok", None, False),
        "otx": ("error", "timeout", True),
        "virustotal": ("rate_limited", "rate_limited", True),
        "threatfox": ("error", "auth_failed", True),
    }
    assert response.score.answered_sources == 1


def test_a_stale_answer_stays_visible_when_its_refresh_fails(
    session: Session,
    session_factory: sessionmaker[Session],
    service: IntelService,
    network: Network,
    clock: Clock,
) -> None:
    network.wires["threatfox"] = Script(Wire(body=found(entry())), Wire(503))
    service.investigate(session, CONTEXT, IP)

    clock.advance(hours=7)  # past ThreatFox's six-hour cache, inside VirusTotal's 24 hours
    views = by_provider(service.investigate(session, CONTEXT, IP))

    stale = views["threatfox"]
    assert (stale.status, stale.freshness, stale.from_cache) == ("ok", "stale", True)
    assert stale.verdict == "malicious", "the stored answer is still shown"
    assert (stale.reason, stale.message) == (
        "unavailable",
        "ThreatFox returned an unexpected HTTP status (503).",
    )
    assert views["virustotal"].freshness == "fresh" and views["virustotal"].reason is None
    assert audits(session_factory)[-1].result == "partial"


# --- Caching, per provider -----------------------------------------------------------------


def test_every_provider_is_cached_for_its_own_time(
    session: Session, service: IntelService, network: Network, clock: Clock
) -> None:
    service.investigate(session, CONTEXT, IP)
    assert network.call_counts() == [1, 1, 1, 1]

    clock.advance(hours=7)  # AbuseIPDB and ThreatFox keep answers for 6 hours
    service.investigate(session, CONTEXT, IP)
    assert network.call_counts() == [2, 1, 1, 2]

    clock.advance(hours=6)  # 13 hours in: OTX (12 hours) too; VirusTotal (24 hours) still not
    service.investigate(session, CONTEXT, IP)
    assert network.call_counts() == [3, 2, 1, 3]

    clock.advance(hours=12)  # 25 hours in: everything has outlived its cache
    service.investigate(session, CONTEXT, IP)
    assert network.call_counts() == [4, 3, 2, 4]


# --- Indicator types -----------------------------------------------------------------------


def test_a_sha1_hash_is_not_sent_to_providers_that_cannot_look_it_up(
    session: Session, service: IntelService, network: Network
) -> None:
    network.wires["otx"] = Wire(body=otx_payload([]))
    network.wires["virustotal"] = Wire(body=vt_payload("file", SHA256))

    views = by_provider(service.investigate(session, CONTEXT, SHA1))

    assert {name: view.status for name, view in views.items()} == {
        "abuseipdb": "unsupported",
        "otx": "no_data",
        "virustotal": "ok",
        "threatfox": "unsupported",
    }
    assert all(views[name].reason is None for name in ("abuseipdb", "threatfox"))
    assert network.call_counts() == [0, 1, 1, 0]
    assert network.calls("virustotal")[0].url.path == f"/api/v3/files/{SHA1}"


@pytest.mark.parametrize("value", [MD5, SHA256])
def test_md5_and_sha256_hashes_go_to_virustotal_and_threatfox(
    value: str, session: Session, service: IntelService, network: Network
) -> None:
    network.wires["otx"] = Wire(body=otx_payload([]))
    network.wires["virustotal"] = Wire(body=vt_payload("file", SHA256))
    network.wires["threatfox"] = Wire(
        body=found(entry("http://198.51.100.7:8080/a.bin", ioc_type="url", confidence_level=100))
    )

    views = by_provider(service.investigate(session, CONTEXT, value))

    assert views["abuseipdb"].status == "unsupported"
    assert (views["virustotal"].status, views["threatfox"].status) == ("ok", "ok")
    assert views["threatfox"].summary["association"] == "file_hash"
    assert network.call_counts() == [0, 1, 1, 1]


# --- Secrets -------------------------------------------------------------------------------


@pytest.mark.usefixtures("production_logging")
def test_no_key_reaches_the_response_the_audit_trail_or_the_logs(
    session: Session,
    session_factory: sessionmaker[Session],
    service: IntelService,
    network: Network,
    caplog: pytest.LogCaptureFixture,
) -> None:
    network.wires["virustotal"] = Wire(401, body={"error": {"message": KEYS["virustotal"]}})
    network.wires["threatfox"] = Wire(error=httpx2.ConnectError(KEYS["threatfox"]))

    response = service.investigate(session, CONTEXT, IP)

    rendered = response.model_dump_json() + json.dumps(audits(session_factory)[-1].details)
    for key in KEYS.values():
        assert key not in rendered
    assert_nothing_sensitive_logged(caplog, *KEYS.values(), IP)


# --- Deadlines and reported reasons --------------------------------------------------------


def test_a_provider_with_a_longer_budget_is_not_cut_off_by_the_default_one(
    monkeypatch: pytest.MonkeyPatch, session: Session, clock: Clock
) -> None:
    monkeypatch.setattr(intel_service, "_WAIT_GRACE_SECONDS", 0.0)
    never, soon = threading.Event(), threading.Event()
    hung = FakeAbuse(block=never)  # the service-wide budget: 0.2 s
    patient = FakeOtx([answer("otx", signal=MODERATE, evidence_at=clock.ago(days=1))], block=soon)
    patient.timeout_seconds = 3.0  # its own, longer budget
    timer = threading.Timer(0.6, soon.set)
    timer.start()
    built = IntelService([hung, patient], clock=clock, provider_timeout_seconds=0.2)

    try:
        views = by_provider(built.investigate(session, CONTEXT, IP))
    finally:
        never.set()
        soon.set()
        timer.cancel()
        built.close()
        # The abandoned worker logs when it finally returns; wait so that line stays in this test.
        for worker in threading.enumerate():
            if worker.name.startswith("intel-lookup"):
                worker.join(timeout=5)

    assert (views["abuseipdb"].status, views["abuseipdb"].reason) == ("error", "timeout")
    assert views["abuseipdb"].message == "AbuseIPDB did not respond in time."
    assert (views["otx"].status, views["otx"].reason) == ("ok", None)


@pytest.mark.parametrize(
    ("claimed", "shown"),
    [
        ("malicious", "malicious"),
        ("suspicious", "suspicious"),
        ("harmless", "harmless"),
        ("unknown", "unknown"),
        ("not_found", "not_found"),
        ("safe", None),
        ("MALICIOUS", None),
        ("", None),
        (7, None),
        (["malicious"], None),
        (None, None),
    ],
)
def test_only_a_known_verdict_label_is_passed_on(
    claimed: Any, shown: str | None, session: Session, clock: Clock
) -> None:
    abuse = FakeAbuse(
        [
            answer(
                "abuseipdb",
                signal=MODERATE,
                evidence_at=clock.ago(days=1),
                summary={"verdict": claimed},
            )
        ]
    )
    built = IntelService([abuse], clock=clock)

    try:
        [view] = built.investigate(session, CONTEXT, IP).providers
    finally:
        built.close()

    assert view.verdict == shown


@pytest.mark.parametrize("reason", list(Reason))
def test_the_reason_a_provider_gives_for_a_failure_is_passed_on(
    reason: Reason, session: Session, clock: Clock
) -> None:
    abuse = FakeAbuse([ProviderFailure(ProviderStatus.ERROR, "AbuseIPDB could not help.", reason)])
    built = IntelService([abuse], clock=clock)

    try:
        [view] = built.investigate(session, CONTEXT, IP).providers
    finally:
        built.close()

    assert (view.status, view.reason, view.verdict) == ("error", reason.value, None)


def test_a_missing_key_is_reported_as_missing_configuration_and_an_unsupported_type_is_not(
    session: Session, clock: Clock
) -> None:
    keyless = FakeOtx(api_key=None)
    ip_only = FakeAbuse()
    built = IntelService([keyless, ip_only], clock=clock)

    try:
        otx, abuse = built.investigate(session, CONTEXT, "example.com").providers
    finally:
        built.close()

    assert (otx.status, otx.reason) == ("not_configured", "not_configured")
    assert (abuse.status, abuse.reason) == ("unsupported", None)

# Architecture

This document describes what is built (Phases 1 and 2) and how the remaining modules are intended to
plug in. Anything not built is labelled **planned**. The intended end state follows the project
specification; nothing planned here should be read as implemented.

## System context

```mermaid
flowchart LR
    Browser[Browser] -->|HTTP, port 3000| Nginx
    subgraph Compose[Docker Compose network]
        Nginx["frontend: nginx<br/>static SPA + reverse proxy"] -->|/api, /health, /ready| API[backend: FastAPI]
        Migrate["migrate: alembic upgrade head<br/>one-shot"] --> DB
        API --> DB[(PostgreSQL 16)]
    end
    API -.->|JWKS fetch, cached 1 h| Entra[Microsoft Entra ID]
    API -.->|HTTPS, API key, only when a lookup needs it| Feeds[AbuseIPDB and AlienVault OTX]
```

- The browser only talks to nginx. The SPA calls the API with relative URLs, so there is no CORS in
  the default deployment.
- nginx sets the security headers and the Content Security Policy for the static files and strips
  the duplicates the API adds, so each header appears once.
- The API reaches Entra ID only to download signing keys. Tokens are validated locally.
- The API reaches the two threat-intelligence providers only through their collectors, at fixed
  hosts, and only when an investigation needs a fresh answer. The browser never contacts them and
  never sees their keys.
- Migrations are a separate one-shot step, not something the API does at startup.

## Threat-intelligence flow (Phase 2)

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API (intel router)
    participant S as Intel service
    participant D as PostgreSQL
    participant P as AbuseIPDB / OTX
    C->>A: POST /api/v1/intel/investigate
    A->>A: validate token, require SecurityAnalyst or Admin, per-user rate limit
    A->>S: raw indicator, refresh flag
    S->>S: normalise and refuse non-public targets (refusals are audited)
    S->>D: get or create the indicator, read cached answers
    S->>P: only providers with no usable cached answer, in parallel, one deadline
    P-->>S: an answer or a labelled failure
    S->>D: store answers, store the new score, write the audit row (one commit)
    S-->>A: each provider on its own, then the score, uncertainty and actions
    A-->>C: JSON with Cache-Control no-store
```

The collectors, the scoring function and the service are separate so each can be tested without the
others: the scorer is a pure function, the collectors run against a stub transport, and the service
runs against SQLite and PostgreSQL. [threat-intelligence.md](threat-intelligence.md) has the details
(normalisation, caching, the `intel-risk-v1` method, stored data and the limits).

## Target architecture (planned)

```mermaid
flowchart TD
    Feeds[Threat intelligence feeds] --> Norm
    Sensor[Network sensor] --> Norm
    Events[Auth / file / honeypot events] --> Norm
    Norm[Security event and normalisation layer] --> Corr[Enrichment and correlation]
    Corr --> Score[Explainable risk score]
    Score --> Rules[Detection rules and alerts]
    Rules --> SOC[Incidents and SOC dashboard]
    SOC --> Analyst[Analyst investigation and response]
```

Only the threat-intelligence feed path (indicator in, enrichment, explainable score out) is built.
It scores one indicator on demand; there is no event stream, correlation across events, detection
rules or incident handling yet.

## Module map

| Module | Purpose | Status | Where it lives or will live |
| --- | --- | --- | --- |
| Core platform | Config, logging, auth, errors, health | **Phase 1 done** | `backend/app/core`, `security`, `api`, `database` |
| Intel | Threat-intelligence ingestion, IOC investigation, caching | **Phase 2 done** (API only; no UI yet) | `collectors/`, `services/`, `correlation/scoring.py`, `api/v1/intel.py` |
| SOC | Command-centre UI, triage, analytics | Status page only; investigation UI planned (Phase 3) | `frontend/src` |
| Sentinel | Defensive network monitoring and anomaly detection | Not started | `sensor/`, `detection/` |
| Core (correlation) | Event normalisation, correlation, scoring, rules | Indicator scoring only; event correlation and rules not started | `correlation/`, `detection/` |
| Case | Incidents, notes, timelines | Not started | `services/`, `models/` |
| Vault | Client-side encrypted file sharing | Not started; needs a threat model first | `docs/encryption-design.md` |

## Backend

`backend/app` is organised by responsibility, with one-way dependencies: `api` calls `services`,
which use `models`, `collectors` and `correlation`; `core` and `security` are shared by everything.

| Package | Responsibility |
| --- | --- |
| `api/` | HTTP routes and request dependencies. No business logic. Versioned under `/api/v1`. |
| `core/` | Settings, structured logging and redaction, correlation ID context, error envelope, middleware. |
| `security/` | Entra ID token validation, role-based access control and the in-memory rate limiter. |
| `database/` | Engine and session factory, the readiness probe. |
| `models/`, `schemas/` | SQLAlchemy tables and Pydantic request/response models. |
| `services/` | Indicator normalisation, the investigation workflow (caching, scoring, storage) and the audit writer. |
| `collectors/` | One adapter per provider (AbuseIPDB, OTX) behind a common interface, plus response sanitising helpers. |
| `correlation/` | The pure, explainable scoring function (`intel-risk-v1`). |
| `detection/`, `workers/` | Placeholders for later phases. |

### Request lifecycle

`create_app` stacks the middleware so a request passes through, outermost first:

```text
CorrelationId -> SecurityHeaders -> RequestLogging -> CORS (only if configured)
              -> UnhandledException -> router -> endpoint
```

- **CorrelationId** accepts an incoming `X-Correlation-ID` only if it matches `[A-Za-z0-9._-]{8,64}`
  (otherwise it generates one), so a client cannot inject log lines.
- **SecurityHeaders** adds `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`.
- **RequestLogging** writes one structured line per request (method, path, status, duration). It
  never logs query strings or bodies.
- **UnhandledException** turns any unexpected error into a generic 500, so the outer layers can
  still add headers and logging.

The middleware are plain ASGI rather than `BaseHTTPMiddleware`, so the correlation ID context
variable also reaches synchronous endpoints running in the thread pool.

### Errors

Every error uses one envelope: `{"error": {"code", "message", "correlation_id", "details?"}}`.
Validation errors (422) return only the location, message and type of each problem, never the
submitted value. A 500 never exposes internals.

### Authentication and authorisation

`AUTH_MODE=entra` validates Microsoft Entra ID access tokens: RS256 only, signature checked against
the tenant's cached JWKS, and `exp`, `iss`, `aud`, `sub` and `tid` required and verified.
`require_roles(...)` guards endpoints by role (`Admin`, `SecurityAnalyst`, `User`). `AUTH_MODE=dev`
returns a fixed local principal and is refused when `ENVIRONMENT=production`. The validator can be
injected into `create_app`, which is how the tests use generated keys instead of a real tenant.

Resource-level authorisation (for example per-file access in Vault) is not implemented and must be
designed with the feature that needs it.

### Data layer

SQLAlchemy 2 with Alembic. Constraint names follow a naming convention so migrations stay
deterministic. Two migrations exist: `0001` (the baseline) and `0002_threat_intel`, which adds
`threat_sources`, `threat_indicators`, `threat_observations` and `audit_logs`. The audit table is
append-only: triggers on SQLite and PostgreSQL reject `UPDATE` and `DELETE`. Unit tests run on
SQLite and, when `TEST_DATABASE_URL` is set, again on PostgreSQL (the same tests, parametrised),
including upgrade, downgrade and upgrade again on the real engine. Production requires PostgreSQL.

## Frontend

React 19 and TypeScript, built with Vite and styled with Tailwind CSS.

```text
pages/        route-level screens (StatusPage)
features/     domain logic with no React (overallStatus)
hooks/        stateful logic (useServiceStatus polls every 30 s)
services/     the API client and per-resource services
components/   shared presentational components
types/        API types mirroring the backend schemas
```

All network access goes through `services/apiClient.ts`: relative URLs, a timeout, no caching,
runtime shape checks on responses, and errors that surface only the server's sanitised message and
correlation ID. A bearer token can be supplied from memory; tokens are never persisted.

## Design decisions

| Decision | Reason |
| --- | --- |
| App factory, no module-level `app` | Importing the module has no side effects; tests build apps with explicit settings. |
| Fail-closed settings | A missing or unsafe setting stops the API rather than weakening security silently. |
| Migrations as a separate step | No race between replicas, and the API process never changes the schema. |
| PostgreSQL as the cache for provider results | The specification says not to add a queue or cache service just to make the MVP look complex. Answers are stored as observations; the cache is a freshness check against them, so a restart loses nothing. |
| Scoring is a pure function of the stored answers | The same evidence always gives the same score, every point is a listed factor, and the method (`intel-risk-v1`) is tested with worked examples instead of being trusted. |
| One provider failing never fails the investigation | Each provider ends in a labelled status (for example `ok`, `no_data`, `not_configured`, `rate_limited` or `error`). Failures are shown, counted as uncertainty and never stored as answers. |
| Audit row written in the same transaction as the result | A stored score always has its audit row, and refused input is audited too. Reads are not audited (see [security.md](security.md)). |
| `httpx2` instead of `httpx` | The maintained continuation of HTTPX; Starlette's test client prefers it. The provider adapters use it, and its request logging is silenced because it records full request URLs, which contain the indicators being investigated. |
| TypeScript pinned to 6.0.3 | The latest stable `typescript-eslint` does not yet support TypeScript 7. |
| Exact version pins | Reproducible builds; Dependabot proposes updates and CI vets them. |

## How later phases plug in

1. **Collectors** (`collectors/`) wrap one provider each behind a common interface and return a
   normalised observation. They are tested against recorded responses, never live APIs. A new
   provider is one collector class, its settings and one registry entry (see
   [threat-intelligence.md](threat-intelligence.md#adding-a-provider)).
2. **Services** (`services/`) orchestrate collectors, persistence, caching and scoring. Phase 2
   built this for indicators; internal telemetry and incidents will add their own services.
3. **Detection rules** (`detection/`) live in one place, not in controllers or UI code. Not built.
4. **Workers** (`workers/`) appear only when scheduled refresh or correlation needs them. Not built;
   scores are recomputed only when an indicator is investigated.
5. Detection and response stay separate: the platform recommends actions and does not block
   anything automatically.

# CipherForge

**Intelligence. Detection. Encryption.**

CipherForge is a cloud-native cybersecurity and mini-SOC portfolio platform: multi-source threat
intelligence, network anomaly detection, explainable risk scoring, SIEM-style alerting, incident
management and client-side encrypted file sharing, built as one modular defensive-security project.

> It is designed for a controlled lab. Run packet capture, load generation or honeypots only on
> systems and networks you own or are explicitly authorised to test.

## Status

The project is built in vertical slices, each one tested and committed before the next begins.

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Foundation: FastAPI, React + TypeScript, PostgreSQL, Docker Compose, configuration, logging, auth shape | **Done.** The Docker stack itself is unverified, see [verification status](docs/deployment.md#verification-status) |
| 2 | Threat Intel MVP: AbuseIPDB + AlienVault OTX, normalisation, persistence, caching, risk score | **Done** (backend and API). Providers are tested against recorded responses only, see [threat-intelligence.md](docs/threat-intelligence.md#verification-status) |
| 3 | SOC dashboard: investigation view, IOC table and search, charts | Planned next |
| 4-12 | Network sensor, detection, correlation, mini-SIEM, cases, Vault, integrations, Azure, DevSecOps | Not started |

The roadmap follows the project specification; see [docs/architecture.md](docs/architecture.md) for
how each module (Intel, Sentinel, Core, SOC, Case, Vault) maps to the code.

### What works today

**Phase 1: foundation**

- `GET /health` (liveness) and `GET /ready` (checks the database connection) with stable JSON.
- `GET /api/v1/me`: the authenticated identity and roles. Microsoft Entra ID access tokens are
  validated (signature, issuer, audience, tenant, expiry) and mapped to the `Admin`,
  `SecurityAnalyst` and `User` roles. A local `dev` mode exists for development only.
- Structured JSON logging with secret redaction, correlation IDs on every request and a uniform
  error format.
- A React + TypeScript status page that shows the API and database health.
- PostgreSQL with SQLAlchemy and Alembic migrations.
- Docker Compose for the whole stack, and a GitHub Actions pipeline (lint, tests, security checks,
  dependency audits, image build and a stack smoke test).

**Phase 2: threat intelligence (API only, no dashboard yet)**

- `POST /api/v1/intel/investigate` takes one indicator (IPv4, IPv6, domain, URL or SHA-256; defanged
  forms such as `hxxp://example[.]com` are accepted), validates and normalises it, asks AbuseIPDB
  and AlienVault OTX where they apply, and returns **each provider's answer on its own**, then an
  explainable CipherForge score from 0 to 100 with its confidence, the evidence it rests on, what is
  not known and recommended next steps. One source alone can never push the score above 60.
- `GET /api/v1/intel/indicators` (search, filter, page), `GET /api/v1/intel/indicators/{id}` and
  `GET /api/v1/intel/stats` read the stored results without contacting a provider.
- Answers are cached in PostgreSQL (6 hours for AbuseIPDB, 12 for OTX by default). A provider that
  is missing, slow or failing shows up as a labelled status; it never breaks the lookup.
- Every investigation, including refused input, is written to an append-only audit table.
  Investigations are rate-limited per analyst. Access needs the `SecurityAnalyst` or `Admin` role.
- Private, loopback and reserved addresses and internal names are refused before any outside call.

The method is documented in [docs/threat-intelligence.md](docs/threat-intelligence.md) and the
endpoints in [docs/api.md](docs/api.md).

### Not implemented yet

The investigation dashboard (Phase 3), packet capture, detection rules, event correlation, alerts,
incidents, file sharing and encryption, Redis, background workers (so a stored score is recomputed
only when its indicator is investigated again), Azure deployment. The folders
`sensor/` and `infra/` and the matching documents in `docs/` are placeholders that say so.
The frontend has no sign-in flow yet (see [Limitations](#limitations)).

## Quick start

You need Python 3.12 and Node 22.22 or newer (Node 24 is what CI and the Docker image use).

### Option A: everything in Docker

```bash
cp .env.example .env          # for anything beyond local play, set a random POSTGRES_PASSWORD
docker compose up --build
```

Open <http://localhost:3000>. The ports are bound to `127.0.0.1` only. Compose starts PostgreSQL,
runs the migrations once, starts the API and then serves the frontend through nginx, which also
proxies `/api`, `/health` and `/ready` to the API.

### Option B: run the pieces locally

1. Create the configuration file and a database. The quickest database is the Compose one:

   ```bash
   cp .env.example .env
   docker compose up -d postgres
   ```

   Without Docker, set `DATABASE_URL=sqlite+pysqlite:///./cipherforge.db` in `.env`. SQLite is for
   local experiments only; `ENVIRONMENT=production` requires PostgreSQL.

2. Backend (<http://127.0.0.1:8000>, interactive docs at `/docs` outside production):

   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
   pip install -r requirements-dev.txt
   alembic upgrade head
   uvicorn app.main:create_app --factory --reload
   ```

3. Frontend (<http://127.0.0.1:5173>, proxies the API calls to port 8000):

   ```bash
   cd frontend
   npm ci
   npm run dev
   ```

   On Windows PowerShell with script execution disabled, use `npm.cmd` instead of `npm`.

### Try an investigation (API)

With `AUTH_MODE=dev` (the `.env.example` default) the local principal is a `SecurityAnalyst`, so no
token is needed:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/intel/investigate \
  -H "Content-Type: application/json" -d '{"indicator": "8.8.8.8"}'
```

Without provider keys, both providers come back as `not_configured`, the score is 0 with confidence
0 and `answered_sources` of 0, and the advice says nothing can be concluded. That is "not assessed",
not "clean". To query the real services, put free keys in `.env`: `ABUSEIPDB_API_KEY`
(<https://www.abuseipdb.com/account/api>) and `OTX_API_KEY` (<https://otx.alienvault.com/settings>).
Restart the API after changing `.env`.

## Quality checks

```bash
# Backend (from backend/)
ruff check . && ruff format --check .
bandit -c pyproject.toml -r app -q
pip-audit -r requirements.txt
pytest --cov=app                  # SQLite only
TEST_DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/test_db pytest
                                  # runs the database tests on PostgreSQL as well

# Frontend (from frontend/)
npm run typecheck && npm run lint && npm test && npm run build
npm audit --audit-level=moderate
```

Point `TEST_DATABASE_URL` at a throwaway database: the PostgreSQL tests create and drop tables in it.

## Configuration

Settings come from environment variables; for local runs they can also live in a git-ignored
`.env` at the repository root. Invalid settings stop the API from starting, and the error names the
setting but never prints its value. See [.env.example](.env.example) for the full annotated list.

| Variable | Purpose | Default |
| --- | --- | --- |
| `ENVIRONMENT` | `development`, `test` or `production` | `production` |
| `AUTH_MODE` | `entra` (validate Entra ID tokens) or `dev` (local only) | `entra` |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` | Required when `AUTH_MODE=entra` | none |
| `ENTRA_AUDIENCE` | Expected token audience | `ENTRA_CLIENT_ID` |
| `DATABASE_URL` | SQLAlchemy URL; PostgreSQL in production | required |
| `DEV_AUTH_ROLES` | Roles of the local dev principal | `SecurityAnalyst` |
| `CORS_ORIGINS` | Comma separated origins; `*` is rejected | none |
| `LOG_LEVEL`, `LOG_FORMAT` | Logging verbosity and `json` or `console` output | `INFO`, `json` |
| `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | Provider keys; a provider without one is reported as not configured | none |
| `ABUSEIPDB_CACHE_TTL_SECONDS`, `OTX_CACHE_TTL_SECONDS` | How long a provider answer is reused (60 seconds to 30 days) | `21600`, `43200` |
| `PROVIDER_TIMEOUT_SECONDS` | How long to wait for one provider (1 to 30) | `10` |
| `INVESTIGATE_RATE_LIMIT_PER_MINUTE` | Investigations per analyst per minute, per API process (1 to 600) | `30` |

The defaults are deliberately strict. In production, `AUTH_MODE=dev` is refused, PostgreSQL is
required and a `DATABASE_URL` that still contains `CHANGE_ME` is refused. Provider keys are held as
secrets: they are never logged, never returned by the API and, in Compose, given only to the
`backend` container.

## Repository layout

```text
backend/      FastAPI service (app/, alembic/, tests/)
frontend/     React + TypeScript + Vite + Tailwind single-page app, served by nginx in Docker
sensor/       Network sensor (placeholder, not implemented)
infra/        Infrastructure as code (placeholder, not implemented)
docs/         Architecture, security and deployment notes
.github/      CI workflow and Dependabot configuration
docker-compose.yml
.env.example
```

## Security

Security is a design input, not a later phase. The headline controls are fail-closed configuration,
Entra token validation with role checks, secret redaction in logs, a uniform error format that
never echoes input, security headers and a strict Content Security Policy, non-root containers
with all Linux capabilities dropped (and a read-only root filesystem for the API), pinned
dependencies, and automated dependency and static analysis in CI. The threat-intelligence feature
adds strict indicator validation (no server-side requests to internal targets), defensive parsing of
untrusted provider data, provider keys kept server-side, a per-analyst rate limit and an
append-only audit trail.
The details, and what is deliberately left for later, are in [docs/security.md](docs/security.md)
and [docs/threat-model.md](docs/threat-model.md).

## Limitations

- **No sign-in in the frontend yet.** The API validates Entra ID tokens and the frontend client can
  attach a bearer token, but there is no MSAL integration. Use `AUTH_MODE=dev` locally until an
  Entra app registration and the sign-in flow are added.
- **TLS and HSTS are the job of the proxy in front of nginx.** The compose stack speaks plain HTTP
  on loopback.
- **Single-instance assumptions.** The rate limiter keeps its counts in memory, per API process, so
  several replicas would each allow the full rate. Nothing shared between replicas exists yet (no
  Redis).
- **The providers have only been tested against recorded responses**, never the live AbuseIPDB and
  OTX services. Their request formats were checked against public documentation and AlienVault's
  client library; some OTX response fields are unconfirmed. See
  [docs/threat-intelligence.md](docs/threat-intelligence.md#verification-status).
- **Scores are advice, not verdicts.** They come from two community and commercial feeds, age with
  the evidence only when an indicator is investigated again, and say nothing about your own
  environment because no internal telemetry is connected yet.
- The container images, Compose file and CI workflow are checked statically and by the CI
  pipeline; see [docs/deployment.md](docs/deployment.md#verification-status).

## Licence

MIT. See [LICENSE](LICENSE).

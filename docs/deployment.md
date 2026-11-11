# Deployment

How to run CipherForge locally with Docker Compose, what to change before exposing it anywhere, and
what has and has not been verified. The Azure deployment is **planned, not built**.

## Local stack with Docker Compose

```bash
cp .env.example .env
# Edit .env: set a random POSTGRES_PASSWORD (letters and digits only), for example
#   openssl rand -hex 24
docker compose up --build
```

Services, in start-up order:

| Service | Image | Role | Host port (loopback only) |
| --- | --- | --- | --- |
| `postgres` | `postgres:16-alpine` | Database. Data lives in the `postgres_data` volume. | `5432` (`POSTGRES_PORT`) |
| `migrate` | backend image | Runs `alembic upgrade head` once, then exits. | none |
| `backend` | backend image | FastAPI on port 8000. Starts after the migration succeeds. | `8000` (`BACKEND_PORT`) |
| `frontend` | nginx (unprivileged) | Static app and reverse proxy to the API. | `3000` (`FRONTEND_PORT`) |

Open <http://localhost:3000>. That is the dashboard: Overview, Investigate, Indicators and System
status. It needs the API's development authentication (the template's `AUTH_MODE=dev`), because
there is no browser sign-in yet; against an API that requires Entra tokens every screen shows
"Not signed in". `docker compose down` stops the stack and keeps the data;
`docker compose down --volumes` also deletes the database.

### Configuration

Compose reads `.env` for substitution and passes the relevant values to the containers. The template
selects `ENVIRONMENT=development` and `AUTH_MODE=dev` so the stack works out of the box. If you omit
them entirely, the secure defaults apply and the API will refuse to start until Entra is configured.

`DATABASE_URL` is built by Compose from `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`.
Because the password sits inside a URL, keep it to letters and digits.

### Threat-intelligence providers

IOC investigation (Phase 2) queries two outside services. Each is optional and needs its own free
account key, which you put in `.env`:

| Variable | Provider | Covers | Where to get a key |
| --- | --- | --- | --- |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IPv4 and IPv6 addresses | <https://www.abuseipdb.com/account/api> |
| `OTX_API_KEY` | AlienVault OTX | IP addresses, domains, URLs and SHA-256 hashes | <https://otx.alienvault.com/settings> |

- **No key is needed to start the stack.** A provider without a key is reported as
  `not_configured` in every investigation, never silently skipped and never counted as "clean".
- **Keys reach only the `backend` container.** The migration job and the web front end do not
  receive them. The API never returns a key, and the log filter masks the exact value if it is ever
  written.
- The remaining settings have working defaults: `ABUSEIPDB_CACHE_TTL_SECONDS` (21600, six hours),
  `OTX_CACHE_TTL_SECONDS` (43200, twelve hours), `PROVIDER_TIMEOUT_SECONDS` (10) and
  `INVESTIGATE_RATE_LIMIT_PER_MINUTE` (30 per analyst, counted in memory by each API process, so
  running several replicas multiplies it). Compose repeats the defaults from
  `backend/app/core/config.py`, and a test fails if the two drift apart.
- A longer cache time spends less of the free quota but shows older answers; every answer is shown
  with its age either way.

The source address recorded in the audit trail comes from the `X-Forwarded-For` header set by nginx,
and the backend honours that header only from the networks in `FORWARDED_ALLOW_IPS`. Compose defaults
this to the private ranges (`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`) so the nginx container is
trusted. Two things follow:

- If you put a TLS-terminating proxy in front of nginx, nginx sees the proxy as the client and the
  audit trail records the proxy's address. Configure nginx's `real_ip` module for that proxy, or
  accept it. This stack does not do either for you.
- Do not publish the backend port (8000) beyond loopback. A caller inside the trusted ranges that
  reaches the backend directly can choose the address that gets recorded. The recorded value is
  still checked to be a valid IP address, and the audited user always comes from the token.

### Migrations

Schema changes are applied by the one-shot `migrate` service, never by the API at start-up. To run
them by hand: `docker compose run --rm migrate`. Create a new migration from the backend directory
with `alembic revision -m "describe the change"` and review it before committing.

### Backups

All state is in the `postgres_data` volume. For a simple logical backup:

```bash
docker compose exec postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > backup.sql
```

Treat the dump as sensitive. There is no automated backup or retention policy yet.

## Before exposing it beyond your machine

This stack is a development and demonstration setup. Before it faces a network:

1. **Terminate TLS in front of it** (a reverse proxy, Azure Front Door or Application Gateway) and
   have that layer set `Strict-Transport-Security`.
2. **Set `ENVIRONMENT=production` and `AUTH_MODE=entra`**, with a real Entra app registration (below).
   The API refuses to start in production with dev auth, SQLite or the template password. Until
   browser sign-in is built, the dashboard cannot be used against such an API.
3. **Use a strong, unique database password** and keep `.env` out of version control. In Azure, use
   Key Vault and managed identities instead of a file.
4. **Do not publish the database port.** Remove the `postgres` `ports` entry if you do not need
   host access.
5. **Add rate limiting at the proxy.** The API limits investigations per analyst, but in memory and
   per process; it does not limit anything else, and it does not slow unauthenticated requests. Use
   a shared limiter at the proxy, especially with more than one backend replica.
6. **Keep provider keys in a secret store** (Key Vault in Azure), give them to the backend only, and
   rotate them if they leak. Review the provider terms for your use before sending real indicators.
7. **Monitor and back up.** Ship the JSON logs somewhere durable and schedule database backups. The
   `audit_logs` table is append-only through the application and database triggers, but a database
   superuser can still remove it or its triggers: restrict who has that role, and back it up.

## Entra ID setup (for `AUTH_MODE=entra`)

The API validates v2.0 access tokens issued by your tenant. In the Entra admin centre:

1. Register an application that represents the API.
2. Make it issue **v2.0 access tokens** (set the requested access token version to 2 in the app
   registration's manifest).
3. Define **app roles** with the values `Admin`, `SecurityAnalyst` and `User`, and assign them to
   users or groups. The API reads them from the token's `roles` claim and ignores unknown values.
4. Set `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` (and `ENTRA_AUDIENCE` if your tokens use a different
   audience) in the environment.

Browser sign-in (MSAL) is not part of the frontend yet, so tokens must currently be obtained by
other means when testing against a real tenant, and the dashboard shows "Not signed in" against such
an API. This path has not been exercised against a real
tenant; it is covered only by tests that use generated signing keys.

## Azure (planned, not built)

The intended shape, from the project specification: Azure Container Apps or App Service for the
containers, Azure Database for PostgreSQL, Blob Storage for encrypted files, Key Vault for
server-side secrets, Entra ID for identity, and Azure Monitor / Application Insights for telemetry,
described as infrastructure as code (Bicep or Terraform) in `infra/`. None of it exists yet.

## Verification status

What was actually run while building Phases 1 to 3, and what was not. The build machine had no
Docker.

| Item | Result |
| --- | --- |
| Backend tests | 787 passing and 1 skipped. The suite runs on SQLite and on a real PostgreSQL 16.2; the skip is intentional (SQLite has no `TRUNCATE`). SQLite alone gives 615 passing, because the PostgreSQL variants skip without `TEST_DATABASE_URL`. Line coverage 98%. |
| Backend static checks | `ruff check`, `ruff format --check`, `bandit` and `pip-audit` all clean. |
| Frontend checks | Type check, ESLint, 154 unit and component tests (in 23 files) and the production build all pass, and `npm audit` reports no vulnerabilities. CI runs the same checks on every push. |
| Dashboard in a real browser | Headless Microsoft Edge drove the production bundle against the live API on PostgreSQL 16.2 (`AUTH_MODE=dev`, no provider keys). The bundle was served by a small Node server standing in for nginx: it sends the same headers and Content Security Policy and proxies `/api`, `/health` and `/ready`. All 24 checks passed: navigation, the skip link and where focus lands, a rejected value showing the API's 422 message and its reference, investigating an indicator, opening and re-checking the saved record, the list with search and filters kept in the address, Back, a bookmarked deep link, the status page, an unknown route, a malformed id sending no request, and a 375 px wide screen without sideways scrolling. The browser reported no CSP violations. Provider evidence was not available, so the only investigation result seen live was "Not assessed"; the screens for real evidence were checked in the browser with made-up example data and by component tests. |
| Database and API on PostgreSQL | Alembic upgrade, downgrade and upgrade again (both migrations) on PostgreSQL 16.2. A live server against it answered `/health`, `/ready` and `/api/v1/me`, and (without provider keys) the intel endpoints: investigate, refused private and hostile input (422, audited without the input), list, stats and an unknown id (404). The audit table refused a `DELETE`. Provider calls were not part of this check. |
| Provider adapters (AbuseIPDB, OTX) | Tested against recorded response shapes through a stub HTTP transport. **Never called against the live services.** Endpoints, headers and the main fields were checked against AbuseIPDB's public documentation and AlienVault's own client library; the OTX pulse-level fields are not confirmed against a live response. |
| Compose and `.env.example` against the settings | A test parses both files and fails if they drift from the application's defaults, if the keys reach the migration job, or if forwarded headers are trusted from public networks by default. |
| nginx configuration | Syntax checked and exercised with a real nginx 1.30.6 build (using a copy that differs only in listen address, document root and upstream): security headers appear once, caching and gzip, SPA fallback, 404 for missing assets, proxying of the API with the error envelope intact, correlation-ID replacement and the 413 body limit. |
| `docker-compose.yml` | Validated against the Compose specification JSON schema. **Never run.** |
| Dockerfiles | **Never built.** The base image tags were confirmed to exist. |
| GitHub Actions workflow | `actionlint` clean; pinned action SHAs confirmed to match their release tags. **Never run on GitHub.** |
| `dependabot.yml` | Validated against its published schema. |
| Entra token validation against a real tenant | **Not tested.** |

The first end-to-end proof of the containers is the `docker` job in CI, which builds the images,
starts the stack and checks `/ready`, `/health`, `/api/v1/me`, the SPA fallback and the CSP header.
If you run Compose locally and something fails, that is more likely to be a defect in the container
files than in the application, and a report is welcome.

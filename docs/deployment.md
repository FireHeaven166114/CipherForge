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

Open <http://localhost:3000>. `docker compose down` stops the stack and keeps the data;
`docker compose down --volumes` also deletes the database.

### Configuration

Compose reads `.env` for substitution and passes the relevant values to the containers. The template
selects `ENVIRONMENT=development` and `AUTH_MODE=dev` so the stack works out of the box. If you omit
them entirely, the secure defaults apply and the API will refuse to start until Entra is configured.

`DATABASE_URL` is built by Compose from `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`.
Because the password sits inside a URL, keep it to letters and digits.

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
   The API refuses to start in production with dev auth, SQLite or the template password.
3. **Use a strong, unique database password** and keep `.env` out of version control. In Azure, use
   Key Vault and managed identities instead of a file.
4. **Do not publish the database port.** Remove the `postgres` `ports` entry if you do not need
   host access.
5. **Add rate limiting** at the proxy until the API has its own (Phase 2).
6. **Monitor and back up.** Ship the JSON logs somewhere durable and schedule database backups.

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
other means when testing against a real tenant. This path has not been exercised against a real
tenant; it is covered only by tests that use generated signing keys.

## Azure (planned, not built)

The intended shape, from the project specification: Azure Container Apps or App Service for the
containers, Azure Database for PostgreSQL, Blob Storage for encrypted files, Key Vault for
server-side secrets, Entra ID for identity, and Azure Monitor / Application Insights for telemetry,
described as infrastructure as code (Bicep or Terraform) in `infra/`. None of it exists yet.

## Verification status

What was actually run while building Phase 1, and what was not. The build machine had no Docker.

| Item | Result |
| --- | --- |
| Backend tests | 79 passing against a real PostgreSQL 16.2; 78 passing and 1 skipped (the PostgreSQL migration test) on SQLite alone. Coverage 95%. |
| Backend static checks | `ruff check`, `ruff format --check`, `bandit` and `pip-audit` all clean. |
| Frontend checks | Type check, ESLint, 25 unit tests and the production build all pass. `npm audit` was clean when last run; CI runs it on every push. |
| API against PostgreSQL | Alembic upgrade, downgrade and upgrade again; `/health`, `/ready` and `/api/v1/me` served correctly. |
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

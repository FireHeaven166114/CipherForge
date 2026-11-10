# Security

How CipherForge is hardened today, what is deliberately left for later, and how dependencies are
managed. The threats behind these controls are in [threat-model.md](threat-model.md).

Nothing here is a claim of production readiness. CipherForge is a lab and portfolio project, and
this document says what is and is not covered.

## Principles

These come from the project specification and are applied as design rules:

1. Least privilege and explicit authorisation; deny by default.
2. Secure defaults and fail-closed behaviour for anything sensitive.
3. Validate input, never echo it, and keep errors generic.
4. Never hard-code secrets, and never write them to logs.
5. Use established libraries and protocols; never invent cryptography or authentication.
6. Treat external intelligence as evidence, not truth.
7. Recommend response actions; do not take them automatically.

## Implemented controls (Phase 1)

### Configuration and secrets

| Control | Detail |
| --- | --- |
| Environment-only secrets | Read from environment variables or a git-ignored `.env`. `.env.example` holds placeholders only. |
| Fail closed | Invalid settings stop the API at startup. Messages name the setting and never its value. |
| Safe production profile | `ENVIRONMENT` defaults to `production`. Production refuses `AUTH_MODE=dev`, requires PostgreSQL, rejects a `DATABASE_URL` that still contains `CHANGE_ME`, and disables `/docs`. |
| No wildcard CORS | `CORS_ORIGINS=*` is rejected. CORS is off unless origins are listed, and credentials are never allowed. |
| Typed secrets | Secret settings are `SecretStr`, so `repr()` and `str()` never show them. |

### Logging

- One JSON line per event with a correlation ID. Query strings and request bodies are never logged.
- A redaction filter removes JWTs, `Bearer` and `Basic` credentials, credentials inside URLs,
  `api_key`/`token`/`secret`/`password`-style `name=value` pairs, and the exact values of the
  configured secrets.
- Redaction is a safety net, not a licence to log secrets; code should not log them in the first
  place. A test starts the API against an unreachable PostgreSQL URL and asserts the password
  appears in neither the logs nor any response.

### Authentication and authorisation

- Microsoft Entra ID access tokens (OIDC/OAuth 2.0). No custom protocol, no local passwords.
- RS256 only. The `alg` header is not trusted: HS256 key-confusion and `alg: none` tokens are
  rejected (both are covered by tests).
- Required claims `exp`, `iss`, `aud` and `sub`. The `tid` claim must match the configured tenant.
  Clock skew is limited to 60 seconds and oversized tokens are rejected before parsing.
- Signing keys come from the tenant's JWKS endpoint with a one-hour cache and a 5-second timeout.
  A key-service outage returns `503`, not `401`, so clients can tell the two apart.
- Role-based access with `require_roles(...)`: `Admin`, `SecurityAnalyst`, `User`. Failures are
  logged without the token.

### HTTP hardening

| Where | Headers / limits |
| --- | --- |
| API | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. |
| nginx | The same three headers plus `Content-Security-Policy` (`default-src 'self'`, no inline scripts or styles, `frame-ancestors 'none'`, `object-src 'none'`), `Permissions-Policy` and `Cross-Origin-Opener-Policy`. `server_tokens off`, request bodies limited to 64 KB. |

The built frontend contains no inline scripts or styles, which is what allows a strict CSP. The
nginx configuration was exercised against a real nginx 1.30.6 build; see
[deployment.md](deployment.md#verification-status).

HSTS and TLS are intentionally **not** set by this stack: they belong to the TLS-terminating proxy
or load balancer in front of it. Sending HSTS over plain HTTP is meaningless, and enabling it on a
local hostname can lock a browser out.

### Errors

One envelope for every error. Validation errors list location, message and type but never the
submitted value. Unexpected exceptions become a generic 500, with the detail only in the server
log. Correlation IDs from clients are accepted only if they match a strict pattern, which prevents
log injection.

### Containers and network

- Backend and frontend images run as non-root users (UID 10001 for the API, the unprivileged nginx
  image for the frontend).
- All Linux capabilities are dropped and `no-new-privileges` is set on every service. The API and
  migration containers also use a read-only root filesystem with a small `tmpfs` for `/tmp`.
- Published ports are bound to `127.0.0.1`. PostgreSQL is reachable from the host only on loopback
  and is not exposed on any other interface.
- Healthchecks gate start-up order (database, then migrations, then API, then frontend).

### Supply chain and automation

- Direct dependencies are exactly pinned. The frontend lockfile is committed and does not embed any
  registry mirror URLs (`omit-lockfile-registry-resolved`), so `npm ci` works anywhere.
- CI runs ruff, bandit, `pip-audit`, `npm audit`, the full test suites, and builds the images.
  GitHub Actions are pinned to commit SHAs, workflow permissions are `contents: read`, and
  checkout does not persist credentials.
- Dependabot is configured for pip, npm, Docker, Compose and GitHub Actions.

## Dependency management

Pins and the reasoning behind the non-obvious ones:

| Dependency | Decision |
| --- | --- |
| Python packages | Direct dependencies pinned in `requirements.txt`; transitive packages float within them. `pip-audit` checks the resolved set in CI. A hash-locked file (`pip-compile --generate-hashes`) is a possible later hardening. |
| `httpx2` | The maintained continuation of HTTPX. Starlette's test client prefers it, and the Phase 2 provider adapters use it. |
| TypeScript 6.0.3 | The latest stable `typescript-eslint` does not support TypeScript 7 yet. Revisit when it does. |
| `minimatch` override (`11.0.4`) | Dev-tooling dependencies pulled in a `minimatch` version affected by a denial-of-service advisory (GHSA-g3hv-75wg-m249). The override keeps `npm audit` at zero findings. Remove it once upstream packages update. |
| Node 24 image | The toolchain needs a recent Node (Vitest 5 requires 22.12 or newer, and `package.json` sets `engines` to 22.22 or newer); CI and the Docker build use Node 24. |

Update flow: Dependabot opens a pull request, CI runs every check and the stack smoke test, and a
human reviews the change before merging.

## Not implemented yet

| Gap | Planned |
| --- | --- |
| Rate limiting and brute-force protection on API routes | Phase 2 (in-process limiter; Redis once there is more than one instance). |
| Audit log table with protected, append-oriented storage | Phase 2 (`IOC_LOOKUP`), extended in later phases. |
| Sign-in in the browser (MSAL) | With the SOC dashboard work. |
| CodeQL and Trivy (container and filesystem) scanning | Phase 12, once the repository is hosted. |
| SBOM generation and image signing | Phase 12. |
| Azure Key Vault, managed identities, Azure Monitor | Phase 11. |
| Resource-level authorisation (per-file, per-incident) | With each feature. |
| Vault cryptography | Requires a STRIDE threat model and review first. Nothing is implemented. See [encryption-design.md](encryption-design.md). |

## Responsible use

Run packet capture, load generation and honeypots only on systems and networks you own or are
explicitly authorised to test. Do not collect third-party traffic or sensitive data. IP reputation
and geolocation are evidence about an address, not about a person, and must never be presented as
the location or identity of an attacker.

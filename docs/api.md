# API reference

Version 1 of the REST API. Interactive OpenAPI docs are served at `/docs` when
`ENVIRONMENT` is not `production`; they are disabled in production.

Endpoint names for later phases are proposals, not frozen contracts. They are listed at the end and
marked **not implemented**.

## Conventions

- **Versioning.** Business endpoints live under `/api/v1`. The operational probes `/health` and
  `/ready` are unversioned so orchestrators can rely on them.
- **Format.** JSON in and out.
- **Authentication.** `Authorization: Bearer <Microsoft Entra ID access token>`. The probes are
  public. With `AUTH_MODE=dev` (never in production) no token is needed.
- **Correlation ID.** Every response carries `X-Correlation-ID`. A client may supply its own value
  matching `[A-Za-z0-9._-]{8,64}`; anything else is replaced. Quote the ID when reporting a problem:
  it appears in the server logs for that request.
- **Caching.** Responses are sent with `Cache-Control: no-store`.

### Error format

Every error, including unknown routes and unexpected failures, uses one envelope:

```json
{
  "error": {
    "code": "forbidden",
    "message": "Insufficient permissions.",
    "correlation_id": "0f3c9a1e5b7d4c2a8e6f1b3d5a7c9e0f",
    "details": []
  }
}
```

`details` is present only for validation errors and contains `loc`, `msg` and `type` for each
problem. Submitted values are never echoed back, and server errors never expose internals.

| Status | `code` | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | The request is malformed. |
| 401 | `unauthorized` | Missing, invalid or expired token. Includes `WWW-Authenticate: Bearer`. |
| 403 | `forbidden` | Authenticated, but the role is not allowed. |
| 404 | `not_found` | Unknown route or resource. |
| 405 | `method_not_allowed` | The route does not support that method. |
| 413 | `payload_too_large` | Body over the limit (nginx allows 64 KB). |
| 422 | `validation_error` | The request body or parameters failed validation. |
| 429 | `rate_limited` | Reserved for rate limiting (planned for Phase 2). |
| 500 | `internal_error` | Unexpected failure; the message is always generic. |
| 503 | `service_unavailable` | A dependency is unavailable (for example the token key service). |

## Implemented endpoints

### `GET /health`

Liveness. Does not touch any dependency, so it stays green while the database is down.

```json
{ "status": "ok", "service": "cipherforge-api", "version": "0.1.0" }
```

### `GET /ready`

Readiness. Runs `SELECT 1` against the database.

- `200`: `{ "status": "ready", "checks": { "database": "ok" } }`
- `503`: `{ "status": "not_ready", "checks": { "database": "unavailable" } }`

The response never includes the underlying error; the cause is logged as `database_unavailable`.

### `GET /api/v1/me`

The authenticated caller. Any valid identity may call it.

```json
{
  "subject": "dev-user",
  "name": "Local Developer",
  "roles": ["SecurityAnalyst"],
  "auth_mode": "dev"
}
```

Roles are `Admin`, `SecurityAnalyst` and `User`. In `entra` mode they come from the token's `roles`
claim.

## Roles

| Role | Scope |
| --- | --- |
| `Admin` | Platform configuration and user/role administration. |
| `SecurityAnalyst` | IOC investigation, alerts, incidents, analytics and case workflow. |
| `User` | Authorised file upload, sharing and download (Vault, not built). |

Having a role is necessary but not sufficient for per-resource access (for example another user's
file). Resource-level checks are part of the feature that needs them.

## Planned endpoints (not implemented)

| Phase | Endpoint | Purpose |
| --- | --- | --- |
| 2 | `POST /api/v1/intel/investigate` | Look up one IOC, normalise, store and score it. |
| 2 | `GET /api/v1/intel/indicators/{id}` | One stored indicator with its evidence. |
| 2 | `GET /api/v1/intel/indicators` | Search and filter stored indicators. |
| 5-7 | `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}` | Alerts. |
| 8 | `POST /api/v1/incidents`, `GET /api/v1/incidents/{id}` | Incidents. |
| 9 | Vault endpoints | Designed only after the encryption threat model exists. |

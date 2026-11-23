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
| 409 | `conflict` | The state changed under the request: an indicator was deleted while it was being investigated. |
| 413 | `payload_too_large` | Body over the limit (nginx allows 64 KB). |
| 422 | `validation_error` | The request body or parameters failed validation. |
| 429 | `rate_limited` | Too many investigations. `Retry-After` gives the seconds to wait. |
| 500 | `internal_error` | Unexpected failure; the message is always generic. |
| 503 | `service_unavailable` | A dependency is unavailable (for example the token key service). |

## Implemented endpoints

### `GET /health`

Liveness. Does not touch any dependency, so it stays green while the database is down.

```json
{ "status": "ok", "service": "cipherforge-api", "version": "0.5.0" }
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

## Threat-intelligence endpoints

All routes are under `/api/v1/intel` and need the `SecurityAnalyst` or `Admin` role: a request without
a valid token gets `401`, and one with another role gets `403`. How results are produced is explained in
[threat-intelligence.md](threat-intelligence.md). The dashboard uses `POST /investigate`, `GET /overview`,
`GET /indicators`, `GET /indicators/{id}`, `DELETE /indicators/{id}`, `POST /indicators/bulk-delete` and
`GET /stats` (to warn when the providers are simulated), and its status page uses `/health` and `/ready`.

### `POST /api/v1/intel/investigate`

Normalise an indicator, query the configured providers (or reuse fresh cached answers), store the
answers, score the indicator and audit the lookup.

| Field | Type | Notes |
| --- | --- | --- |
| `indicator` | string, 1 to 2048 characters | An IPv4 or IPv6 address, a domain, an `http` or `https` URL, or a SHA-256 hash. Defanged input such as `example[.]com` is accepted. |
| `refresh` | boolean, default `false` | Ask the providers again even though a cached answer is fresh. Honoured only for answers at least 60 seconds old. |

Unknown fields are rejected. Outcomes:

- `200`: an investigation, shown below.
- `422 validation_error`: the indicator is not accepted (a private address, an unsupported hash type
  and so on). The message says what is wrong and never repeats the input. The attempt is still
  audited, as `rejected`.
- `429 rate_limited`: too many investigations. The limit is per user (default 30 a minute) and
  `Retry-After` gives the seconds to wait.
- `409 conflict`: another request deleted this indicator while the providers were being asked. The
  answers have nothing left to attach to and are dropped. The lookup is still audited (as `partial`),
  and investigating the value again stores it as a new indicator.

Example for `{"indicator": "malware[.]example[.]org"}`, abridged. The values are illustrative, and
OTX is the only provider configured:

```json
{
  "indicator": {
    "indicator_id": "6f1c7d52-3a0e-4c0b-9d57-2f6b3f0a9c11",
    "indicator_type": "domain",
    "indicator_value": "malware.example.org",
    "risk_score": 25,
    "classification": "low",
    "confidence": 35,
    "first_seen": "2025-11-20T09:30:00Z",
    "last_seen": "2026-01-01T08:00:00Z",
    "source_count": 1,
    "tags": ["phishing"],
    "status": "active",
    "created_at": "2026-01-02T10:15:30Z",
    "scored_at": "2026-01-02T10:15:30Z",
    "last_checked_at": "2026-01-02T10:15:30Z"
  },
  "providers": [
    {
      "provider": "abuseipdb",
      "display_name": "AbuseIPDB",
      "status": "unsupported",
      "freshness": null,
      "signal": null,
      "fetched_at": null,
      "evidence_at": null,
      "first_evidence_at": null,
      "cache_expires_at": null,
      "from_cache": false,
      "summary": {},
      "tags": [],
      "message": "AbuseIPDB does not accept domain indicators."
    },
    {
      "provider": "otx",
      "display_name": "AlienVault OTX",
      "status": "ok",
      "freshness": "fresh",
      "signal": 0.55,
      "fetched_at": "2026-01-02T10:15:30Z",
      "evidence_at": "2026-01-01T08:00:00Z",
      "first_evidence_at": "2025-11-20T09:30:00Z",
      "cache_expires_at": "2026-01-02T22:15:30Z",
      "from_cache": false,
      "summary": { "pulse_count": 3, "pulses_analyzed": 3, "top_pulses": ["..."] },
      "tags": ["phishing"],
      "message": null
    }
  ],
  "score": {
    "methodology": "intel-risk-v1",
    "score": 25,
    "classification": "low",
    "confidence": 35,
    "answered_sources": 1,
    "contributing_sources": 1,
    "supporting_sources": 1,
    "factors": [
      {
        "code": "provider:otx",
        "label": "AlienVault OTX evidence",
        "points": 25,
        "detail": "Evidence strength 0.55, recency weight 1.0 (latest activity 2026-01-01); up to 45 points."
      }
    ],
    "uncertainty": [
      "No internal telemetry was available; this score reflects external provider evidence only.",
      "Only AlienVault OTX returned an answer, so this result could not be cross-checked against another source."
    ],
    "recommended_actions": ["Treat this as context, not a finding. Do not act on this indicator alone."],
    "scored_at": "2026-01-02T10:15:30Z"
  },
  "internal_evidence": {
    "available": false,
    "message": "CipherForge has no internal telemetry (Sentinel, SOC, Case) connected yet, so no internal sightings are included."
  }
}
```

| Field | Meaning |
| --- | --- |
| `classification` | `informational`, `low`, `medium`, `high` or `critical`, always lower case. |
| `status` (indicator) | `active` while at least one provider answer is fresh, otherwise `stale`. |
| `providers[].status` | `ok`, `no_data`, `not_configured`, `unsupported`, `rate_limited`, `error` or `not_queried`. |
| `providers[].freshness` | `fresh` inside the provider's cache time, `stale` after it, `null` when there is no answer. |
| `providers[].signal` | Strength of that provider's evidence from 0 to 1. Not a probability of malice. |
| `providers[].from_cache` | `true` when the answer came from storage rather than a new provider call. |
| `providers[].summary` | Whitelisted facts; the keys depend on the provider. Free text in it is community-supplied: show it as text, never as markup. |
| `score.factors` | The named contributions. Their `points` add up to `score`. |
| `score.answered_sources` | How many providers gave an answer. When it is `0` the score says nothing about the indicator (not assessed, not clean). Show that state explicitly. |
| `score.uncertainty`, `score.recommended_actions` | What is not known, and advice for the analyst. CipherForge recommends actions and never takes them. |
| `internal_evidence` | Always unavailable until internal telemetry exists. |

### `GET /api/v1/intel/indicators/{indicator_id}`

One stored indicator in the same shape as above. It is read-only: it never calls a provider and is
not audited. `404 not_found` for an unknown id and `422` when the id is not a UUID.

### `GET /api/v1/intel/indicators`

Search stored indicators. Query parameters, all optional:

| Parameter | Default | Notes |
| --- | --- | --- |
| `type` | any | `ipv4`, `ipv6`, `domain`, `url` or `sha256`. |
| `classification` | any | `informational`, `low`, `medium`, `high` or `critical`. Repeat it to match several, for example `?classification=high&classification=critical`. |
| `assessed` | any | `true` keeps indicators that at least one provider answered for. `false` keeps those no provider answered for, whose score of `0` says nothing about them (not assessed, not clean). |
| `q` | none | Case-insensitive substring of the indicator value, up to 256 characters. |
| `sort` | `recent` | `recent` (most recently investigated first) or `risk` (highest score first). |
| `limit` | `25` | 1 to 100. |
| `offset` | `0` | 0 to 10000. |

Response: `{ "items": [ ...indicators... ], "total": 12, "limit": 25, "offset": 0 }`, where each item has
the `indicator` fields shown above.

`classification` matches score bands only. An indicator no provider answered for scores 0, so it
falls in `informational` even though nothing was checked. Combine the two filters to tell them
apart: the dashboard sends `assessed=true` with a band (High and critical together are
`classification=high&classification=critical&assessed=true`), and `assessed=false` alone for "Not assessed".

### `DELETE /api/v1/intel/indicators/{indicator_id}`

Deletes one stored indicator and every provider answer stored for it. The rows are removed from the
database; nothing is only hidden or marked. The answer has the same body as the bulk endpoint below, with
the id in `deleted`. `404 not_found` when no such indicator is stored (so a second delete of the same id
is a `404`) and `422` when the id is not a UUID.

### `POST /api/v1/intel/indicators/bulk-delete`

Deletes several indicators the same way, in one transaction. It is a `POST` with a body rather than a
`DELETE`, because the body of a `DELETE` has no defined meaning (some proxies drop it) and up to 100 ids
do not belong in a URL.

| Field | Type | Notes |
| --- | --- | --- |
| `indicator_ids` | array of 1 to 100 UUIDs | Repeated ids count once. Unknown fields are rejected. |

There is deliberately no "delete everything that matches these filters": a request removes only what it
names, so a filter that matches more than the analyst saw can never take extra indicators with it. The
dashboard sends the ids of the rows the analyst ticked.

```json
{
  "deleted": ["6f1c7d52-3a0e-4c0b-9d57-2f6b3f0a9c11"],
  "not_found": ["0b1e5d7c-8a4f-4f43-9d0a-1c2a6d6b7e33"],
  "observations_removed": 2
}
```

| Field | Meaning |
| --- | --- |
| `deleted` | The indicators this request removed, in the order they were sent. |
| `not_found` | Ids that matched nothing: they were deleted already (perhaps by another analyst a moment ago) or were never stored. This is **not** an error. The response is still `200`, so repeating a request is harmless. |
| `observations_removed` | How many stored provider answers went with the deleted indicators. |

What deleting does, and what it does not:

- It removes the `threat_indicators` rows and their `threat_observations` rows, so the indicators are gone
  from the list, the overview, the search and the detail endpoint. Investigating the same value again
  stores a new indicator with a new id and asks the providers again.
- It never edits the audit trail, which is append-only (see [security.md](security.md)). Each deleted
  indicator adds one `IOC_DELETE` audit row (actor, target `type:value`, source address, and how many
  answers went with it), written in the same transaction as the deletion. The earlier `IOC_LOOKUP` rows
  stay as they were. **The audit rows still name the value**, and no endpoint deletes or edits them.
- The overview's lookup figures (`lookups_24h`, `series[].lookups`, `activity`) are counted from the audit
  trail, so they do not drop. Its indicator figures (`total_indicators`, `new_indicators_24h`,
  `top_risk`, `recent`, the matrix and the breakdowns) are counted from what is stored, so they do.
- Both routes need the `SecurityAnalyst` or `Admin` role. Neither calls a provider.

### `GET /api/v1/intel/stats`

Counts for an overview screen:

```json
{
  "total_indicators": 12,
  "by_classification": { "informational": 3, "low": 4, "medium": 3, "high": 2, "critical": 0 },
  "by_type": { "ipv4": 5, "ipv6": 0, "domain": 4, "url": 1, "sha256": 2 },
  "lookups_last_24h": 7,
  "providers": [
    { "name": "abuseipdb", "display_name": "AbuseIPDB", "configured": true, "supported_types": ["ipv4", "ipv6"], "simulated": false },
    { "name": "otx", "display_name": "AlienVault OTX", "configured": false, "supported_types": ["ipv4", "ipv6", "domain", "url", "sha256"], "simulated": false }
  ]
}
```

`lookups_last_24h` counts audited lookups that succeeded or partly succeeded. `configured` says only
whether a key is set; keys are never returned. `simulated` is `true` only for the development demo
server (see [Try it without keys](../README.md#try-it-without-api-keys)), whose providers return invented
answers; the dashboard then shows a banner so no one mistakes them for real intelligence.

### `GET /api/v1/intel/overview`

Everything the overview dashboard draws, in one read-only request. It is computed from stored
indicators, the latest answer each provider gave for each indicator and the lookup audit trail. It
never calls a provider and is not audited.

| Field | Meaning |
| --- | --- |
| `generated_at` | When the figures were computed. |
| `kpis` | `total_indicators`; `new_indicators_24h` and `new_indicators_prev_24h` (the 24 hours before that); `lookups_24h` and `lookups_prev_24h`; `high_risk_indicators` (high plus critical, among assessed indicators); `critical_indicators`; `not_assessed_indicators`. |
| `by_classification` | Indicators per band, plus `not_assessed` for those no provider answered for. |
| `by_type` | Indicators per type. |
| `matrix` | One row per type with `counts` per band and `not_assessed` (types by risk). |
| `series` | The last 14 UTC days, oldest first, today last and zero days included: `day`, `lookups`, `high_risk_lookups`, `new_indicators`. |
| `activity` | The last 7 UTC days, each with `hours`: 24 lookup counts, one per UTC hour. |
| `countries` | Up to 40 entries. This is the country a provider reports for an IP address's registration. It is **not** where an attacker is. |
| `malware_families`, `attack_techniques`, `tags` | Up to 10 entries each, most frequent first. |
| `top_risk`, `recent` | Up to 8 indicators: highest score first, and most recently updated first. |
| `providers` | As in `/stats`. |
| `scope` | How much was read: `series_days`, `activity_days`, `lookups_scanned`, `lookups_truncated`, `answers_scanned`, `answers_truncated`. |

Every entry in `countries`, `malware_families`, `attack_techniques` and `tags` has `key`, `count` (distinct
indicators whose latest provider answer carries the value), `max_risk` and up to 5 `samples` of the
highest-risk indicators, each with `indicator_id`, `indicator_type`, `indicator_value`, `risk_score`
and `classification`. A lookup is a completed investigation, including a re-check; an input that was
rejected is not one. The attribute breakdowns read at most the 2,000 most recent successful provider answers and
the lookup figures at most 20,000 audit rows from the 14-day window. When a limit is reached the matching
`scope` flag is `true`, and the dashboard says so instead of implying the figures are complete.

## Trying it from a terminal

With the API running, the fastest way to explore it is the interactive page at
<http://127.0.0.1:8000/docs> (disabled when `ENVIRONMENT=production`). The examples below make the
same calls from a terminal.

Windows (PowerShell):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/api/v1/me
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/intel/investigate -ContentType 'application/json' -Body '{"indicator": "8.8.8.8"}' | ConvertTo-Json -Depth 8
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/intel/indicators?sort=risk&limit=5" | ConvertTo-Json -Depth 5
```

macOS or Linux:

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/v1/me
curl -s -X POST -H "Content-Type: application/json" -d '{"indicator": "8.8.8.8"}' http://127.0.0.1:8000/api/v1/intel/investigate
curl -s "http://127.0.0.1:8000/api/v1/intel/indicators?sort=risk&limit=5"
```

(On Windows, `curl.exe` also works, but its quoting rules differ between PowerShell versions, so these
examples use `Invoke-RestMethod`.)

> **Always read `score.answered_sources`.** With no provider keys configured, `/investigate` answers
> `risk_score: 0` and `classification: "informational"` because it has no evidence at all — that is
> **not** the same as "clean". `answered_sources: 0` means no provider answered, so the result is
> unknown. The dashboard makes this check for you and shows **Not assessed**; a script of your own
> must make the same check.

### Deleting indicators

These commands investigate `8.8.8.8` and then delete exactly that indicator, exercising the `DELETE`
route described above:

Windows (PowerShell):

```powershell
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/intel/investigate -ContentType 'application/json' -Body '{"indicator": "8.8.8.8"}'
Invoke-RestMethod -Method Delete -Uri "http://127.0.0.1:8000/api/v1/intel/indicators/$($result.indicator.indicator_id)"
```

macOS or Linux (copy the `indicator_id` from the first answer into the second command):

```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"indicator": "8.8.8.8"}' http://127.0.0.1:8000/api/v1/intel/investigate
curl -s -X DELETE http://127.0.0.1:8000/api/v1/intel/indicators/PASTE-THE-ID-HERE
```

To delete several at once, send their ids to `bulk-delete` (up to 100 per request):

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/intel/indicators/bulk-delete -ContentType 'application/json' -Body '{"indicator_ids": ["PASTE-ID-1", "PASTE-ID-2"]}'
```

There is no API call that deletes audit entries: the audit trail is append-only by design (see
[security.md](security.md)).

## Roles

| Role | Scope |
| --- | --- |
| `Admin` | Platform configuration and user/role administration. |
| `SecurityAnalyst` | IOC investigation (built), alerts, incidents, analytics and case workflow. |
| `User` | Authorised file upload, sharing and download (Vault, not built). |

Having a role is necessary but not sufficient for per-resource access (for example another user's
file). Resource-level checks are part of the feature that needs them.

## Planned endpoints (not implemented)

| Phase | Endpoint | Purpose |
| --- | --- | --- |
| 5-7 | `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}` | Alerts. |
| 8 | `POST /api/v1/incidents`, `GET /api/v1/incidents/{id}` | Incidents. |
| 9 | Vault endpoints | Designed only after the encryption threat model exists. |

# API reference

Version 1 of the REST API. Interactive OpenAPI docs are served at `/docs` when
`ENVIRONMENT` is not `production`; they are disabled in production.

| Group | Paths | Who may call it |
| --- | --- | --- |
| [Probes and caller](#implemented-endpoints) | `/health`, `/ready`, `/api/v1/me` | The probes: anyone. `/api/v1/me`: any valid identity. |
| [Threat intelligence](#threat-intelligence-endpoints) | `/api/v1/intel/...` | `SecurityAnalyst` or `Admin`. |
| [Network monitoring](#network-monitoring-endpoints) | `/api/v1/network/...` | `SecurityAnalyst` or `Admin`. |
| [Encrypted files](#owner-endpoints) | `/api/v1/files/...` | Any signed-in role (`User`, `SecurityAnalyst` or `Admin`), for the caller's own files. |
| [Share links](#share-link-endpoints) | `/api/v1/shares/{token}...` | Nobody signs in. The link token in the path is the credential. |

[Roles](#roles) has the full matrix.

Endpoint names for later phases are proposals, not frozen contracts. They are listed at the end and
marked **not implemented**.

## Conventions

- **Versioning.** Business endpoints live under `/api/v1`. The operational probes `/health` and
  `/ready` are unversioned so orchestrators can rely on them.
- **Format.** JSON in and out, with two exceptions. The two upload endpoints (`POST /api/v1/files` and
  `POST /api/v1/network/pcap`) take the raw bytes of the file as the body
  (`Content-Type: application/octet-stream`, the file name in an `X-File-Name` header), and a share
  download returns the decrypted bytes. A `multipart/form-data` upload is refused with `415`.
- **Authentication.** `Authorization: Bearer <Microsoft Entra ID access token>`. The probes and the
  share-link endpoints under `/api/v1/shares/{token}` are public. With `AUTH_MODE=dev` (never in
  production) no token is needed: every request is the fixed identity `dev-user`, with the roles
  listed in `DEV_AUTH_ROLES` (default `SecurityAnalyst`).
- **Correlation ID.** Every response carries `X-Correlation-ID`. A client may supply its own value
  matching `[A-Za-z0-9._-]{8,64}`; anything else is replaced. Quote the ID when reporting a problem:
  it appears in the server logs for that request.
- **Caching and headers.** Responses are sent with `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`,
  unless the route sets a value of its own. A share download does ([the headers are listed
  below](#downloading-through-a-link)).
- **Timestamps.** Every timestamp in a JSON body is UTC, timezone-aware and in ISO 8601 form, for
  example `2026-01-02T10:15:30Z`. Text written for people is in Indian Standard Time instead, as
  `DD-MM-YYYY hh:mm:ss A IST` (for example `25-11-2026 09:49:00 AM IST`): the `explanation` of a
  network alert, the dates inside a score factor's `detail` and the uncertainty notes, and the
  per-day buckets of the overview (an IST day starts at 00:00 IST). The dashboard converts the UTC
  values to IST in the browser. [Time handling](architecture.md#time-handling-utc-storage-ist-display)
  in the architecture document has the full rule.

### Rate limits

A refused request is answered with `429` and a `Retry-After` header (whole seconds, at least 1).
The limits are settings, counted in the memory of one API process over a sliding window (so they
start again when it restarts), and a refused request does not count against them. The defaults:

| Limit | Applies to | Counted per | Default | Setting |
| --- | --- | --- | --- | --- |
| Investigations | `POST /api/v1/intel/investigate`, `POST /api/v1/network/pcap`, `POST /api/v1/network/alerts/{alert_id}/enrich` and `GET /api/v1/network/interfaces?refresh=true`, together | Signed-in user | 30 a minute | `INVESTIGATE_RATE_LIMIT_PER_MINUTE` |
| File uploads | `POST /api/v1/files` | Signed-in user | 10 a minute | `FILE_UPLOAD_RATE_LIMIT_PER_MINUTE` |
| Share creation | `POST /api/v1/files/{file_id}/shares` | Signed-in user | 10 a minute | `SHARE_CREATE_RATE_LIMIT_PER_MINUTE` |
| Link requests | `GET /api/v1/shares/{token}` and both download routes, together | Client network (an IPv6 address counts as its /64 network) | 30 a minute | `SHARE_DOWNLOAD_RATE_LIMIT_PER_MINUTE` |
| Wrong passwords | `POST /api/v1/shares/{token}/download` | Each link, and each client network | 5 in 15 minutes | `SHARE_PASSWORD_ATTEMPT_LIMIT` |

The code is `rate_limited`, except for wrong passwords: `too_many_attempts`.

### Error format

Every error, including unknown routes and unexpected failures, uses one envelope:

```json
{
  "error": {
    "code": "forbidden",
    "message": "Insufficient permissions.",
    "correlation_id": "0f3c9a1e5b7d4c2a8e6f1b3d5a7c9e0f"
  }
}
```

`code` is stable: match on it, not on `message`. `details` is added only when there is something to
list. A validation error (`422 validation_error`, message `Request validation failed.`) carries one
entry for each problem, with `loc`, `msg` and `type`:

```json
"details": [
  { "loc": ["body", "indicator"], "msg": "String should have at least 1 character", "type": "string_too_short" }
]
```

Submitted values are never echoed back, and server errors never expose internals.

These are the generic codes, by status. Many routes return a more specific `code` for the same
status; the full list is in [Error codes](#error-codes).

| Status | `code` | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | The request is malformed. |
| 401 | `unauthorized` | Missing, invalid or expired token. Includes `WWW-Authenticate: Bearer`. |
| 403 | `forbidden` | Authenticated, but the role is not allowed. |
| 404 | `not_found` | Unknown route or resource. |
| 405 | `method_not_allowed` | The route does not support that method. |
| 409 | `conflict` | The state changed under the request: an indicator was deleted while it was being investigated. |
| 410 | `gone` | The resource existed and is no longer available. |
| 413 | `payload_too_large` | Body over a limit. In the Docker set-up nginx limits ordinary API request bodies to 64 KB. The two upload routes are allowed larger bodies there, and the API applies their own limits (`file_too_large`). |
| 415 | `unsupported_media_type` | The body is not in the format the route needs, for example a multipart upload. |
| 422 | `validation_error` | The request body or parameters failed validation. |
| 429 | `rate_limited` | A [rate limit](#rate-limits) was reached. `Retry-After` gives the seconds to wait. |
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

An indicator is an IP address, a domain, a URL or a file hash (MD5, SHA-1 or SHA-256). Four providers
can answer: AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox. [Which of them answers which
type](threat-intelligence.md#which-provider-answers-which-indicator-type) is in the threat-intelligence
document. A provider that does not apply or has no key never fails a request; its row in the response
says why ([below](#how-a-providers-result-is-reported)).

### `POST /api/v1/intel/investigate`

Normalise an indicator, query the configured providers (or reuse fresh cached answers), store the
answers, score the indicator and audit the lookup.

| Field | Type | Notes |
| --- | --- | --- |
| `indicator` | string, 1 to 2048 characters | An IPv4 or IPv6 address, a domain, an `http` or `https` URL, or a file hash: MD5, SHA-1 or SHA-256 (the type follows from the length). Defanged input such as `example[.]com` is accepted. |
| `refresh` | boolean, default `false` | Ask the providers again even though a cached answer is fresh. Honoured only for answers at least 60 seconds old. |

Unknown fields are rejected. Outcomes:

- `200`: an investigation, shown below.
- `422 validation_error`: the indicator is not accepted (a private address, a SHA-512 hash and so on).
  The message says what is wrong and never repeats the input. The attempt is still audited, as
  `rejected`.
- `429 rate_limited`: over the investigation [rate limit](#rate-limits) (per user, default 30 a
  minute, shared with some network routes). `Retry-After` gives the seconds to wait.
- `409 conflict`: another request deleted this indicator while the providers were being asked. The
  answers have nothing left to attach to and are dropped. The lookup is still audited (as `partial`),
  and investigating the value again stores it as a new indicator.

Example for `{"indicator": "malware[.]example[.]org"}`, abridged. The values are illustrative, and
OTX is the only provider configured (no key is set for VirusTotal or ThreatFox):

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
      "message": "AbuseIPDB does not accept domain indicators.",
      "verdict": null,
      "reason": null
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
      "message": null,
      "verdict": null,
      "reason": null
    },
    {
      "provider": "virustotal",
      "display_name": "VirusTotal",
      "status": "not_configured",
      "freshness": null,
      "signal": null,
      "fetched_at": null,
      "evidence_at": null,
      "first_evidence_at": null,
      "cache_expires_at": null,
      "from_cache": false,
      "summary": {},
      "tags": [],
      "message": "VirusTotal is not configured (no API key set).",
      "verdict": null,
      "reason": "not_configured"
    },
    {
      "provider": "threatfox",
      "display_name": "ThreatFox",
      "status": "not_configured",
      "freshness": null,
      "signal": null,
      "fetched_at": null,
      "evidence_at": null,
      "first_evidence_at": null,
      "cache_expires_at": null,
      "from_cache": false,
      "summary": {},
      "tags": [],
      "message": "ThreatFox is not configured (no API key set).",
      "verdict": null,
      "reason": "not_configured"
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
        "detail": "Evidence strength 0.55, recency weight 1.0 (latest activity 01-01-2026 01:30:00 PM IST); up to 45 points."
      }
    ],
    "uncertainty": [
      "No internal telemetry was available; this score reflects external provider evidence only.",
      "Only AlienVault OTX returned an answer, so this result could not be cross-checked against another source.",
      "VirusTotal is not configured, so it contributed no evidence.",
      "ThreatFox is not configured, so it contributed no evidence."
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
| `providers[].message` | A sentence for the analyst when the provider could not answer, or when an older answer is shown because the new lookup failed. `null` when the lookup worked. |
| `providers[].verdict` | VirusTotal and ThreatFox only; `null` for the others and when there is no answer. The provider's own label for the indicator: `malicious`, `suspicious`, `harmless`, `unknown` or `not_found`. It describes that provider's data and is not a CipherForge verdict. `harmless` and `not_found` never mean the indicator is safe. |
| `providers[].reason` | Why a lookup produced no answer: `not_configured`, `invalid_input`, `auth_failed`, `rate_limited`, `timeout`, `unavailable` or `malformed_response`. `null` when the provider answered, and for `unsupported`. |
| `score.factors` | The named contributions. Their `points` add up to `score`. |
| `score.answered_sources` | How many providers gave an answer. When it is `0` the score says nothing about the indicator (not assessed, not clean). Show that state explicitly. |
| `score.uncertainty`, `score.recommended_actions` | What is not known, and advice for the analyst. CipherForge recommends actions and never takes them. |
| `internal_evidence` | Always unavailable until internal telemetry exists. |

#### How a provider's result is reported

`providers` has one row for each of the four providers, always in the order AbuseIPDB, OTX,
VirusTotal, ThreatFox. A provider that cannot answer never fails the request: its row says why, in
`status`, `reason` and `message`. Nothing is sent to a provider that does not take the type of
indicator or has no key. `<Name>` below is the provider's display name.

| Situation | `status` | `reason` | `message` |
| --- | --- | --- | --- |
| The provider does not take this type of indicator | `unsupported` | `null` | `<Name> does not accept <type> indicators.` |
| No API key is set | `not_configured` | `not_configured` | `<Name> is not configured (no API key set).` |
| The provider says its quota is used up (HTTP 429) | `rate_limited` | `rate_limited` | `<Name> rate limit reached; try again later.`, or `...try again in about N seconds.` when the provider says how long |
| The provider rejects the key (HTTP 401 or 403) | `error` | `auth_failed` | `<Name> rejected the configured credentials.` |
| The provider rejects the request (HTTP 400 or 422) | `error` | `invalid_input` | `<Name> rejected the request as invalid (<status>).` |
| Any other HTTP status | `error` | `unavailable` | `<Name> returned an unexpected HTTP status (<status>).` |
| No answer in time | `error` | `timeout` | `<Name> did not respond in time.` |
| The provider cannot be reached | `error` | `unavailable` | `Could not reach <Name>.` |
| The answer is not JSON, is over 2 MiB or has an unexpected shape | `error` | `malformed_response` | `<Name> returned invalid JSON.`, `<Name> response was too large to process.` or `Unexpected response format from <Name>.` |
| An indicator is read back and no answer is stored for the provider | `not_queried` | `null` | `No stored answer from <Name>: it was not queried, or the lookup failed. Investigate the indicator again to retry.` |
| The provider answered with a record | `ok` | `null` | `null` |
| The provider answered that it has nothing on the indicator | `no_data` | `null` | `null` |

- A failed lookup is never stored. When an older stored answer exists, the row shows that answer
  (`from_cache` is `true` and `freshness` follows its age) together with the `message` and `reason` of
  the failure. A stored answer from a provider that has since lost its key is shown the same way, with
  `reason` `not_configured`.
- `ok` and `no_data` are answers and count towards `score.answered_sources`. `no_data` means the
  provider has nothing on the indicator. It never means the indicator is safe.
- Every status other than `ok` and `no_data` means no answer, so that provider adds no points. A
  missing key or an unavailable provider is named in `score.uncertainty` instead of being treated as a
  clean result. An unsupported type adds no note, because that provider was never expected to answer.
- The retries, timeouts and cache times behind these outcomes are described in
  [threat-intelligence.md](threat-intelligence.md#provider-outcomes).

A VirusTotal row with a verdict looks like this (abridged: `summary` has more keys, which
[threat-intelligence.md](threat-intelligence.md#virustotal) lists). One engine out of 72 flagged the
indicator, which is weak evidence, and the note says so:

```json
{
  "provider": "virustotal",
  "display_name": "VirusTotal",
  "status": "ok",
  "freshness": "fresh",
  "signal": 0.25,
  "fetched_at": "2026-01-02T10:15:30Z",
  "evidence_at": "2026-01-02T09:58:12Z",
  "first_evidence_at": "2024-06-01T07:20:00Z",
  "cache_expires_at": "2026-01-03T10:15:30Z",
  "from_cache": false,
  "summary": {
    "verdict": "malicious",
    "malicious": 1,
    "suspicious": 0,
    "harmless": 60,
    "undetected": 11,
    "timeout": 0,
    "engines_total": 72,
    "notes": ["Only 1 of 72 engines flagged this indicator; a lone detection is often a false positive, so the signal is low."]
  },
  "tags": [],
  "message": null,
  "verdict": "malicious",
  "reason": null
}
```

### `GET /api/v1/intel/indicators/{indicator_id}`

One stored indicator in the same shape as above. It is read-only: it never calls a provider and is
not audited. `404 not_found` for an unknown id and `422` when the id is not a UUID.

### `GET /api/v1/intel/indicators`

Search stored indicators. Query parameters, all optional:

| Parameter | Default | Notes |
| --- | --- | --- |
| `type` | any | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1` or `sha256`. |
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
  "by_type": { "ipv4": 5, "ipv6": 0, "domain": 4, "url": 1, "md5": 0, "sha1": 0, "sha256": 2 },
  "lookups_last_24h": 7,
  "providers": [
    { "name": "abuseipdb", "display_name": "AbuseIPDB", "configured": true, "supported_types": ["ipv4", "ipv6"], "simulated": false },
    { "name": "otx", "display_name": "AlienVault OTX", "configured": false, "supported_types": ["domain", "ipv4", "ipv6", "md5", "sha1", "sha256", "url"], "simulated": false },
    { "name": "virustotal", "display_name": "VirusTotal", "configured": false, "supported_types": ["domain", "ipv4", "ipv6", "md5", "sha1", "sha256", "url"], "simulated": false },
    { "name": "threatfox", "display_name": "ThreatFox", "configured": false, "supported_types": ["domain", "ipv4", "ipv6", "md5", "sha256", "url"], "simulated": false }
  ]
}
```

`providers` always lists the four providers in this order, and `supported_types` is sorted alphabetically.
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
| `series` | The last 14 IST days, oldest first, today last and zero days included: `day` (a date, `YYYY-MM-DD`), `lookups`, `high_risk_lookups`, `new_indicators`. |
| `activity` | The last 7 IST days, each with `hours`: 24 lookup counts, one per IST hour, the first for 00:00 to 00:59 IST. |
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
`scope` flag is `true`, and the dashboard says so instead of implying the figures are complete. The
days and hours are IST calendar days and hours (see [Timestamps](#conventions)); the timestamps stored
and returned elsewhere stay UTC.

## Network monitoring endpoints

All routes are under `/api/v1/network` and need the `SecurityAnalyst` or `Admin` role. A session
belongs to the user who started the capture or uploaded the file, and so do its flows and alerts:
another user's session or alert answers `404`, just as an unknown one does. Ids are UUIDs, so a
malformed id answers `422`. [network-monitoring.md](network-monitoring.md) explains what the module
captures, the [detection rules](network-monitoring.md#detection-rules), the
[lookups of outside addresses](network-monitoring.md#external-ip-enrichment), retention and what to do
when [something goes wrong](network-monitoring.md#when-something-goes-wrong). This section lists the
requests and their answers.

| Request | What it does | Success | Errors besides the generic ones |
| --- | --- | --- | --- |
| `GET /api/v1/network/status` | The state of the caller's live capture, whether capture is possible on this server, whether someone else's capture holds the single capture slot (`busy`) and whether a capture file is being analysed. | `200` `NetworkStatus` | None. |
| `GET /api/v1/network/interfaces` | The interfaces a capture can start on. The list is cached for 30 seconds; `?refresh=true` looks at the system again and counts against the investigation [rate limit](#rate-limits). | `200` `InterfaceList` | `429 rate_limited` (only with `refresh=true`). |
| `GET /api/v1/network/rules` | The detection rules with this server's thresholds. A rule's `active` is `false` when it cannot fire in the current configuration, for example when lookups of outside addresses are off. | `200`, a list of rules | None. |
| `POST /api/v1/network/capture/start` | Start a live capture on one interface. One capture runs at a time. Body: `{"interface": "<id from /interfaces>"}` (1 to 512 characters; unknown fields are rejected). | `200` `NetworkStatus` | `404 interface_not_found`, `409 capture_already_running`, `503` `capture_permission_denied`, `capture_backend_missing`, `interface_unavailable` or `capture_failed`. |
| `POST /api/v1/network/capture/stop` | Stop the caller's live capture. | `200` `NetworkStatus` | `409 capture_not_running`. |
| `POST /api/v1/network/pcap` | Analyse an uploaded capture file ([details below](#post-apiv1networkpcap)). | `202` `SessionDetail` | See below. |
| `GET /api/v1/network/sessions` | The caller's sessions, live and from files, newest first. Query: `limit` (1 to 100, default 25), `offset` (0 to 1,000,000). | `200` `{items, total, limit, offset}` | None. |
| `GET /api/v1/network/sessions/{session_id}` | One session with its totals, top talkers, outside addresses and how far their lookups have got. | `200` `SessionDetail` | `404 session_not_found`. |
| `GET /api/v1/network/sessions/{session_id}/flows` | The session's flows, newest first. Query: `limit` (1 to 200, default 50), `offset` (0 to 1,000,000). | `200` `{items, total, limit, offset}` | `404 session_not_found`. |
| `GET /api/v1/network/sessions/{session_id}/alerts` | The session's alerts, newest first. Query: `severity` (`low`, `medium`, `high` or `critical`; repeat it to match several), `rule` (a rule id from `/rules`: `NET-` and three digits), `limit` (1 to 200, default 50), `offset` (0 to 1,000,000). | `200` `{items, total, limit, offset}` | `404 session_not_found`. |
| `DELETE /api/v1/network/sessions/{session_id}` | Delete a session that has ended, with its flows and alerts. | `204`, no body | `404 session_not_found`, `409 session_running`. |
| `POST /api/v1/network/alerts/{alert_id}/enrich` | Look up the alert's outside address with the threat-intelligence providers now, on demand. Fresh provider answers are reused, so asking again does not spend their quota. | `200` `AlertOut` | `404 alert_not_found`, `409 enrichment_disabled`, `422 address_not_public`, `429 rate_limited` (with `Retry-After`). |

### `POST /api/v1/network/pcap`

Analyse a capture file in PCAP or PCAPNG format. The body is the raw file, not a form. The answer is
`202` with a new session whose `status` is `running`; the analysis goes on in the background, so poll
`GET /api/v1/network/sessions/{session_id}` until `status` is `completed` or `failed`. The upload is
kept in a private temporary folder only while it is analysed.

| Part | Rules |
| --- | --- |
| `Content-Type` | `application/octet-stream` (parameters after a `;` are ignored). Anything else is refused with `415 unsupported_media_type`, including `multipart/form-data`: uploads are raw bytes on purpose. |
| `X-File-Name` | Sent exactly once; a missing or repeated header is `422 invalid_filename`. The file name, percent-encoded as UTF-8, at most 1024 characters, ending in `.pcap`, `.pcapng` or `.cap`. Only the last path component is used, and it is shortened to 120 characters for display. It is a label and is never used as a path. |
| Body | The raw bytes, at most `NETWORK_MAX_PCAP_SIZE_MB` megabytes (default 50, allowed 1 to 500). The declared `Content-Length` is checked before the body is read, and the bytes are counted again as they arrive. |

The checks run in this order, and the first one that fails is the answer:

1. The role (`401`, `403`).
2. The investigation [rate limit](#rate-limits), before any of the body is read (`429 rate_limited`).
3. `Content-Type` (`415 unsupported_media_type`).
4. `X-File-Name` (`422 invalid_filename`).
5. The declared `Content-Length` (`400 invalid_content_length` when it is not a valid number,
   `413 file_too_large` when it is over the limit).
6. Only one analysis runs at a time (`409 analysis_already_running`).
7. The body as it is read (`413 file_too_large` when it outgrows the limit, `400 upload_interrupted`
   when the client disconnects, `422 invalid_capture_file` when it is empty).
8. The structure of the file (`422 invalid_capture_file`: not a readable PCAP or PCAPNG file, or no
   complete packet).
9. Starting the analysis (`503 analysis_failed`).

An analysis that runs past 10 minutes stops: the session ends `failed` with the `error_code`
`analysis_timeout`, and the flows and alerts found so far are kept. A file that is cut short or
damaged after some point is analysed up to that point: the session ends `completed` with the
`error_code` `capture_truncated`. Neither is a failed request, because the upload itself was accepted;
both show up in the session's `status`, `error_code` and `message` ([session codes](#session-error-codes)).
A worked example is in [Uploading a capture file and listing its alerts](#uploading-a-capture-file-and-listing-its-alerts).

### Network response objects

| Object | Fields |
| --- | --- |
| `NetworkStatus` | `state` (`not_configured`, `ready`, `starting`, `running`, `stopping`, `stopped`, `failed` or `permission_denied`), `backend` (`name`: `npcap`, `winpcap`, `libpcap`, `native` or `none`; `available`), `interface`, `session_id`, `error_code`, `message`, `busy`, `analysis` (`running`, `session_id` for the caller's own analysis only, `max_upload_mb`), `enrichment_enabled`. |
| `InterfaceList` | `backend` as above, and `interfaces`: `id`, `name`, `description`, `addresses`. |
| Rule | `rule_id`, `name`, `title`, `description`, `unit`, `threshold`, `window_seconds`, `detail`, `active`, `severities` (the severity at one, three and ten times the threshold). |
| `SessionOut` | `id`, `source_kind` (`live` or `pcap`), `status` (`starting`, `running`, `stopping`, `stopped`, `completed`, `failed` or `permission_denied`), `interface`, `source_label` (the display name of an uploaded file), `started_at`, `ended_at`, `duration_seconds`, `packets_total`, `bytes_total`, `flows_total`, `active_flows`, `alerts_total`, `packets_dropped`, `error_code`, `message`. |
| `SessionDetail` | Everything in `SessionOut`, plus `first_packet_at`, `last_packet_at`, `protocols`, `top_sources`, `top_destinations`, `non_ip_packets`, `malformed_packets`, `flows_evicted`, `flows_stored`, `flows_not_stored`, `alerts_by_rule`, `alerts_suppressed`, `alerts_lost`, `talkers_truncated`, `external_ips` and `enrichment` (the counts `enabled`, `total`, `completed`, `pending`, `failed`, `unavailable`, `skipped`). |
| `external_ips[]` | At most 100 addresses, the ones named in alerts first and then the heaviest by bytes: `address`, `first_seen`, `last_seen`, `packets`, `bytes`, `sent_to`, `alerted`, `peers`, `ports`, `protocols`, `enrichment`. |
| Flow | `id`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `first_seen`, `last_seen`, `duration_seconds`, `packets_out`, `packets_in`, `bytes_out`, `bytes_in`, `tcp_flags`, `tcp_flag_names`, `close_reason`. |
| `AlertOut` | `id`, `session_id`, `rule_id`, `rule_name`, `title`, `severity`, `explanation` (text for people, with times in IST), `observed_value`, `threshold`, `unit`, `window_seconds`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `first_observed`, `last_observed`, `created_at`, `evidence`, `enrichment`. |
| `enrichment` (of an address or an alert) | `status` (`pending`, `completed`, `failed`, `unavailable`, `disabled`, `skipped_budget`, `not_applicable` or `not_looked_up`), `address`, `risk_score` and `classification` (present only when `status` is `completed` and `assessed` is `true`; `null` otherwise), `assessed` (`true` only when a provider returned evidence, not only "nothing known"), `indicator_id` (the stored indicator, which the [intel endpoints](#threat-intelligence-endpoints) read and delete), `completed_at`, `error_code`, `message`, `providers` (`provider`, `display_name`, `status`, `verdict`). `error_code` is `rate_limited`, `provider_error`, `no_provider_available`, `queue_full`, `lookup_failed`, `indicator_deleted` or `interrupted`. |

When `assessed` is `false` the lookup is `completed`, but every provider that answered said "no
data", so the answer holds no evidence. `risk_score` and `classification` are then `null` (the score
the intelligence service gives an indicator without evidence is 0, which says nothing about the
address and is never passed on as a finding), and `message` says that this does not mean the address
is safe. If no provider answered at all, `status` is not `completed` and there is no score either.

## Encrypted file endpoints

Files are encrypted before they are stored. The routes come in two groups: the owner routes under
`/api/v1/files`, for signed-in users and their own files, and the link routes under
`/api/v1/shares/{token}`, which need no sign-in. [file-sharing.md](file-sharing.md) describes the
workflow, the life of a link, the limits and the security design, and
[encryption-design.md](encryption-design.md) the cryptography. This section lists the requests.

The feature stays off until a master key is configured
([Turning it on](file-sharing.md#turning-it-on)). Until then `GET /api/v1/files/status` answers
`configured: false`, and uploading a file, creating a link and every link route answer
`503 feature_not_configured`.

### Owner endpoints

Any signed-in role may call these routes: `User`, `SecurityAnalyst` or `Admin`. Every request is
limited to the caller's own files, and `Admin` has no extra access to other people's files. A file id
that does not exist, is not a UUID or belongs to someone else answers `404 file_not_found`, so the
answer does not reveal whether the file exists.

| Request | What it does | Success | Errors besides the generic ones |
| --- | --- | --- | --- |
| `GET /api/v1/files/status` | Whether the feature is configured, and its limits: `configured`, `max_file_size_bytes`, `default_share_expiry_hours`, `max_share_expiry_hours`, `max_share_downloads`, `min_password_length`, `max_password_length`. | `200` | None. |
| `POST /api/v1/files` | Encrypt and store a file ([details below](#uploading-a-file)). | `201` `FileOut` | See below. |
| `GET /api/v1/files` | The caller's files, newest first. Query: `limit` (1 to 200, default 50), `offset` (0 to 1,000,000). | `200` `{items, total}` | None. |
| `GET /api/v1/files/{file_id}` | One file with its links. A link carries no token. | `200` `FileDetail` | `404 file_not_found`. |
| `DELETE /api/v1/files/{file_id}` | Delete the file, its stored ciphertext and all its links. The audit trail keeps its history. | `204`, no body | `404 file_not_found`; `503 storage_unavailable` when the ciphertext could not be removed (nothing else is deleted then). |
| `POST /api/v1/files/{file_id}/shares` | Create a share link ([details below](#creating-a-share-link)). | `201` `ShareCreated` | See below. |
| `POST /api/v1/files/{file_id}/shares/{share_id}/revoke` | Revoke a link, from the next request on. Revoking it again changes nothing and records nothing. | `200` `ShareOut` | `404 file_not_found`, also for a `share_id` that is not one of this file's links. |
| `GET /api/v1/files/{file_id}/activity` | The file's most recent audit events: `timestamp`, `action`, `result`, `share_id`, `reason`. Newest first, at most 100, and without source addresses. | `200` `{items}` | `404 file_not_found`. |

#### Uploading a file

The body is the raw bytes of the file, not a form.

| Part | Rules |
| --- | --- |
| `Content-Type` | `application/octet-stream`. Anything else is refused with `415 unsupported_media_type`, and that includes `multipart/form-data`. Multipart is refused on purpose: its parser writes larger parts to temporary files, which would put plaintext on disk before it is encrypted. |
| `X-File-Name` | The file name, percent-encoded as UTF-8: exactly one header, ASCII only, at most 1024 characters. The name is cleaned before it is encrypted ([the rules](file-sharing.md#uploading-a-file)) and is stored encrypted. Uploading the same name twice makes two files. |
| Body | At most `MAX_ENCRYPTED_FILE_SIZE_MB` megabytes (default 25, allowed 1 to 100). The declared `Content-Length` is checked before any of the body is read, and the bytes are counted again as they arrive. |

The server checks in this order and answers with the first failure:

| Status | `code` | When |
| --- | --- | --- |
| 401, 403 | `unauthorized`, `forbidden` | No valid token, or a role that is not allowed. |
| 503 | `feature_not_configured` | No master key is set. This is checked before any of the body is read. |
| 429 | `rate_limited` | More than `FILE_UPLOAD_RATE_LIMIT_PER_MINUTE` uploads (default 10) in a minute by this user. |
| 415 | `unsupported_media_type` | `Content-Type` is not `application/octet-stream`. |
| 422 | `invalid_filename` | `X-File-Name` is missing, repeated, not valid percent-encoded UTF-8, over 1024 characters, or empty after cleaning. |
| 400 | `invalid_content_length` | `Content-Length` is not a number. |
| 413 | `file_too_large` | The file is over the limit, by its declared length or as it arrives. |
| 400 | `upload_interrupted` | The client disconnected before the whole body arrived. |
| 422 | `empty_file` | The body has no bytes. |
| 503 | `storage_unavailable` | The ciphertext could not be written. Nothing is stored. |
| 500 | `internal_error` | The database failed. Nothing is stored. |

#### Creating a share link

`POST /api/v1/files/{file_id}/shares` takes an optional JSON body (`Content-Type: application/json`).
Without a body every setting takes its default. Unknown fields are rejected.

| Field | Default | Rule |
| --- | --- | --- |
| `expires_in_hours` | `DEFAULT_SHARE_EXPIRY_HOURS` (24) | A whole number from 1 to `MAX_SHARE_EXPIRY_HOURS` (default 720, the setting allows up to 8760). |
| `max_downloads` | 1 | A whole number from 1 to `MAX_SHARE_DOWNLOADS` (default 100, the setting allows up to 10000). |
| `password` | none | 8 to 128 characters. Leave it out, or send `null`, for a link without a password. An empty string is invalid. |

A value out of range answers `422 validation_error`, and `details` names the field, for example
`{"loc": ["body", "expires_in_hours"], "msg": "Must be between 1 and 720.", "type": "value_error"}`.
`GET /api/v1/files/status` returns the limits this server uses. The other errors:

| Status | `code` | When |
| --- | --- | --- |
| 404 | `file_not_found` | The file does not exist or is not the caller's. |
| 503 | `feature_not_configured` | No master key is set. |
| 409 | `file_unavailable` | The file is quarantined (its `status` is `corrupt`), or its stored key failed verification just now, which quarantines it. |
| 503 | `encryption_key_mismatch` | The configured master key is not the one that encrypted this file. |
| 429 | `rate_limited` | More than `SHARE_CREATE_RATE_LIMIT_PER_MINUTE` links (default 10) in a minute by this user. `Retry-After` is set. |
| 503 | `service_busy` | A password link needs a key derivation, and all slots stayed busy for 10 seconds (at most two run at once). `Retry-After: 2` is set. |
| 500 | `internal_error` | The database failed. |

The answer is `201`. **The token appears in this response and nowhere else**: only its SHA-256 hash is
stored, so it cannot be shown again. If it is lost, revoke the link and create a new one. The link
holds neither a key nor the password.

```json
{
  "share": {
    "id": "5c1d2e0a-7b4f-4a58-9c36-0e1f2a3b4c5d",
    "file_id": "b2a9c0de-1f34-4e56-8a78-9b0c1d2e3f40",
    "created_at": "2026-01-02T10:15:30Z",
    "expires_at": "2026-01-03T10:15:30Z",
    "max_downloads": 1,
    "download_count": 0,
    "downloads_remaining": 1,
    "last_downloaded_at": null,
    "revoked_at": null,
    "password_protected": false,
    "status": "active"
  },
  "token": "<43 URL-safe characters, shown only here>",
  "path": "/share/<token>"
}
```

`path` is the route of the dashboard page for the link, and the dashboard builds the full address from
its own origin. To download without the dashboard, use the API address
`/api/v1/shares/<token>/download`.

#### Owner response objects

| Object | Fields |
| --- | --- |
| `FileOut` | `id`, `name` (reads `(unreadable name)` if it cannot be decrypted), `size_bytes`, `status` (`active`, or `corrupt` for a quarantined file), `algorithm` (`AES-256-GCM`), `created_at`, `share_count`, `active_share_count`. |
| `FileDetail` | Everything in `FileOut`, plus `shares`, a list of `ShareOut`. |
| `ShareOut` | `id`, `file_id`, `created_at`, `expires_at`, `max_downloads`, `download_count`, `downloads_remaining`, `last_downloaded_at`, `revoked_at`, `password_protected`, `status`. |
| `ShareOut.status` | `active`, `expired`, `revoked` or `exhausted` (all downloads used). A link that is several of these shows the first in the order `revoked`, `expired`, `exhausted`, `active`. |
| `ShareCreated` | `share` (a `ShareOut`), `token` and `path`. |

### Share-link endpoints

These routes need no sign-in and no cookie. The link token in the path is the credential: whoever
holds it can use the link within its rules, and nothing else (the routes cannot list files or links, or
read the audit trail). The request is recorded with the actor `anonymous`. A token that is malformed
(it must be 43 URL-safe characters) or unknown answers `404 share_not_found`, without a database
lookup.

| Request | What it does | Success |
| --- | --- | --- |
| `GET /api/v1/shares/{token}` | What the link offers, without using a download: `state` (always `available`), `file_name` (`null` when the link needs a password), `size_bytes`, `password_required`, `expires_at`, `downloads_remaining`. It never answers `403`: for a password link it reports `password_required: true`. | `200` `PublicShareInfo` |
| `GET /api/v1/shares/{token}/download` | Download through a link without a password. A link with a password answers `403 password_required`, because a password is never accepted in a URL. | `200`, the file |
| `POST /api/v1/shares/{token}/download` | Download through a link, with or without a password. Optional JSON body: `{"password": "<the password>"}`. | `200`, the file |

All three go through the same gate. [The checks, in order](file-sharing.md#the-checks-in-order) gives
the order and the audit rules. The errors a link can answer with:

| Status | `code` | When |
| --- | --- | --- |
| 404 | `share_not_found` | The token is malformed or unknown. |
| 410 | `share_revoked`, `share_expired`, `share_limit_reached` | The owner revoked the link, its time has run out, or all its downloads are used. The first that applies, in that order, is reported. |
| 409 | `file_unavailable` | The file is quarantined, or its stored data failed verification just now (the file is quarantined and no download is used). |
| 403 | `password_required`, `invalid_password` | A download of a password link without a password, or with a wrong one. |
| 429 | `rate_limited` | More than `SHARE_DOWNLOAD_RATE_LIMIT_PER_MINUTE` requests (default 30) in a minute from this client network. `Retry-After` is set. |
| 429 | `too_many_attempts` | The wrong-password budget of this link, or of this client network, is spent (default 5 in 15 minutes). `Retry-After` is set, and a correct password does not clear it. |
| 503 | `feature_not_configured`, `encryption_key_mismatch` | No master key is set, or it is not the key that encrypted this file. |
| 503 | `service_busy` | A password download needs a key derivation, and all slots stayed busy for 10 seconds. `Retry-After: 2` is set. |
| 503 | `storage_unavailable` | The stored ciphertext could not be read. |

#### Downloading through a link

`POST /api/v1/shares/{token}/download` takes an optional body: `{"password": "<the password>"}` with
`Content-Type: application/json`. An empty body means no password. This route is open to anyone, so
the body is read under a small cap, and before the link itself is looked at, so these errors come
before the link errors above:

- Over 4096 bytes: `413 request_too_large`.
- Not empty, and not sent as `application/json`: `415 unsupported_media_type`.
- Not valid (a password over 128 characters, an unknown field, text that is not JSON):
  `422 validation_error`. The `details` give `loc`, `msg` and `type` and never repeat the password.
- A `Content-Length` that is not a number: `400 invalid_content_length`. A disconnect before the whole
  body arrived: `400 upload_interrupted`.

The server decrypts and verifies the whole file before it counts the download, so a wrong password or
a failed integrity check never uses one up. One conditional database update then reserves the download,
so `max_downloads` stays exact when requests arrive together: of two requests for the last download,
one gets the file and the other `410 share_limit_reached`
([why](file-sharing.md#download-limits-stay-exact-under-load)).

A successful download answers `200` with the decrypted bytes and these headers:

| Header | Value |
| --- | --- |
| `Content-Type` | `application/octet-stream` |
| `Content-Disposition` | `attachment; filename="<ASCII fallback>"; filename*=UTF-8''<percent-encoded name>` |
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; sandbox` |
| `Referrer-Policy` | `no-referrer` |

Like every response it also carries `X-Correlation-ID` and `X-Frame-Options: DENY`. A browser treats
the bytes as an opaque download and never renders them.

## Audit actions

Actions that change something write one row to the append-only audit trail. The row holds the actor,
the action, a target, the result (`success`, `partial`, `rejected` or `failed`), the client address, the
correlation ID and a few `details`. It never holds a secret, a password, a link token or the content of
a file. No endpoint deletes or edits audit rows; the only read access is the owner's limited
`GET /api/v1/files/{file_id}/activity`. [security.md](security.md) describes the trail.

| Group | Actions | Target |
| --- | --- | --- |
| Threat intelligence | `IOC_LOOKUP`, `IOC_DELETE` | The indicator as `type:value`. An input that was rejected has no target. A lookup the network module starts for an outside address uses the actor `system:network-monitor`. |
| Network monitoring | `NETWORK_CAPTURE_START`, `NETWORK_CAPTURE_STOP`, `NETWORK_PCAP_ANALYZE`, `NETWORK_SESSION_DELETE`, `NETWORK_ENRICH` | `network-session:{id}`, or `network-alert:{id}` for `NETWORK_ENRICH`. A request rejected before it had a session has no target, and `details.reason` says why. Their `details` hold counts, sizes and the interface name, never traffic addresses or file names ([data collected](network-monitoring.md#data-collected-and-privacy)). |
| Encrypted files | `FILE_CREATE`, `FILE_DELETE`, `FILE_INTEGRITY_FAILED` | `file:{id}` |
| Share links | `SHARE_CREATE`, `SHARE_REVOKE`, `SHARE_DOWNLOAD`, `SHARE_DOWNLOAD_REJECTED`, `SHARE_PASSWORD_FAILED`, `SHARE_EXPIRED`, `SHARE_LIMIT_REACHED` | `file:{id}`, with the link in `details.share_id`. Link holders are recorded as the actor `anonymous`. |

[file-sharing.md](file-sharing.md#audit-events) lists when each file and link action is written and what
it keeps. Rate-limit refusals (`429`), the refusal once the wrong-password budget is spent (the wrong
guesses before it are audited), an unconfigured feature and unknown link tokens are not audited.

## Error codes

`error.code` is stable, and `message` is not. These are the codes the routes above return, besides the
generic ones in [Error format](#error-format). Some codes appear on more than one route.

### Network monitoring

| Status | `code` | Meaning |
| --- | --- | --- |
| 400 | `invalid_content_length` | `Content-Length` of an upload is not a number. |
| 400 | `upload_interrupted` | The client disconnected before the whole upload arrived. |
| 404 | `interface_not_found` | The interface id is not one that `/interfaces` lists. |
| 404 | `session_not_found` | No such session, or it belongs to someone else. |
| 404 | `alert_not_found` | No such alert, or it belongs to someone else. |
| 409 | `capture_already_running` | A live capture is running already. Only one runs at a time. |
| 409 | `capture_not_running` | The caller has no live capture to stop. |
| 409 | `analysis_already_running` | A capture file is being analysed. Only one analysis runs at a time. |
| 409 | `session_running` | The session has not ended, so it cannot be deleted. Stop it first. |
| 409 | `enrichment_disabled` | Lookups of outside addresses are switched off (`EXTERNAL_ENRICHMENT_ENABLED`). |
| 413 | `file_too_large` | The capture file is over `NETWORK_MAX_PCAP_SIZE_MB`. |
| 415 | `unsupported_media_type` | The upload is not `application/octet-stream`. |
| 422 | `invalid_filename` | `X-File-Name` is missing, repeated or not a usable capture file name. |
| 422 | `invalid_capture_file` | The file is empty, is not a readable PCAP or PCAPNG file, or holds no complete packet. |
| 422 | `address_not_public` | The alert involves no public address, so there is nothing to look up. |
| 429 | `rate_limited` | The investigation [rate limit](#rate-limits). |
| 503 | `capture_permission_denied`, `capture_backend_missing`, `interface_unavailable`, `capture_failed`, `analysis_failed` | The session codes below, when a request fails with them. |

#### Session error codes

A session that ends badly keeps a code in `error_code` and a safe sentence in `message` (in
`SessionOut` and in the live capture status). The messages point to
[network-monitoring.md](network-monitoring.md#when-something-goes-wrong), which says what to do.

| `error_code` | Status when a request fails with it | Meaning |
| --- | --- | --- |
| `capture_permission_denied` | 503 | The operating system refused packet capture to the API process. |
| `capture_backend_missing` | 503 | No capture driver (Npcap or libpcap) was found. |
| `interface_unavailable` | 503 | The interface is gone or down. |
| `capture_failed` | 503 | Packet capture stopped because of an error. |
| `invalid_capture_file` | 422 | The file is not a readable PCAP or PCAPNG capture, or holds no complete packet. |
| `analysis_failed` | 503 | The file could not be analysed, or the analysis could not be started. |
| `interrupted` | Session only | The API stopped while the session was running. |
| `capture_truncated` | Session only | The file is cut short or damaged after some point. Everything before that was analysed. |
| `analysis_timeout` | Session only | The analysis reached its limit of 10 minutes. The results so far are kept. |
| `results_incomplete` | Session only | The database was unavailable for part of the session, so the totals may be incomplete. |

### Encrypted files and share links

| Status | `code` | Meaning |
| --- | --- | --- |
| 400 | `invalid_content_length` | `Content-Length` is not a number. |
| 400 | `upload_interrupted` | The client disconnected before the whole body arrived. |
| 403 | `password_required` | A download of a password link without a password. |
| 403 | `invalid_password` | The password is wrong. |
| 404 | `file_not_found` | The file does not exist, is not a UUID or is not the caller's. Also an unknown link id on revoke. |
| 404 | `share_not_found` | The link token is malformed or unknown. |
| 409 | `file_unavailable` | The file is quarantined, or failed verification. |
| 410 | `share_revoked`, `share_expired`, `share_limit_reached` | The link was revoked, has expired, or has no downloads left. |
| 413 | `file_too_large` | The upload is over `MAX_ENCRYPTED_FILE_SIZE_MB`. |
| 413 | `request_too_large` | The JSON body of a download is over 4096 bytes. |
| 415 | `unsupported_media_type` | An upload that is not `application/octet-stream`, or a download body that is not `application/json`. |
| 422 | `empty_file` | The upload has no bytes. |
| 422 | `invalid_filename` | `X-File-Name` is missing, repeated or unusable. |
| 429 | `rate_limited` | A file upload, link creation or link request [rate limit](#rate-limits). |
| 429 | `too_many_attempts` | Too many wrong passwords for this link or from this client network. |
| 500 | `internal_error` | The database failed. |
| 503 | `feature_not_configured` | No master key is set. |
| 503 | `encryption_key_mismatch` | The configured master key is not the one that encrypted the file. |
| 503 | `storage_unavailable` | Stored ciphertext could not be written, read or removed. |
| 503 | `service_busy` | The key-derivation slots were all busy. Retry shortly. |

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

These examples use the local development setup (`AUTH_MODE=dev`), where no token is needed. With
Microsoft Entra ID sign-in, send `Authorization: Bearer <your access token>` with every request except
the link routes under `/api/v1/shares`: `-H "Authorization: Bearer <your access token>"` for curl, or
`-Headers @{ Authorization = "Bearer <your access token>" }` for `Invoke-RestMethod`. The JSON
examples use `Invoke-RestMethod`, because the quoting rules of `curl.exe` differ between PowerShell
versions. The last two examples in this section send and receive raw file bytes, so they use
`curl.exe` and pipe their JSON in on standard input, which avoids those quoting rules.

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

### Uploading a capture file and listing its alerts

These commands send a capture file for analysis, wait until it has finished and list its high and
critical alerts. `example.pcap` stands for a capture of your own. The caller needs the
`SecurityAnalyst` or `Admin` role, which `DEV_AUTH_ROLES` gives by default.

Windows (PowerShell):

```powershell
$base = "http://127.0.0.1:8000"

$session = curl.exe -s -X POST "$base/api/v1/network/pcap" `
  -H "Content-Type: application/octet-stream" `
  -H "X-File-Name: example.pcap" `
  --data-binary "@example.pcap" | ConvertFrom-Json

# The analysis runs in the background: ask again until the status is no longer "running".
while ($session.status -eq "running") {
  Start-Sleep -Seconds 2
  $session = curl.exe -s "$base/api/v1/network/sessions/$($session.id)" | ConvertFrom-Json
}
"$($session.status): $($session.alerts_total) alerts"

curl.exe -s "$base/api/v1/network/sessions/$($session.id)/alerts?severity=high&severity=critical"
```

macOS or Linux (copy the session `id` from the first answer into the next two commands):

```bash
base=http://127.0.0.1:8000
curl -s -X POST "$base/api/v1/network/pcap" \
  -H "Content-Type: application/octet-stream" \
  -H "X-File-Name: example.pcap" \
  --data-binary "@example.pcap"
curl -s "$base/api/v1/network/sessions/PASTE-THE-SESSION-ID-HERE"
curl -s "$base/api/v1/network/sessions/PASTE-THE-SESSION-ID-HERE/alerts?severity=high&severity=critical"
```

The upload answers `202` with the new session. When a request fails, the answer is an `error` object
instead; its `code` is explained in [Error codes](#error-codes). The alerts answer is
`{"items": [...], "total": ..., "limit": ..., "offset": ...}`, and each item is an `AlertOut`
([fields](#network-response-objects)). What the analysis looks at is in
[network-monitoring.md](network-monitoring.md#analysing-a-capture-file).

### Uploading a file, sharing it and downloading it

These commands upload `report.pdf`, create a link that works once within 24 hours and download the file
through the link without signing in. File sharing must be turned on first
([Turning it on](file-sharing.md#turning-it-on)); any role may upload.

Windows (PowerShell):

```powershell
$base = "http://127.0.0.1:8000"

# 1. Upload. The body is the raw file, and its name travels in X-File-Name.
$file = curl.exe -s -X POST "$base/api/v1/files" `
  -H "Content-Type: application/octet-stream" `
  -H "X-File-Name: report.pdf" `
  --data-binary "@report.pdf" | ConvertFrom-Json

# 2. Create the link. The JSON goes in on standard input.
$share = '{"expires_in_hours": 24, "max_downloads": 1}' |
  curl.exe -s -X POST "$base/api/v1/files/$($file.id)/shares" `
    -H "Content-Type: application/json" --data-binary "@-" | ConvertFrom-Json
$token = $share.token   # this answer is the only place the token is ever shown

# 3. Download through the link. No sign-in is needed. -D - prints the response headers.
curl.exe -s -D - -o restored.pdf "$base/api/v1/shares/$token/download"
```

macOS or Linux (copy the values from each answer into the next command):

```bash
base=http://127.0.0.1:8000
curl -s -X POST "$base/api/v1/files" \
  -H "Content-Type: application/octet-stream" \
  -H "X-File-Name: report.pdf" \
  --data-binary "@report.pdf"
echo '{"expires_in_hours": 24, "max_downloads": 1}' |
  curl -s -X POST "$base/api/v1/files/PASTE-THE-FILE-ID-HERE/shares" \
    -H "Content-Type: application/json" --data-binary @-
curl -s -D - -o restored.pdf "$base/api/v1/shares/PASTE-THE-TOKEN-HERE/download"
```

Things to know:

- The headers printed by the last command include `Content-Disposition`, `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff`. If the status line is not `200`, `restored.pdf` holds the JSON
  error instead of the file. Read its `code` in [Error codes](#error-codes).
- `GET "$base/api/v1/shares/$token"` shows what the link offers without using the download. The one
  download of this example is used by step 3, so a second try answers `410 share_limit_reached`.
- For a link with a password, add `"password": "<a password of 8 to 128 characters>"` to the JSON of
  step 2. The download then needs `POST` with the password in the body, never in the address:

  ```powershell
  '{"password": "<the password>"}' |
    curl.exe -s -D - -o restored.pdf -X POST "$base/api/v1/shares/$token/download" `
      -H "Content-Type: application/json" --data-binary "@-"
  ```

- To stop a link early, send `POST /api/v1/files/{file_id}/shares/{share_id}/revoke`, with the file
  `id` and `$share.share.id` from the answers above.
- Keep the token as secret as the file itself: whoever holds it can download within the link's rules.

## Roles

| Role | Scope |
| --- | --- |
| `Admin` | Platform configuration and user/role administration (planned: no endpoint exists for either yet). Today an `Admin` can call everything a `SecurityAnalyst` can, and use the file features on the same terms as a `User`. |
| `SecurityAnalyst` | IOC investigation and network monitoring (built); alerts from all sources, incidents, analytics and case workflow (planned). Also the file features, on the same terms as a `User`. |
| `User` | Encrypted file upload and sharing (built), for the user's own files. |

Which role may call which endpoints. A role that is not allowed gets `403 forbidden`.

| Endpoints | `User` | `SecurityAnalyst` | `Admin` |
| --- | --- | --- | --- |
| `/health`, `/ready` | Anyone | Anyone | Anyone |
| `/api/v1/me` | Yes | Yes | Yes |
| `/api/v1/intel/...` | No | Yes | Yes |
| `/api/v1/network/...` | No | Yes | Yes |
| `/api/v1/files/...` | Yes, own files | Yes, own files | Yes, own files |
| `/api/v1/shares/{token}...` | Anyone with the link | Anyone with the link | Anyone with the link |

Having a role is necessary but not sufficient for per-resource access. A user's files and links, and
the network sessions, flows and alerts a user created, belong to that user: someone else's answers
`404`, and `Admin` is no exception. Resource-level checks are part of the feature that needs them.

## Planned endpoints (not implemented)

None of these routes exists yet. The phase numbers are the roadmap's, see
[project-status.md](project-status.md#not-implemented-yet). Network alerts are already served under
[`/api/v1/network`](#network-monitoring-endpoints); the planned alert endpoints would list alerts from
every source, and the incident endpoints would add case handling.

| Roadmap phase | Endpoint | Purpose |
| --- | --- | --- |
| 5-7 | `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}` | Alerts from all sources. |
| 8 | `POST /api/v1/incidents`, `GET /api/v1/incidents/{id}` | Incidents. |

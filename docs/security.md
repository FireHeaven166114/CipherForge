# Security

How CipherForge is hardened today, what is deliberately left for later, and how dependencies are
managed. The threats behind these controls are in [threat-model.md](threat-model.md).

Nothing here is a claim of production readiness. CipherForge is a lab and portfolio project, and
this document says what is and is not covered.

This page lists the controls by area and keeps the limits next to them. The module guides hold the
detail: [file-sharing.md](file-sharing.md) and [encryption-design.md](encryption-design.md) for
encrypted file sharing, [network-monitoring.md](network-monitoring.md) and
[detection-engine.md](detection-engine.md) for network monitoring.

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
| nginx | The same three headers plus `Content-Security-Policy` (`default-src 'self'`, no inline scripts or styles, `frame-ancestors 'none'`, `object-src 'none'`), `Permissions-Policy` and `Cross-Origin-Opener-Policy`. `server_tokens off`, request bodies limited to 64 KB except on the two upload paths (`/api/v1/files` and `/api/v1/network/pcap`), which allow up to 500 MB and pass the body through as it arrives; the backend enforces the limit actually configured. The access log leaves share-link tokens out. |

The built frontend contains no inline scripts or styles, which is what allows a strict CSP. The
nginx configuration was exercised against real nginx builds (1.30.6 for the Phase 3 version,
1.30.8 for the Phase 4 upload locations and log redaction) using a copy that differs only in
listen address, document root, log path and upstream. The Phase 4 run showed the 413 limits (64 KB
by default, 500 MB declared on the upload paths), 10 MB uploads reaching a stand-in backend
unchanged, nothing written to the proxy's temporary body folders, and `[redacted]` in the access
log for every share URL. It also showed that the nginx **error** log is not redacted: a share URL
requested while the backend was down appeared there in full. Treat that log like the share links
themselves (see [Known limits of the Phase 4 controls](#known-limits-of-the-phase-4-controls)).
See also [deployment.md](deployment.md#verification-status). The Phase 3 to 3c bundle was later
loaded in a real browser under the same policy; see
[Frontend controls](#frontend-controls-phases-3-to-3c). Building the container image and running
the browser suite against it is covered only by the CI docker job.

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
- CI runs ruff, bandit, `pip-audit`, `npm audit`, the full test suites, the browser end-to-end
  suite, and builds the images. A finding in a package that ships fails the build. The frontend's
  development tools are audited too, but that step only reports for now (see
  [Dependency management](#dependency-management)). GitHub Actions are pinned to commit SHAs,
  workflow permissions are `contents: read`, and checkout does not persist credentials.
- Dependabot is configured for pip, npm, Docker, Compose and GitHub Actions.

## Implemented controls (Phase 2: threat intelligence)

| Control | Detail |
| --- | --- |
| Authorisation | Every `/api/v1/intel` route requires `SecurityAnalyst` or `Admin`; everything else is denied. |
| Rate limiting | `POST /investigate` is limited for each authenticated user (default 30 a minute) and answers `429` with `Retry-After`. Authorisation runs first, so a caller who is not allowed in never uses anyone's budget. The limiter is in memory and per process (see the gaps below). |
| Audit trail | Every investigation, including refused input, writes an `audit_logs` row (actor, action `IOC_LOOKUP`, target, result, source address, correlation ID) in the same transaction as the work it describes. So does every deletion of a stored indicator: one `IOC_DELETE` row for each indicator removed. Database triggers reject `UPDATE` and `DELETE` on those rows, on SQLite and PostgreSQL, and no endpoint or screen can delete or edit an audit row. Secrets and provider payloads are never recorded. |
| Deleting indicators | An analyst can delete a stored indicator, or several, from the Indicators page or an indicator's own page (`DELETE /indicators/{id}`, `POST /indicators/bulk-delete`). The request names exact ids, so it can remove only what it names: there is no "delete everything matching this search". One request carries at most 100 ids, the same roles as the rest of `/api/v1/intel` are needed, and the dashboard always asks for confirmation first, naming what will go. The indicator and every provider answer stored for it are removed in one transaction that also writes the `IOC_DELETE` audit rows, so either all of it happens or none of it does. A lookup that was still waiting on providers when its indicator was deleted is discarded with `409` instead of bringing the indicator back. SQLite overwrites the freed bytes (`secure_delete`), and foreign keys are enforced so nothing is left pointing at a deleted row. |
| Provider API keys | The four keys (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `THREATFOX_API_KEY`) are read from the environment as `SecretStr`, masked in logs by exact value, never returned by the API (the stats endpoint only says whether a key is set), and passed to the `backend` container only, not to the one-shot `migrate` job. A key that contains whitespace or control characters is refused at start-up, because it would corrupt the HTTP header it travels in. A test fails if Compose drifts from this. |
| No request forgery | The backend contacts four provider hosts (AbuseIPDB, AlienVault OTX, VirusTotal and abuse.ch ThreatFox), each fixed in code. The VirusTotal and ThreatFox base URLs can be overridden by setting, but only to an `https` URL (plain `http` is accepted for loopback alone) with no credentials, query string or fragment, so a key cannot be sent in clear text. An indicator is validated first (non-public addresses and reserved names are refused), appears in a request only as an escaped path, query value or JSON field, and redirects are not followed. |
| Bounded provider calls | 5-second connect timeout, a configurable overall timeout, a 2 MiB response cap and a small connection pool. Providers run in parallel against one shared deadline, and a failure degrades that provider only. VirusTotal and ThreatFox have their own timeout and retry settings; a retry follows only a timeout, a connection failure or a 5xx answer, within the same overall timeout. |
| Untrusted provider data | Parsed defensively into whitelisted, size-limited fields. Text is stripped of control and invisible characters and truncated, counts are bounded, and implausible dates are discarded. Free text from a provider is community-supplied and must only be displayed as text. |
| No indicator or key in logs | HTTP client libraries log full request URLs at INFO, which would contain the indicator and could contain a credential. The `httpx`, `httpx2`, `httpcore` and `httpcore2` loggers are silenced, and a test guards it. Application logs record the indicator type and score, never the value. |
| Valid source address only | The audited address is stored only if it is a valid IP address. Behind nginx it comes from `X-Forwarded-For`, which uvicorn does not validate, so a hostile value is dropped rather than stored. |
| Strict indicator input | Length limit, whitespace and invisible characters refused, MD5, SHA-1 and SHA-256 file hashes only (hexadecimal; SHA-512 is refused with a message that says so), `http`/`https` URLs only, no credentials in URLs. Error messages never echo the input. |
| Lookups only, and no data is not safe | VirusTotal and ThreatFox are only asked about an indicator. CipherForge never uploads a file or submits a URL for scanning. An answer of "nothing found" is stored as no data, never as clean, and an indicator no provider answered about stays "Not assessed". The score is still the deterministic `intel-risk-v1`; the two providers only add evidence to it. See [threat-intelligence.md](threat-intelligence.md). |

### Known limits of the Phase 2 controls

- **Forwarded headers in Compose.** The backend trusts `X-Forwarded-For` from private network ranges
  (`FORWARDED_ALLOW_IPS`, so that nginx's address is replaced by the real client's). A peer inside
  those ranges that can reach the backend directly can therefore choose the *source address* recorded
  in the audit row. The actor comes from the token and cannot be forged this way, and rate limits are
  keyed by user, not address. Keep the backend port on loopback (the default) and the backend off
  other networks.
- **A TLS proxy in front of nginx.** nginx then sees the proxy's address, so the audit trail records
  the proxy's address unless nginx is also configured to read the real client address (`real_ip`).
  That is not configured.
- **Reads are not audited.** Looking up a stored indicator records nothing; only investigations do.
- **Audit protection is not absolute.** The triggers stop application code and ordinary SQL from
  changing or deleting audit rows, but a database superuser can drop them. Ship the rows to storage
  the application cannot write to if the trail must survive a database compromise.
- **Deleting an indicator does not erase the audit rows that name it.** The audit trail is
  append-only on purpose, and an audit row's target is the indicator's `type:value` (that is how an
  analyst can see what was looked up). After a deletion the indicator is gone from the indicator
  tables, every list, the overview's top-risk and recent lists and the detail page, but the older
  `IOC_LOOKUP` rows, and the new `IOC_DELETE` row, still contain its value. The overview's lookup
  counts come from those rows, so they do not fall when an indicator is deleted. If a value must
  disappear from the audit trail as well (for example a customer's address that should never have
  been submitted), that is a database operation by whoever administers the database, outside the
  application, and it removes the evidence the trail exists to keep.
- **Deletion is not forensic erasure.** SQLite is told to overwrite freed pages and PostgreSQL
  reclaims the space at its next vacuum, but copies in backups, replicas, the write-ahead log and
  the operating system's file system are outside the application's reach. Delete from the backups
  too if that matters.
- **Any analyst can delete any indicator.** There is no per-indicator ownership: the roles that can
  investigate can delete, and the audit trail records who did. The rate limit applies to
  investigations only, so deletion is bounded by the 100-id batch size, not by a request budget.

## Frontend controls (Phases 3 to 3c)

The dashboard displays text that third parties wrote (provider pulse names, tags, malware families,
ISP names), so most of these controls are about displaying it safely and about not misleading the
analyst. Phase 3b added charts, a map, a command palette, a details drawer and visual effects on top
of the same rules, and a browser test suite that checks them against the shipped build. Phase 3c
restyled every screen and moved the effects onto anime.js; it changed no request, route or wording,
and the same tests run unchanged against it.

| Control | Detail |
| --- | --- |
| Provider text is only ever text | Everything a provider supplies is rendered as React text, which escapes it: in lists, drawers and tooltips, and in the text inside the SVG charts and the map. ESLint fails the build on `dangerouslySetInnerHTML`, on assignments to `innerHTML` or `outerHTML`, and on `eval` and `new Function`, and the CSP would block inline script even if one slipped through. Browser tests give every list, chart label, drawer, tooltip and stored record names and values built to become markup, a script, a link or a broken layout, and check that each stays text: nothing is created in the page, nothing runs and nothing is followed. |
| Outbound links cannot be steered | The only links to other sites go to OTX pulses and MITRE ATT&CK techniques. Each URL is built from a fixed base and an identifier that must match a strict pattern (24 hexadecimal characters for a pulse; `T1234` or `T1234.001` for a technique), so provider data never chooses a host, a path or a scheme. A value that does not match is shown as plain text. The links open in a new tab with `rel="noopener noreferrer"`. |
| Route parameters are checked before use | The detail page accepts only a UUID. Anything else shows "not found" and sends no request, so a crafted link such as `/indicators/..%2F..%2Fhealth` cannot make the app call a different API path. Identifiers placed in a request are URL-encoded. |
| Strict CSP is satisfied | The production HTML has no inline script, no `<style>` element, no `style=` attribute and no event handler, and nothing in the app needs the policy loosened (the styles the code sets, such as a legend swatch's opacity and the motion layer's pointer positions, are written through the CSSOM, and its animations run through the Web Animations API; the policy permits both). Every browser test fails on a CSP violation, so each screen, drawer and palette state it visits ran under the exact policy in `frontend/nginx.conf`. Twenty further scenes inject script, event handlers, `javascript:` links, styles, `<base>`, frames, forms, sockets, beacons and `data:` or `blob:` scripts into the running page, and check that the browser refuses each one; another test checks that `eval`, `new Function` and string timers are refused even from the app's own script file. |
| The motion layer adds no way in | Phase 3c's effects use anime.js through Web Animations, CSSOM writes and a 2D canvas. They read no provider text, make no request, store nothing, and use no `eval`, `new Function`, WebGL, inline style or other host. The built bundle was scanned: no `eval(`, no `new Function`, no source-map reference, only `.html`, `.css`, `.js`, `.svg` and `.woff2` files in the output, and the only host names in it are XML namespaces, placeholder and documentation addresses inside libraries, and the fixed OTX and MITRE link bases. The privacy browser test still checks every request of a full session against the page's own origin, and every browser test fails on a console error or warning, so a failing effect cannot hide. |
| Almost nothing is kept in the browser | The only thing the console stores is the visual-effects choice (`cipherforge.effects`, `on` or `off` in `localStorage`), and only after a person changes the switch. There is no `sessionStorage`, cookie, IndexedDB, cache or service worker. When sign-in exists, the token is requested for each call and never stored. The Indicators page keeps its filters, including the search text, in the address so that views can be bookmarked; that text can therefore appear in browser history. The command palette's "Search indicators" uses the same address. What is typed on the Investigate page, or handed to it from the palette, is sent in the body of a `POST` and is never put in an address. A browser test walks a full session and checks all of this. |
| No third party sees the analyst | The fonts, the world map and every icon are built into the console, so there is no CDN, font host or map tile server to learn who is using it. `Referrer-Policy: no-referrer` and `noreferrer` links keep the address from reaching OTX or MITRE. Requests use `cache: "no-store"` and the API replies `Cache-Control: no-store`. A browser test follows a session through every screen and checks that each request went to the console's own origin and carried no cookie and no `Referer`. Its check was shown to be able to fail: loosening the referrer policy made it fail. |
| No cross-site tricks | The API sends no CORS headers, so another site cannot read its answers. A form or `text/plain` request from another site is refused with `422` and starts no lookup. The same goes for deletion: it takes only a JSON body of ids (or one id in the path), so a form cannot trigger it, a cross-site preflight is answered without the headers that would allow it (unless `CORS_ORIGINS` names that site), and there is no endpoint that edits a stored indicator or deletes by filter. No address or link can start a lookup or a deletion either. A lookup starts only when the analyst presses Investigate or chooses the palette's Investigate entry, whose value travels in navigation state, not in an address. A deletion happens only when the analyst confirms the dialog that names what will go. Another site cannot put the console in a frame (`frame-ancestors 'none'` and `X-Frame-Options: DENY`). Each is tested in a browser or against the running API. |
| Responses are checked at run time | The client verifies the shape of each response before a screen uses it, so a mismatched version shows "Unexpected response from the API" instead of rendering missing fields, and keys it does not know are ignored, so an API that sends extra fields cannot change what is drawn. Errors show only the server's sanitised message and its correlation ID. The identity chip shows roles as text and never the name or subject in the token. |
| No false reassurance | An indicator that no provider answered about is shown as "Not assessed", never as Informational or clean, and its score is not shown; the overview counts those indicators as their own group. Each provider is displayed separately, and advice is labelled as advice that CipherForge never carries out. A result for one indicator cannot appear under another: requests are cancelled when the screen changes, and the detail page is keyed by indicator. A country on the map or in a list is labelled as provider-reported, never as where an attacker is. Every chart has a text equivalent with the exact numbers, and counts are shortened only with the exact value one hover away. When any provider is simulated, a banner says so on every screen. |
| Disclosure is stated | The Investigate page says the indicator is sent to each configured provider, outside the organisation, and asks the analyst not to submit anything they may not share. |

### Demo mode

Phase 3b added a development tool so that the dashboard can be seen and tested without provider keys:
`backend/devtools` runs the real application with simulated providers and a seeded two-week history.
It sets `ENVIRONMENT=development` and `AUTH_MODE=dev`, so it can never pass the production checks in
the settings, and its providers answer from an in-process stand-in for the network, so it makes no
outbound calls. Its database must be a `.db` file directly inside `backend/.demo/`; any other path is
refused, so it cannot be pointed at a real database. `backend/.dockerignore` keeps it out of the
image and nothing under `app/` imports it. Because the data is synthetic, the dashboard shows a
banner on every screen whenever any provider is simulated.

### Known limits of the frontend controls

- **No browser sign-in.** The dashboard works only against an API running `AUTH_MODE=dev`, which the
  API refuses in production. Against Entra ID authentication every screen shows "Not signed in".
- **The lint rule is a pattern match.** It catches the usual ways of injecting markup or code, not
  every conceivable one (for example, a variable passed to `setTimeout` is not flagged). The CSP
  and code review are the backstops.
- **The browser checks used a stand-in for nginx.** The tests serve the production build from a small
  Node server that sends the headers and policy it reads from `frontend/nginx.conf`, and further
  tests check the rest of that file as text (each header declared once, the hidden server version,
  the body limit, compression of static files only, what is proxied). The browser suite never ran
  against nginx or the container images. The CI `docker` job starts both and checks the page, the
  API behind nginx and the policy header, nothing more (see
  [deployment.md](deployment.md#verification-status)).
- **Only Chromium-based browsers.** The tests ran in Microsoft Edge on Windows and, in CI, in
  Chromium on Linux, which share one browser engine. Firefox and Safari were not tested, and no screen
  reader was used, so the accessibility checks are automated ones: axe-core, contrast, layout and
  keyboard operation of the shell, palette and drawers.
- **Search text is in the address bar.** Anyone with access to the browser profile, or to a shared
  link, can see what was searched for in the Indicators list.
- **Reads are not throttled.** The overview is computed on every request from bounded scans (the
  newest 2,000 provider answers, and up to 20,000 lookups and 20,000 new indicators from the last
  14 days), and the response says when a bound cut a figure short. There is no per-user limit on
  reads, so many dashboards refreshing every minute add up. Cache or pre-aggregate it before a busy
  installation uses it.
- **The effects were not tuned on slow hardware.** The particle field is capped and drawn at 30
  frames a second, backdrop blur is only used while effects are on, and one switch (or the system's
  reduced-motion setting) stops everything, but nobody measured the frame rate on an old laptop or
  phone. A person who finds it heavy should switch the effects off.
- **The look has not been judged by eye.** The redesign was checked by measurement: layout and
  overflow at eight window sizes and at 200% text with the effects off and, with them on, at desktop
  and phone width; contrast on every text run; that each effect is really running; and that nothing
  it does reaches the console or the network. A person has not yet reviewed it on a screen.

## Implemented controls (Phase 4: expansion)

Phase 4 added IST display, two more intelligence providers (VirusTotal and ThreatFox), network
monitoring and encrypted file sharing. The provider controls are in the Phase 2 table above; the
rest are below. Each module guide holds the detail behind its rows.

### Time

The database, the API and the audit trail hold timezone-aware UTC. India Standard Time
(`Asia/Kolkata`, written `DD-MM-YYYY hh:mm:ss A IST`) is applied only when a time is shown to a
person: in the dashboard and in generated text such as alert explanations. `APP_TIMEZONE` accepts no
other zone. Share expiry and capture retention are computed in UTC, so the display zone cannot
change what the system decides.

### Network monitoring

Guides: [network-monitoring.md](network-monitoring.md) and [detection-engine.md](detection-engine.md).

| Control | Detail |
| --- | --- |
| Roles and ownership | Every `/api/v1/network` route needs `SecurityAnalyst` or `Admin`. A session, its flows and its alerts belong to the user who created it. Another user's id answers `404`, the same as an id that does not exist, and only the user who started a capture can stop it. There is no administrator override. |
| Metadata only | Only time, addresses, ports, protocol, packet length and TCP flags are read. Payloads, MAC addresses, DNS names and application data are never stored or logged, and an uploaded capture file is deleted once it has been analysed. |
| No invented traffic | The module analyses what it captures or is given. Synthetic traffic exists only in labelled demo and test tooling (`backend/devtools`, `frontend/e2e/data/synthetic-network.pcap`), which nothing under `app/` imports. |
| Least privilege | Nothing in the application raises its own privileges. The sniffer does not use promiscuous mode, and when the operating system refuses capture the session ends as `capture_permission_denied`. The containers drop every capability, so live capture runs on the host and capture-file analysis also works in the container. |
| Safe uploads | Raw body only (`application/octet-stream`). The declared length is checked before the body is read and the stream is cut at the limit (`NETWORK_MAX_PCAP_SIZE_MB`, default 50, at most 500). The file goes to a private temporary folder under a random name, is structure-checked before analysis and is removed afterwards. Its name is a sanitised display label and never a path. |
| Bounded memory and work | A bounded packet queue, at most 10,000 active flows, 20,000 stored flows per session, capped rule windows and tracked-source tables, 500 alerts per session and 200 per rule, one live capture and one analysis at a time, a 600-second analysis limit, and retention that deletes old sessions (72 hours by default). Whatever a limit cuts short is counted and shown, never dropped silently. |
| Enrichment sends public addresses only | Private, loopback, link-local, multicast, reserved and documentation addresses are never sent to a provider, and only the address text leaves. Lookups are paced (`NETWORK_ENRICHMENT_MAX_PER_MINUTE`), capped per session (`NETWORK_ENRICHMENT_MAX_IPS`) and can be switched off (`EXTERNAL_ENRICHMENT_ENABLED`). They use the same intelligence service as the Investigate page, so key handling, caching, request-forgery checks and the audit trail apply unchanged. |
| Rate limits | Refreshing the interface list, uploading a capture file and enriching an alert draw on the same per-user budget as investigations. |
| Audit trail | `NETWORK_CAPTURE_START`, `NETWORK_CAPTURE_STOP`, `NETWORK_PCAP_ANALYZE`, `NETWORK_SESSION_DELETE` and `NETWORK_ENRICH` say who did what, with counts and an interface name or file size. They never hold addresses or file names. |
| Errors and logs | Every failure has a fixed code and message. Exception text, paths and file names never reach the client, and the logs carry error class names, session identifiers and counts. |
| Advice, not action | Alerts say "suspected" and show their evidence. Nothing is blocked automatically, and no alert names a person. |

### Encrypted file sharing

Guides: [file-sharing.md](file-sharing.md) and [encryption-design.md](encryption-design.md).

| Control | Detail |
| --- | --- |
| Off until a key is set | `CIPHERFORGE_MASTER_KEY` (32 random bytes, base64url) switches the feature on. A malformed value stops the API at start-up with a message that names the setting and never the value. A blank value leaves the feature off, and its routes answer `503 feature_not_configured`. The key is a `SecretStr`, masked in logs by exact value. |
| Authenticated encryption | AES-256-GCM with a fresh random data key for every file, a fresh random 96-bit nonce for every encryption and a 16-byte tag. The data key is stored wrapped under the master key, and the file name is encrypted too. Each ciphertext is bound to its database row by additional authenticated data, so a ciphertext moved to another row fails verification. Plaintext is released only after the tag verifies. Algorithms and the nonce argument are in [encryption-design.md](encryption-design.md). |
| Share tokens | 256 bits from `secrets.token_urlsafe(32)`, shown once when the link is created. Only a SHA-256 of the token is stored, so a copy of the database does not give out working links. The API masks tokens in its own logs and the bundled nginx leaves them out of its access log. |
| Password-protected links | The password is never stored, not even as a hash. A second wrapping of the data key is derived from it with Argon2id (3 passes, 64 MiB, one lane, 16-byte salt) and HKDF with the master key, so a wrong password simply fails to open the key. Passwords are 8 to 128 characters. Wrong guesses are limited per link and per client (5 in 15 minutes by default, answer `429`), and at most two derivations run at once. |
| Link rules enforced by the server | Expiry (24 hours by default, 30 days at most), a download limit (1 by default, 100 at most), revocation and the password are checked in a fixed order on every request. A download is reserved with one atomic conditional database update, so concurrent requests cannot exceed the limit, and a failed or rejected request uses no download. |
| Owner-only management | Files, links and per-file activity belong to their owner (the token subject). Another user's file and an id that does not exist answer the same `404 file_not_found`, and no role bypasses this. A link holder can only open and download through the link. |
| Safe uploads and names | Raw body only, `application/octet-stream` (multipart is refused so that no plaintext reaches a temporary file). The declared length is checked before the body is read, and the size limit is 25 MiB by default (100 at most). The name is cleaned (control and direction-override characters, path parts, characters Windows forbids, reserved device names) and is never used as a path; blobs are stored under random names. |
| Safe downloads | `Content-Disposition: attachment` with an RFC 8187 name, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; sandbox` and `Referrer-Policy: no-referrer`, so a browser treats the bytes as an opaque download. |
| Tamper detection | A blob that fails verification, is missing or has the wrong size quarantines its file (`corrupt`), writes `FILE_INTEGRITY_FAILED` and uses no download. |
| Rate limits | Per-user limits on upload and link creation and a per-client limit on public link requests (`FILE_UPLOAD_RATE_LIMIT_PER_MINUTE`, `SHARE_CREATE_RATE_LIMIT_PER_MINUTE`, `SHARE_DOWNLOAD_RATE_LIMIT_PER_MINUTE`). All answer `429` with `Retry-After`. |
| Audit trail | Ten actions, from `FILE_CREATE` to `SHARE_LIMIT_REACHED`, listed in [file-sharing.md](file-sharing.md#audit-events). Contents, file names, passwords and tokens are never recorded, and link holders appear as `anonymous`. An owner sees time, action, result, link and reason for their own files, and never a source address. |
| Failure text | A database error on these routes is logged by exception type only, because its text can contain key material. Clients get fixed messages. |

### The Network, Files and Share screens

The rules in [Frontend controls](#frontend-controls-phases-3-to-3c) apply to the new screens
unchanged: the same lint rules, the same Content Security Policy, no third-party request. What the new
screens add:

| Control | Detail |
| --- | --- |
| Wire data and file names are only text | Addresses, interface names, rule evidence, alert text, file names and activity entries are rendered as React text. Component tests give the Network and Files screens values built as markup (`<img src=x onerror=alert(1)>`, `<script>`) and check that they stay text, and a browser test does the same with hostile file names, in the list, the details and the activity log. |
| The public page sits outside the console | `/share/:token` has no navigation, no identity request and no sign-in. The token goes to the API only in the request path, the password only in the body of a `POST`, and the page title is always "Shared file", so neither the token nor the file name reaches browser history or a tab strip. The page adds `<meta name="robots" content="noindex,nofollow">`. |
| The link is shown once | The API returns the token only when the link is created. The page builds the address from its own origin and holds it in memory until the owner hides it. Nothing is written to browser storage, and the list of links never contains an address. |
| Downloads are saved, never opened | The decrypted file is offered as a download under a name that the browser code cleans again (`sanitizeFileName`), through a `blob:` URL that is revoked 10 seconds later. The page never renders or opens the file. |
| Nothing new is kept in the browser | The only storage the console uses is still the visual-effects switch. A capture's addresses and a file's name stay in the page and are gone when it is closed. |

### Known limits of the Phase 4 controls

- **Server-side encryption, not end-to-end.** The server sees plaintext while it encrypts and decrypts
  and holds the master key, so whoever controls the server and its key can read every file. Files are
  protected at rest and from other users of the application, not from the operator.
- **One master key, no rotation, no recovery.** Losing it makes every file unreadable, and there is
  no tool to re-wrap files under a new key. Back it up together with the database and the blob
  directory, and keep it in a secret store in production.
- **Limits live in process memory.** The file rate limits and the wrong-password budget, the
  investigation limiter, the one-capture rule and the enrichment pacing reset when the API restarts
  and are not shared between workers. Run one API worker, and add a limiter at the proxy before
  scaling out.
- **Whole files are held in memory** while they are encrypted or decrypted (up to 100 MiB with the
  largest setting), Python cannot reliably wipe secrets from memory, and deleting a file removes its
  blob without overwriting it.
- **Share links reach proxies.** A proxy or load balancer in front of the API must also keep share
  tokens out of its logs. The bundled nginx redacts them in its access log but not in its error log
  (see [deployment.md](deployment.md)).
- **No scanning of uploads.** Files are opaque bytes, and a recipient gets exactly what was uploaded.
- **Heuristic network rules.** They judge headers only, harmless traffic can trip them and a spoofed
  source can fool them. Thresholds are starting points (see
  [detection-engine.md](detection-engine.md#limitations)).
- **Live capture is verified on one platform.** It was run for real on Windows with Npcap, without
  elevated rights. The Linux paths are covered by unit tests that fake the platform.
- **Capture data is personal data.** Addresses identify people. Keep retention short, capture only
  networks you are authorised to monitor, and see
  [Data collected and privacy](network-monitoring.md#data-collected-and-privacy).
- **No independent review.** The design uses standard primitives from the `cryptography` library
  (AES-GCM, HKDF, HMAC-SHA256, Argon2id) and no home-made ones, but nobody outside this project has
  reviewed it.

## Dependency management

Pins and the reasoning behind the non-obvious ones:

| Dependency | Decision |
| --- | --- |
| Python packages | Direct dependencies pinned in `requirements.txt`; transitive packages float within them. `pip-audit` checks the resolved set in CI. A hash-locked file (`pip-compile --generate-hashes`) is a possible later hardening. |
| `httpx2` | The maintained continuation of HTTPX. Starlette's test client prefers it, and the provider adapters use it. Its request logging is silenced because it records full URLs. |
| `cryptography` 50.0.2 | AES-256-GCM, HKDF, HMAC and Argon2id for encrypted file sharing. PyJWT's `crypto` extra already depends on it, so it adds no new package to the image. Exactly pinned; no cryptographic primitive is implemented in the repository. |
| `scapy` 2.8.0 | Reads PCAP and PCAPNG files and sniffs live packets. It is imported on first use and only its Ethernet, IPv4, IPv6 and SCTP protocol modules are loaded. Live capture also needs Npcap (Windows) or libpcap (Linux) on the host, which pip does not install. **Licence:** Scapy is GPL-2.0-only, and CipherForge is MIT. Running the two together on your own machine is fine. If you redistribute CipherForge with Scapy (an image, for example), the combined work carries GPL obligations, so check that before publishing one. |
| `tzdata` 2026.6 | The IANA time-zone database. Windows has none, and the IST display needs `Asia/Kolkata` from `zoneinfo`. |
| TypeScript 6.0.3 | The latest stable `typescript-eslint` does not support TypeScript 7 yet. Revisit when it does. |
| anime.js 4.5.0 | The animation library behind the visual effects (Phase 3c). MIT licence, no dependencies of its own (its optional peers `three` and `@types/three` are not installed), exactly pinned, and imported from one file (`src/motion/anime.ts`), so only the parts the app uses are in the bundle. It is the only runtime dependency added in Phase 3c; `npm audit` and Dependabot cover it like the rest. Its lockfile entry carries the registry's SHA-1 integrity value, as do a little over half of the lockfile's entries. |
| `minimatch` override (`11.0.4`) | Dev-tooling dependencies pulled in a `minimatch` version affected by a denial-of-service advisory (GHSA-g3hv-75wg-m249). The override fixed the finding. Remove it once upstream packages update. |
| `picomatch` advisory (withdrawn) | GHSA-fc5q-39xc-vjpf (a regular-expression denial of service in `picomatch` through 4.0.7 that needs a specially crafted glob pattern) was published on 19 October 2026 and withdrawn by GitHub on 18 November 2026 as not a security issue. While it was open no fixed version existed, and `npm audit` flagged 12 build, lint and test tools because of it (`picomatch` itself, `vite`, `vitest`, `typescript-eslint` and the packages that depend on them). None ships in the dashboard: they read patterns only from this repository's own configuration and run on developer machines and in CI. That is why CI audits twice: a blocking step for what ships (`npm audit --omit=dev`) and a second step for everything, which only reports. Both audits reported no vulnerabilities on 26 November 2026, so removing `continue-on-error` from the second step in `.github/workflows/ci.yml` would make it blocking again; nobody has made that decision yet. |
| Node 24 image | The toolchain needs a recent Node (Vitest 5 requires 22.12 or newer, and `package.json` sets `engines` to 22.22 or newer); CI and the Docker build use Node 24. |

Update flow: Dependabot opens a pull request, CI runs every check and the stack smoke test, and a
human reviews the change before merging.

## Not implemented yet

| Gap | Planned |
| --- | --- |
| A rate limit shared by several API replicas | The in-process limiter is per instance. Add one at the proxy, or Redis, before running more than one replica. |
| Rate limiting beyond the routes that have it, and brute-force protection | Investigations, three network routes and the file routes are limited. List and detail reads and failed sign-ins are not throttled: authentication failures are cheap to reject, but they are not counted. |
| Audit log viewer, export and retention policy | Later phases. Apart from the per-file activity list that a file's owner sees, the table is write-only from the application's point of view. |
| Sign-in in the browser (MSAL) | Not built. The dashboard works with `AUTH_MODE=dev` only; a real tenant needs sign-in added. |
| Dashboard views of incidents, cases and cross-source telemetry | Later phases, with the data they show. The charts that exist draw threat-intelligence data and CipherForge's own lookup history, and the Network page shows capture sessions, flows and alerts. |
| CodeQL and Trivy (container and filesystem) scanning | Phase 12, once the repository is hosted. |
| SBOM generation and image signing | Phase 12. |
| Azure Key Vault, managed identities, Azure Monitor | Phase 11. Until then the provider keys and `CIPHERFORGE_MASTER_KEY` come from the environment. |
| Resource-level authorisation for incidents and cases | With those features. Files and network sessions are already owner-scoped; indicators are not (any analyst can delete any indicator). |
| End-to-end encryption, master-key rotation, a key-management service for the file master key | Not built. Files are encrypted on the server today ([encryption-design.md](encryption-design.md)); changing that needs its own threat-model update and review first. |
| Automatic clean-up of expired links and unused blobs | Not built; the owner deletes them ([file-sharing.md](file-sharing.md#limitations)). |
| Alert workflow, correlation with internal evidence, remote sensors | Planned, not built ([detection-engine.md](detection-engine.md), [../sensor/README.md](../sensor/README.md)). |

## Responsible use

Run packet capture, load generation and honeypots only on systems and networks you own or are
explicitly authorised to test. Do not collect third-party traffic or sensitive data. IP reputation
and geolocation are evidence about an address, not about a person, and must never be presented as
the location or identity of an attacker. The Network page captures only what you point it at, and
what it stores is described in [network-monitoring.md](network-monitoring.md#data-collected-and-privacy).
Upload to the file-sharing feature only data you are allowed to store and share.

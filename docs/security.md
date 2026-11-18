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
[deployment.md](deployment.md#verification-status). The Phase 3 to 3c bundle was later loaded in a
real browser under the same policy; see [Frontend controls](#frontend-controls-phases-3-to-3c).

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
  suite, and builds the images. GitHub Actions are pinned to commit SHAs, workflow permissions are
  `contents: read`, and checkout does not persist credentials.
- Dependabot is configured for pip, npm, Docker, Compose and GitHub Actions.

## Implemented controls (Phase 2: threat intelligence)

| Control | Detail |
| --- | --- |
| Authorisation | Every `/api/v1/intel` route requires `SecurityAnalyst` or `Admin`; everything else is denied. |
| Rate limiting | `POST /investigate` is limited for each authenticated user (default 30 a minute) and answers `429` with `Retry-After`. Authorisation runs first, so a caller who is not allowed in never uses anyone's budget. The limiter is in memory and per process (see the gaps below). |
| Audit trail | Every investigation, including refused input, writes an `audit_logs` row (actor, action `IOC_LOOKUP`, target, result, source address, correlation ID) in the same transaction as the work it describes. So does every deletion of a stored indicator: one `IOC_DELETE` row for each indicator removed. Database triggers reject `UPDATE` and `DELETE` on those rows, on SQLite and PostgreSQL, and no endpoint or screen can delete or edit an audit row. Secrets and provider payloads are never recorded. |
| Deleting indicators | An analyst can delete a stored indicator, or several, from the Indicators page or an indicator's own page (`DELETE /indicators/{id}`, `POST /indicators/bulk-delete`). The request names exact ids, so it can remove only what it names: there is no "delete everything matching this search". One request carries at most 100 ids, the same roles as the rest of `/api/v1/intel` are needed, and the dashboard always asks for confirmation first, naming what will go. The indicator and every provider answer stored for it are removed in one transaction that also writes the `IOC_DELETE` audit rows, so either all of it happens or none of it does. A lookup that was still waiting on providers when its indicator was deleted is discarded with `409` instead of bringing the indicator back. SQLite overwrites the freed bytes (`secure_delete`), and foreign keys are enforced so nothing is left pointing at a deleted row. |
| Provider API keys | Read from the environment as `SecretStr`, masked in logs by exact value, never returned by the API (the stats endpoint only says whether a key is set), and passed to the `backend` container only, not to the one-shot `migrate` job. A test fails if Compose drifts from this. |
| No request forgery | The backend contacts two fixed provider hosts. An indicator is validated first (non-public addresses and reserved names are refused), appears in a request only as an escaped path or query value, and redirects are not followed. |
| Bounded provider calls | 5-second connect timeout, a configurable overall timeout, a 2 MiB response cap and a small connection pool. Providers run in parallel against one shared deadline, and a failure degrades that provider only. |
| Untrusted provider data | Parsed defensively into whitelisted, size-limited fields. Text is stripped of control and invisible characters and truncated, counts are bounded, and implausible dates are discarded. Free text from a provider is community-supplied and must only be displayed as text. |
| No indicator or key in logs | HTTP client libraries log full request URLs at INFO, which would contain the indicator and could contain a credential. The `httpx`, `httpx2`, `httpcore` and `httpcore2` loggers are silenced, and a test guards it. Application logs record the indicator type and score, never the value. |
| Valid source address only | The audited address is stored only if it is a valid IP address. Behind nginx it comes from `X-Forwarded-For`, which uvicorn does not validate, so a hostile value is dropped rather than stored. |
| Strict indicator input | Length limit, whitespace and invisible characters refused, SHA-256 only, `http`/`https` URLs only, no credentials in URLs. Error messages never echo the input. |

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

## Dependency management

Pins and the reasoning behind the non-obvious ones:

| Dependency | Decision |
| --- | --- |
| Python packages | Direct dependencies pinned in `requirements.txt`; transitive packages float within them. `pip-audit` checks the resolved set in CI. A hash-locked file (`pip-compile --generate-hashes`) is a possible later hardening. |
| `httpx2` | The maintained continuation of HTTPX. Starlette's test client prefers it, and the provider adapters use it. Its request logging is silenced because it records full URLs. |
| TypeScript 6.0.3 | The latest stable `typescript-eslint` does not support TypeScript 7 yet. Revisit when it does. |
| anime.js 4.5.0 | The animation library behind the visual effects (Phase 3c). MIT licence, no dependencies of its own (its optional peers `three` and `@types/three` are not installed), exactly pinned, and imported from one file (`src/motion/anime.ts`), so only the parts the app uses are in the bundle. It is the only runtime dependency added in Phase 3c; `npm audit` and Dependabot cover it like the rest. Its lockfile entry carries the registry's SHA-1 integrity value, as do a little over half of the lockfile's entries. |
| `minimatch` override (`11.0.4`) | Dev-tooling dependencies pulled in a `minimatch` version affected by a denial-of-service advisory (GHSA-g3hv-75wg-m249). The override keeps `npm audit` at zero findings. Remove it once upstream packages update. |
| Node 24 image | The toolchain needs a recent Node (Vitest 5 requires 22.12 or newer, and `package.json` sets `engines` to 22.22 or newer); CI and the Docker build use Node 24. |

Update flow: Dependabot opens a pull request, CI runs every check and the stack smoke test, and a
human reviews the change before merging.

## Not implemented yet

| Gap | Planned |
| --- | --- |
| A rate limit shared by several API replicas | The in-process limiter is per instance. Add one at the proxy, or Redis, before running more than one replica. |
| Rate limiting for routes other than investigations, and brute-force protection | With the features that add them. Authentication failures are cheap to reject, but are not throttled. |
| Audit log viewer, export and retention policy | Later phases. Today the table is write-only from the application's point of view. |
| Sign-in in the browser (MSAL) | Not built. The dashboard works with `AUTH_MODE=dev` only; a real tenant needs sign-in added. |
| Dashboard views of telemetry, alerts and incidents | Later phases, with the data they show. The charts that exist draw threat-intelligence data and CipherForge's own lookup history. |
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

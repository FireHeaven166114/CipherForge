# Project status and history

This is the long, phase-by-phase record of what has been built. If you are new here, start with the
[README](../README.md), which explains the project in plain words. Come back to this page when you want
the detail: what each phase added, and what is still missing.

## Status

The project is built in vertical slices, each one tested before the next begins. Phases 1 to 3c are
tagged (`v0.1.0-phase1` up to `v0.5.0-phase3c`); Phase 4 has no tag yet.

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Foundation: FastAPI, React + TypeScript, PostgreSQL, Docker Compose, configuration, logging, auth shape | **Done.** The Docker stack is built and smoke-tested by CI on a GitHub runner but has not been run on a personal computer, see [verification status](deployment.md#verification-status) |
| 2 | Threat Intel MVP: AbuseIPDB + AlienVault OTX, normalisation, persistence, caching, risk score | **Done** (backend and API). Providers are tested against canned answers; AbuseIPDB and OTX have also been called for real (by the opt-in live test and by the author's own installation), see [threat-intelligence.md](threat-intelligence.md#verification-status) |
| 3 | SOC dashboard: investigation view, IOC table and search, charts | **Done** (React dashboard for the Phase 2 API). Works against `AUTH_MODE=dev` only: there is no browser sign-in yet |
| 3b | Command deck: a redesigned futuristic UI, the `/overview` aggregates, a demo mode with simulated providers, and an end-to-end browser test suite | **Done.** Tested against simulated providers only, see [Testing the dashboard](testing.md#testing-the-dashboard) |
| 3c | Aurora Forge: every screen restyled as spectral glass over a layered, animated background, with a light that follows the pointer, a sliding navigation lamp and choreographed entrances, built on anime.js | **Done.** Visual only: the routes, API calls, wording and behaviour are the same as in 3b. See [the screenshots](../README.md#using-the-dashboard), [Phase 3c](#what-works-today) and [Testing the dashboard](testing.md#testing-the-dashboard) |
| 4 | Expansion: India Standard Time on screen, VirusTotal and ThreatFox, MD5 and SHA-1 indicators, network monitoring (live capture, capture-file analysis, rules NET-001 to NET-007, enrichment), encrypted file sharing | **Done**, with limits: VirusTotal and ThreatFox have never been called for real (no keys were available), live capture was tried on Windows only, and file encryption is server-side. See [Phase 4: expansion](#phase-4-expansion) and the [verification status](deployment.md#verification-status) |
| 5-12 | A separate network sensor, further detection, correlation, mini-SIEM, cases, integrations, Azure (11), DevSecOps (12) | Not started |

The roadmap follows the project specification; see [architecture.md](architecture.md#module-map) for
how each module (Intel, Sentinel, Core, SOC, Case, Vault) maps to the code. Phase 4 was built ahead of
the roadmap's order: it delivers the Sentinel module (inside the API process, not as a separate
sensor) and the Vault module, which the roadmap scheduled later. The remaining phases keep their
numbers.

## What works today

**Phase 1: foundation**

- `GET /health` (liveness) and `GET /ready` (checks the database connection) with stable JSON.
- `GET /api/v1/me`: the authenticated identity and roles. Microsoft Entra ID access tokens are
  validated (signature, issuer, audience, tenant, expiry) and mapped to the `Admin`,
  `SecurityAnalyst` and `User` roles. A local `dev` mode exists for development only.
- Structured JSON logging with secret redaction, correlation IDs on every request and a uniform
  error format.
- A React + TypeScript status page that shows the API and database health (kept at `/status` by the
  Phase 3 dashboard).
- PostgreSQL with SQLAlchemy and Alembic migrations.
- Docker Compose for the whole stack, and a GitHub Actions pipeline (lint, tests, security checks,
  dependency audits, image build and a stack smoke test).

**Phase 2: threat intelligence (API)**

- `POST /api/v1/intel/investigate` takes one indicator (IPv4, IPv6, domain, URL or SHA-256; defanged
  forms such as `hxxp://example[.]com` are accepted), validates and normalises it, asks AbuseIPDB
  and AlienVault OTX where they apply, and returns **each provider's answer on its own**, then an
  explainable CipherForge score from 0 to 100 with its confidence, the evidence it rests on, what is
  not known and recommended next steps. One source alone can never push the score above 60.
- `GET /api/v1/intel/indicators` (search, filter, page), `GET /api/v1/intel/indicators/{id}`,
  `GET /api/v1/intel/stats` and `GET /api/v1/intel/overview` (the aggregates behind the dashboard)
  read the stored results without contacting a provider.
- `DELETE /api/v1/intel/indicators/{id}` and `POST /api/v1/intel/indicators/bulk-delete` (up to 100
  ids) delete stored indicators and the provider answers stored for them. See
  [Deleting indicators](#deleting-indicators-after-phase-3c).
- Answers are cached in PostgreSQL (6 hours for AbuseIPDB, 12 for OTX by default; Phase 4 added 24
  hours for VirusTotal and 6 for ThreatFox). A provider that is missing, slow or failing shows up as
  a labelled status; it never breaks the lookup.
- Every investigation, including refused input, and every deletion of a stored indicator is written
  to an append-only audit table.
  Investigations are rate-limited per analyst. Access needs the `SecurityAnalyst` or `Admin` role.
- Private, loopback and reserved addresses and internal names are refused before any outside call.

The method is documented in [threat-intelligence.md](threat-intelligence.md) and the
endpoints in [api.md](api.md). This block describes Phase 2 as it was built; Phase 4 later added two
providers (VirusTotal and ThreatFox) and MD5 and SHA-1 hashes, see [Phase 4: expansion](#phase-4-expansion).

**Phase 3: investigation dashboard**

A React single-page app over the Phase 2 API. These are its five screens as they stood after
Phase 3b, which added the Overview and the new look. Phase 4 later added the Network and Files
screens (seven in all, see [Phase 4: expansion](#phase-4-expansion)):

- **Overview**: the command deck described under Phase 3b.
- **Investigate**: enter an indicator and see the result at once. Each provider is shown on its own
  card (status, freshness, its own evidence), followed by the CipherForge score with the factors
  behind it, what is not known and the recommended next steps. An internal-evidence card is kept and
  marked "Not available" rather than left out: no internal telemetry feeds an investigation yet.
- **Indicators**: search, filter by type and risk (a band, High and Critical together, or Not
  assessed), sort by recent check or by risk, and page through the stored results. The filters live
  in the address, so a view can be bookmarked. Rows can be ticked and deleted (see below).
- **Indicator details**: the stored record, with a button to re-check it with the providers and a
  button to delete it.
- **System status**: API and database health, as before.

An indicator that no provider answered about is shown as **"Not assessed"**, never as low risk or
clean. Text that comes from a provider is rendered as plain text, and links to outside sites are built
only from identifiers that match a strict pattern.

**Phase 3b: the command deck**

The dashboard was redesigned as a dark, dense "command deck" in the spirit of a threat-intelligence
workbench, and given one aggregate endpoint to draw from:

- **Overview** is one screen of live figures from `GET /api/v1/intel/overview`: five headline tiles
  (each opens the matching filtered list; indicators and lookups also show their change on the
  previous 24 hours), a 14-day trend of lookups and high-risk lookups, the risk bands, a map and
  ranked lists of provider-reported countries, malware families, ATT&CK techniques and provider
  tags (select one to see the indicators behind it), indicators by type and risk, an hourly activity
  grid, the providers, the highest-risk and latest indicators, and the platform modules, with the
  ones not built yet marked **Planned**. It refreshes itself every minute.
- **Keyboard first.** `/` or `Ctrl K` opens a command palette (go to a page, investigate or search
  for what you typed); `G` then `O`, `I`, `L` or `S` jumps to a page (Phase 4 added `N` and `F`).
- **Effects you can switch off.** An animated background, a light that follows the pointer, numbers
  that count up and charts that draw themselves (Phase 3c made them richer). The switch is in the
  header, and they stay off when the system asks for reduced motion.
  Nothing depends on them: every figure also exists as text.
- **Honest by construction.** Large counts are shortened with the exact value kept in tooltips and for
  screen readers, "Not assessed" is its own group, the map says it shows the country a provider
  reports and not where an attacker is, and a banner appears whenever the providers are simulated.
- **Responsive.** Each part lays itself out by the width it is given and by the text size, so it
  works from a phone to a wide screen and at larger text.
- **Self-contained and private.** Fonts and map data are bundled, so the page makes no third-party
  requests, sets no cookies and stores nothing in the browser except the effects switch.
- **Tested end to end** in a real browser, from the form to the record, the list and the totals; see
  [Testing the dashboard](testing.md#testing-the-dashboard).

**Phase 3c: Aurora Forge**

Every screen was restyled and given a motion layer, and nothing was added to what it does: the same
screens, routes, API calls, wording, roles and shortcuts. The Phase 3b browser suite still passes
with one spec changed: the contrast audit now measures against the new, lighter glass colour and
hides the new decorative layers. To see it, start the [demo](../README.md#try-it-without-api-keys)
and open <http://127.0.0.1:5173>; the Effects switch in the header shows the page with and without
the layers.

- **Spectral glass.** Panels are translucent glass with a cyan, violet and magenta edge, headings
  carry a gradient, and badges and chips sit on solid plates so their text keeps its contrast
  whatever the background is doing.
- **A layered, living background.** Aurora orbs drift and lean away from the pointer, a perspective
  grid slides toward you, 18 to 72 dots drift, link up and are pushed aside by the pointer (a 2D
  canvas at 30 frames a second), and a soft light follows the cursor, all under film grain and a
  vignette.
- **Glass that catches the light.** Panels, buttons, chips and navigation links near the pointer
  light up where it is.
- **A navigation lamp.** A lit pill glides to the page you open, on the side rail and on the phone's
  bottom bar, and goes out on a page that has no link.
- **Entrances.** Panels, tiles and page headers arrive in a short staggered wave, headline numbers
  count up and each page's title decodes letter by letter. What a screen reader reads never changes
  while this happens, and a finished entrance leaves no styles behind.
- **Still optional.** All of it is behind the header's Effects switch, stays off when the system asks
  for reduced motion, and the pointer effects are skipped on touch screens.
- **Built on [anime.js](https://animejs.com)** (MIT, version 4.5.0, pinned, no dependencies of its
  own) with CSS and a 2D canvas: no WebGL and no `eval`, and no `style=` attributes or `<style>`
  elements in the markup (the motion layer writes styles through the CSSOM and animates with the Web
  Animations API, both of which the policy allows), so the Content Security Policy is unchanged. See
  [architecture.md](architecture.md#aurora-forge-and-the-motion-layer).
- **Where the ideas came from.** The spotlight cards, the "tubelight" navigation bar and the
  layered pointer-reactive background follow patterns seen on [21st.dev](https://21st.dev) and
  [GetLayers](https://getlayers.ai). No component, prompt or code from either was copied: 21st.dev's
  installer needs a signed-in membership and its components belong to their authors, and GetLayers'
  terms forbid redistributing its prompts, so everything here was written for this project. See
  [Credits](../README.md#credits).

## Deleting indicators (after Phase 3c)

Added after Phase 3c, with no change to its look or any existing behaviour: analysts can delete the
indicators they have investigated, one at a time or a selection at once.

- **On the Indicators page** every row has a tick box and a bin button. Tick rows (Shift-click ticks
  everything between two boxes, the box in the header ticks the whole page) and press **Delete
  selected**, or press one row's bin. **On an indicator's own page** a **Delete** button does the
  same for that one indicator.
- **Always confirmed.** A dialog names what is about to go (the first five values and how many more)
  and says it cannot be undone. Nothing is deleted until it is confirmed, and Cancel and Escape
  leave everything as it was.
- **Really deleted.** The indicator and every provider answer stored for it are removed from the
  database in one transaction, and from every list, chart and count that shows indicators.
  Investigating the same value again later starts a new record.
- **The audit trail is not touched, on purpose.** It stays append-only and there is no feature to
  delete audit rows. Each deletion adds an `IOC_DELETE` row saying who deleted what and when. Audit
  rows name the `type:value` they are about, so a deleted value can still be read there. See
  [security.md](security.md#known-limits-of-the-phase-2-controls).
- **Safe by construction.** Deletion is by exact id (never "everything matching this search"), at most
  100 ids a request, for analysts and admins only, and a form or link from another site cannot
  trigger it. See [security.md](security.md) and [threat-model.md](threat-model.md) (rows 41 to 45).

## Phase 4: expansion

Phase 4 widened the project in four directions. Each item says what exists; the guide it links to
holds the detail, so nothing is repeated here.

- **India Standard Time on screen.** The database, the API and the audit trail still hold UTC. Every
  time a person reads (the dashboard, the header clock, text the backend writes, per-day buckets) is
  shown as `DD-MM-YYYY hh:mm:ss A IST`. See
  [Time handling](architecture.md#time-handling-utc-storage-ist-display).
- **Two more providers and two more hash types.** VirusTotal (API v3) and abuse.ch ThreatFox join
  AbuseIPDB and AlienVault OTX, and the Investigate page accepts MD5 and SHA-1 hashes next to SHA-256.
  The score method (`intel-risk-v1`) is unchanged: the new providers only add evidence to it, and
  "No data" from any provider still means "not assessed", never "safe". VirusTotal and ThreatFox are
  only asked about an indicator (lookups); nothing is uploaded or submitted for scanning. See
  [threat-intelligence.md](threat-intelligence.md).
- **Network monitoring** (the Sentinel module, inside the API process). A user with the
  `SecurityAnalyst` or `Admin` role starts a live capture on a host interface, or uploads a `.pcap`,
  `.pcapng` or `.cap` file. The module reads packet headers only, builds flows, applies seven detection rules
  (NET-001 to NET-007: port scan, connection rate, SYN rate, high volume, known-malicious address,
  suspicious port, unexpected protocol) and can look up the public addresses in an alert with the
  providers. Sessions, flows and alerts belong to the user who created them. 12 endpoints under
  `/api/v1/network`, and the **Network** screen. See [network-monitoring.md](network-monitoring.md)
  and [detection-engine.md](detection-engine.md).
- **Encrypted file sharing** (the Vault module). Any signed-in user (`User`, `SecurityAnalyst` or
  `Admin`) uploads a file, which is encrypted with AES-256-GCM under a fresh key per file, and creates
  share links with an expiry, a download limit, an optional password and revocation. The owner sees
  an activity list for each file; the link holder needs no account. 8 owner endpoints under
  `/api/v1/files`, 3 public ones under `/api/v1/shares`, the **Files** screen and a public **Share**
  page. The feature stays off until `CIPHERFORGE_MASTER_KEY` is set. It is server-side encryption,
  not end-to-end, and nobody outside the project has reviewed the design. See
  [file-sharing.md](file-sharing.md) and [encryption-design.md](encryption-design.md).
- **The dashboard** now has seven screens (Overview, Investigate, Indicators, Indicator details,
  Network, Files, System status) and the public Share page. `G` then `N` or `F` jumps to the new
  ones, and the command palette lists them. The Overview's modules panel marks Network monitoring
  and Secure file sharing as Live.
- **The database** gained three migrations, `0003` (hash indicators), `0004` (network monitoring) and
  `0005` (encrypted files). Existing rows are left alone, and the downgrade path is tested (the `0003`
  downgrade refuses to run while MD5 or SHA-1 indicators are stored). See
  [setup.md](setup.md#environment-variables) for the new settings.

What was not done is listed under [Not implemented yet](#not-implemented-yet). What has not been
checked is recorded in the [verification status](deployment.md#verification-status), and
[Kinds of evidence](testing.md#kinds-of-evidence) explains what each kind of test can and cannot
show.

## Not implemented yet

Sign-in in the browser; a separate network sensor (the monitoring built in Phase 4 runs inside the API
process, on the host that has the interface, and `sensor/` is a placeholder); correlation across
events and sources, a cross-source alert queue, and incidents or cases (network alerts are listed
under the Network screen only, and they have no status, assignee or notes); file encryption that the
server cannot undo, rotation or recovery of the master key, secure wiping of deleted files and a
per-user storage quota; Redis; background workers (so a stored score is recomputed only when its
indicator is investigated again, old capture sessions are purged when the API starts or the session
list is loaded rather than by a timer, and nothing removes expired share links or leftover temporary
blob files on a schedule); Azure deployment, including Key Vault for the master key and provider keys
and Blob Storage for the encrypted files. The folders `infra/` and `sensor/` are placeholders that
say so.

Nobody outside the project has reviewed the file-encryption design or the code (see
[threat-model.md](threat-model.md)).

The frontend has no sign-in flow yet (see [Limitations](../README.md#limitations)): its API client has
a hook for a token provider and nothing registers one, so the dashboard needs `AUTH_MODE=dev`. The
investigation page still shows its internal-evidence card as "Not available": nothing from network
monitoring feeds an investigation or its score.

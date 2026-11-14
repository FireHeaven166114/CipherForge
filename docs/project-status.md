# Project status and history

This is the long, phase-by-phase record of what has been built. If you are new here, start with the
[README](../README.md), which explains the project in plain words. Come back to this page when you want
the detail: what each phase added, and what is still missing.

## Status

The project is built in vertical slices, each one tested and committed before the next begins, and
each phase is tagged (`v0.1.0-phase1` up to `v0.5.0-phase3c`).

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Foundation: FastAPI, React + TypeScript, PostgreSQL, Docker Compose, configuration, logging, auth shape | **Done.** The Docker stack itself is unverified, see [verification status](deployment.md#verification-status) |
| 2 | Threat Intel MVP: AbuseIPDB + AlienVault OTX, normalisation, persistence, caching, risk score | **Done** (backend and API). Providers are tested against recorded responses only, see [threat-intelligence.md](threat-intelligence.md#verification-status) |
| 3 | SOC dashboard: investigation view, IOC table and search, charts | **Done** (React dashboard for the Phase 2 API). Works against `AUTH_MODE=dev` only: there is no browser sign-in yet |
| 3b | Command deck: a redesigned futuristic UI, the `/overview` aggregates, a demo mode with simulated providers, and an end-to-end browser test suite | **Done.** Tested against simulated providers only, see [Testing the dashboard](testing.md#testing-the-dashboard) |
| 3c | Aurora Forge: every screen restyled as spectral glass over a layered, animated background, with a light that follows the pointer, a sliding navigation lamp and choreographed entrances, built on anime.js | **Done.** Visual only: the routes, API calls, wording and behaviour are the same as in 3b. See [the screenshots](../README.md#using-the-dashboard), [Phase 3c](#what-works-today) and [Testing the dashboard](testing.md#testing-the-dashboard) |
| 4-12 | Network sensor, detection, correlation, mini-SIEM, cases, Vault, integrations, Azure, DevSecOps | Not started |

The roadmap follows the project specification; see [architecture.md](architecture.md) for
how each module (Intel, Sentinel, Core, SOC, Case, Vault) maps to the code.

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
- Answers are cached in PostgreSQL (6 hours for AbuseIPDB, 12 for OTX by default). A provider that
  is missing, slow or failing shows up as a labelled status; it never breaks the lookup.
- Every investigation, including refused input, is written to an append-only audit table.
  Investigations are rate-limited per analyst. Access needs the `SecurityAnalyst` or `Admin` role.
- Private, loopback and reserved addresses and internal names are refused before any outside call.

The method is documented in [threat-intelligence.md](threat-intelligence.md) and the
endpoints in [api.md](api.md).

**Phase 3: investigation dashboard**

A React single-page app over the Phase 2 API, with five screens (Phase 3b gave them the look and
the overview described below):

- **Overview**: the command deck described under Phase 3b.
- **Investigate**: enter an indicator and see the result at once. Each provider is shown on its own
  card (status, freshness, its own evidence), followed by the CipherForge score with the factors
  behind it, what is not known and the recommended next steps. Internal telemetry is shown as "not
  connected" rather than left out.
- **Indicators**: search, filter by type and risk (a band, High and Critical together, or Not
  assessed), sort by recent check or by risk, and page through the stored results. The filters live
  in the address, so a view can be bookmarked.
- **Indicator details**: the stored record, with a button to re-check it with the providers.
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
  for what you typed); `G` then `O`, `I`, `L` or `S` jumps to a page.
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

## Not implemented yet

Sign-in in the browser, packet capture, detection rules, event correlation, alerts,
incidents, file sharing and encryption, Redis, background workers (so a stored score is recomputed
only when its indicator is investigated again), Azure deployment. The folders
`sensor/` and `infra/` and the matching documents in `docs/` are placeholders that say so.
The frontend has no sign-in flow yet (see [Limitations](../README.md#limitations)), so the dashboard needs
`AUTH_MODE=dev` or a token supplied some other way.

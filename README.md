# CipherForge

**Intelligence. Detection. Encryption.**

CipherForge is a cloud-native cybersecurity and mini-SOC portfolio platform: multi-source threat
intelligence, network anomaly detection, explainable risk scoring, SIEM-style alerting, incident
management and client-side encrypted file sharing, built as one modular defensive-security project.

> It is designed for a controlled lab. Run packet capture, load generation or honeypots only on
> systems and networks you own or are explicitly authorised to test.

## A look at it

The dashboard as of Phase 3c, captured from the [demo server](#try-it-without-api-keys) in Microsoft
Edge with the Effects switch on. The data is invented and the providers are simulated, as the banner
at the top of every screen says. Each image is one frame of a moving background.

**Overview** (desktop): the headline tiles, the Threat pulse trend and the Risk posture panel, with
the pointer light on the panel under the cursor.

![The Overview screen: the navigation rail with its lamp, five headline tiles, and the Threat pulse and Risk posture panels over the aurora background](docs/screenshots/overview.png)

**Investigate** (desktop): an invented indicator scored 100 (Critical) by the simulated providers,
with the AbuseIPDB and AlienVault OTX cards under the assessment.

![An investigation result: the CipherForge assessment with a risk score of 100, Critical, and a confidence of 90 out of 100, above the AbuseIPDB and AlienVault OTX cards](docs/screenshots/investigate.png)

**On a phone** (390 pixels wide): the same Overview, with the navigation moved to a bottom bar.

<img src="docs/screenshots/phone.png" width="320" alt="The Overview on a phone: headline tiles, with the navigation bar and its lamp along the bottom of the screen">

## Status

The project is built in vertical slices, each one tested and committed before the next begins, and
each phase is tagged (`v0.1.0-phase1` up to `v0.5.0-phase3c`).

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Foundation: FastAPI, React + TypeScript, PostgreSQL, Docker Compose, configuration, logging, auth shape | **Done.** The Docker stack itself is unverified, see [verification status](docs/deployment.md#verification-status) |
| 2 | Threat Intel MVP: AbuseIPDB + AlienVault OTX, normalisation, persistence, caching, risk score | **Done** (backend and API). Providers are tested against recorded responses only, see [threat-intelligence.md](docs/threat-intelligence.md#verification-status) |
| 3 | SOC dashboard: investigation view, IOC table and search, charts | **Done** (React dashboard for the Phase 2 API). Works against `AUTH_MODE=dev` only: there is no browser sign-in yet |
| 3b | Command deck: a redesigned futuristic UI, the `/overview` aggregates, a demo mode with simulated providers, and an end-to-end browser test suite | **Done.** Tested against simulated providers only, see [Testing the dashboard](#testing-the-dashboard) |
| 3c | Aurora Forge: every screen restyled as spectral glass over a layered, animated background, with a light that follows the pointer, a sliding navigation lamp and choreographed entrances, built on anime.js | **Done.** Visual only: the routes, API calls, wording and behaviour are the same as in 3b. See [the screenshots](#a-look-at-it), [Phase 3c](#what-works-today) and [Testing the dashboard](#testing-the-dashboard) |
| 4-12 | Network sensor, detection, correlation, mini-SIEM, cases, Vault, integrations, Azure, DevSecOps | Not started |

The roadmap follows the project specification; see [docs/architecture.md](docs/architecture.md) for
how each module (Intel, Sentinel, Core, SOC, Case, Vault) maps to the code.

### What works today

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

The method is documented in [docs/threat-intelligence.md](docs/threat-intelligence.md) and the
endpoints in [docs/api.md](docs/api.md).

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
  [Testing the dashboard](#testing-the-dashboard).

**Phase 3c: Aurora Forge**

Every screen was restyled and given a motion layer, and nothing was added to what it does: the same
screens, routes, API calls, wording, roles and shortcuts. The Phase 3b browser suite still passes
with one spec changed: the contrast audit now measures against the new, lighter glass colour and
hides the new decorative layers. To see it, start the [demo](#try-it-without-api-keys) and open
<http://127.0.0.1:5173>; the Effects switch in the header shows the page with and without the layers.

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
  [docs/architecture.md](docs/architecture.md#aurora-forge-and-the-motion-layer).
- **Where the ideas came from.** The spotlight cards, the "tubelight" navigation bar and the
  layered pointer-reactive background follow patterns seen on [21st.dev](https://21st.dev) and
  [GetLayers](https://getlayers.ai). No component, prompt or code from either was copied: 21st.dev's
  installer needs a signed-in membership and its components belong to their authors, and GetLayers'
  terms forbid redistributing its prompts, so everything here was written for this project. See
  [Credits](#credits).

### Not implemented yet

Sign-in in the browser, packet capture, detection rules, event correlation, alerts,
incidents, file sharing and encryption, Redis, background workers (so a stored score is recomputed
only when its indicator is investigated again), Azure deployment. The folders
`sensor/` and `infra/` and the matching documents in `docs/` are placeholders that say so.
The frontend has no sign-in flow yet (see [Limitations](#limitations)), so the dashboard needs
`AUTH_MODE=dev` or a token supplied some other way.

## Quick start

You need Python 3.12 and Node 22.22 or newer (Node 24 is what CI and the Docker image use).

### Option A: everything in Docker

```bash
cp .env.example .env          # for anything beyond local play, set a random POSTGRES_PASSWORD
docker compose up --build
```

Open <http://localhost:3000>. The ports are bound to `127.0.0.1` only. Compose starts PostgreSQL,
runs the migrations once, starts the API and then serves the frontend through nginx, which also
proxies `/api`, `/health` and `/ready` to the API.

### Option B: run the pieces locally

1. Create the configuration file and a database. The quickest database is the Compose one:

   ```bash
   cp .env.example .env
   docker compose up -d postgres
   ```

   Without Docker, set `DATABASE_URL=sqlite+pysqlite:///./cipherforge.db` in `.env`. SQLite is for
   local experiments only; `ENVIRONMENT=production` requires PostgreSQL.

2. Backend (<http://127.0.0.1:8000>, interactive docs at `/docs` outside production):

   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
   pip install -r requirements-dev.txt
   alembic upgrade head
   uvicorn app.main:create_app --factory --reload
   ```

3. Frontend (<http://127.0.0.1:5173>, proxies the API calls to port 8000):

   ```bash
   cd frontend
   npm ci
   npm run dev
   ```

   On Windows PowerShell with script execution disabled, use `npm.cmd` instead of `npm`.

### Try an investigation

With `AUTH_MODE=dev` (the `.env.example` default) the local principal is a `SecurityAnalyst`, so no
token is needed. The easiest way is the dashboard: open <http://localhost:3000/investigate> (Docker)
or <http://127.0.0.1:5173/investigate> (local frontend) and enter an indicator. The same lookup from
the command line:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/intel/investigate \
  -H "Content-Type: application/json" -d '{"indicator": "8.8.8.8"}'
```

Without provider keys, both providers come back as `not_configured`, the score is 0 with confidence
0 and `answered_sources` of 0, and the advice says nothing can be concluded. That is "not assessed",
not "clean"; the dashboard says so in words. To query the real services, put free keys in `.env`:
`ABUSEIPDB_API_KEY` (<https://www.abuseipdb.com/account/api>) and `OTX_API_KEY`
(<https://otx.alienvault.com/settings>). Restart the API after changing `.env`.

Private, loopback and documentation-range addresses (for example `192.168.1.1` or `203.0.113.9`)
are refused before any outside call, so use a public address to see a result.

### Try it without API keys

A dashboard with nothing in it shows little. `backend/devtools/` holds a **development-only** demo
server: the real application, but with **simulated providers** and a throwaway SQLite database
seeded with about two weeks of synthetic lookups. Nothing in it comes from AbuseIPDB or OTX, and the
dashboard says so in a banner whenever a provider is simulated.

```bash
cd backend
python -m uvicorn devtools.demo_server:create_demo_app --factory --port 8000
# in a second terminal
cd frontend
npm run dev                       # http://127.0.0.1:5173
```

- Everything is invented. Domains and URLs sit under the names IANA reserves for documentation
  (`example.com`, `.org`, `.net`), the malicious-looking addresses are IPv6 addresses from space
  nobody has been allocated, and the only IPv4 addresses are well-known public resolvers, simulated
  as clean. Tests enforce that the catalogue cannot accuse a real host.
- Development sign-in is on, so no token is needed (`CIPHERFORGE_DEMO_ROLES` changes the roles).
- The database is `backend/.demo/demo.db` (git-ignored). The server refuses any other location, so it
  cannot be pointed at a real database. It is rebuilt at start when its newest lookup is more than a
  day old; `CIPHERFORGE_DEMO_RESET=1` rebuilds it at once and `CIPHERFORGE_DEMO_DB` selects another
  `.db` file inside that folder.
- The code is kept out of the Docker image (`backend/.dockerignore`) and the application never
  imports it. The `CIPHERFORGE_DEMO_*` and `E2E_*` variables are development settings that the
  application does not read.

## Quality checks

```bash
# Backend (from backend/)
ruff check . && ruff format --check .
bandit -c pyproject.toml -r app -q
bandit -c pyproject.toml -r devtools -q --skip B311   # dev-only demo code; seeded randomness is intended
pip-audit -r requirements.txt
pytest --cov=app                  # SQLite only
TEST_DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/test_db pytest
                                  # runs the database tests on PostgreSQL as well

# Frontend (from frontend/)
npm run typecheck && npm run lint && npm test && npm run build
npm audit --audit-level=moderate
npm run test:e2e                  # real-browser tests, see "Testing the dashboard"
```

Point `TEST_DATABASE_URL` at a throwaway database: the PostgreSQL tests create and drop tables in it.

## Testing the dashboard

Unit tests (`npm test`, Vitest) cover components and helpers. What a person would actually see is
checked by an end-to-end suite in `frontend/e2e/`, written with [Playwright](https://playwright.dev/).
It drives a real browser against the **production build** of the dashboard, served with the
security headers from `frontend/nginx.conf`, which talks to the **real API** on a freshly seeded
copy of the [demo database](#try-it-without-api-keys). Expected figures are taken from the API's own
answers, not from what the page displays.

```bash
cd backend && pip install -r requirements-dev.txt     # once: the demo API runs from this environment
cd ../frontend && npm ci                              # once
npm run test:e2e                                      # builds the app, starts both servers, runs everything
npx playwright test e2e/overview.spec.ts -g "the map" # one spec or one group while working
npx playwright show-report                            # HTML report; failures keep a trace and a screenshot
```

- The runner starts its own servers on ports **8100** (API) and **4180** (web), so the development
  servers (8000, 5173) can stay up. It serves what `npm run build` last produced: build again after
  changing `src/` (`npm run test:e2e` does).
- Locally the tests use Microsoft Edge, which Windows already has. Set `E2E_CHANNEL` (for example
  `chrome`) to use another installed browser, or `CI=1` to use the Chromium that
  `npx playwright install --with-deps chromium` downloads, as the CI job does. `E2E_PYTHON` names
  the Python that runs the API (default: `backend/.venv`, then `python` on the PATH).
- The specs share one seeded database and run one after another. A complete run of the 596 tests took
  about 37 minutes on a laptop (the 583 tests before Phase 3c took about 18), so run the spec you
  are working on, and the whole suite before you commit.

| Spec | What it proves |
| --- | --- |
| `shell` | Pages and navigation, the top bar, the `G` shortcuts, the command palette, the effects switch |
| `overview` | Every figure on the overview equals what the API returned; ranked lists, the details drawer, the map, refreshing, an API that does not answer |
| `indicators` | Search, every filter, sorting, paging, the address bar as the state, the record page |
| `investigate` | Form validation, a lookup from the form to the evidence, refused and failed lookups, the palette hand-off |
| `status` | A healthy API, a degraded one, an unreachable one, and recovery |
| `journey` | One story across screens: investigate a new value, open its record, find it in the list, see the totals move by exactly what happened |
| `a11y` | axe-core on every screen in many states (loading, empty, failing, drawer and palette open), with motion reduced, on a phone and with the effects on, plus a text-contrast audit against the lightest glass |
| `motion` | The Phase 3c layers with the effects on: the canvas is painted and moving, the lamp sits on the open page's link (to the sub-pixel, on a phone as well) and goes out on a page with none, the switch removes every layer and brings it back without replaying the entrance, the pointer light follows the mouse and not a finger, entrances leave no styles behind, a heading is read out unchanged while it decodes, and every screen runs with no console message or policy violation and no sideways scroll |
| `responsive` | 320 to 1440 px wide, desktop at 200% zoom, and text enlarged to 200%: nothing overflows, is clipped or overlaps |
| `security` | The real response headers, and the browser itself blocking 20 kinds of injected content (inline and `javascript:` code, `data:` and `blob:` scripts, a `<base>` tag, scripts, styles, frames, forms, sockets and beacons to other sites) |
| `untrusted-data` | Hostile names, values and links in provider data are shown as text and never run or followed |
| `long-data` | Very long values and very large numbers stay inside their boxes |
| `privacy` | No third-party request, no cookies, no `Referer`, nothing kept in the browser but the effects switch, and the indicator only in the body of the one POST |

Every test also runs under a guard that fails it on a console error or warning, an uncaught
exception, a failed request, an unexpected HTTP error status or a Content Security Policy violation.

What a green run does **not** show:

- It uses simulated providers, so no real AbuseIPDB or OTX evidence has been through the dashboard.
- The security specs run against a small Node server that stands in for nginx and reads its header
  values from the real `nginx.conf`: the file is checked, nginx is not. The container images were
  not built either.
- Automated checks find only part of the accessibility problems. No screen reader or other assistive
  technology was used, and the suite's contrast audit measures chart text against the flat glass
  colour, not against what the animated background shows through it. A one-off script that measured
  every text run on every screen against the live, moving background (phone and desktop) found no
  failure, but that script is not part of the repository.
- **Nobody has judged the look.** The checks measure contrast, layout, motion state and a quiet
  console. They cannot say whether the design is attractive or whether the motion feels right, and
  it has not been tuned on slow devices (switch the effects off there).
- It was run in Edge on Windows. Firefox and Safari were not tried, and the CI job that runs it on
  Chromium has not run yet.

## Configuration

Settings come from environment variables; for local runs they can also live in a git-ignored
`.env` at the repository root. Invalid settings stop the API from starting, and the error names the
setting but never prints its value. See [.env.example](.env.example) for the full annotated list.

| Variable | Purpose | Default |
| --- | --- | --- |
| `ENVIRONMENT` | `development`, `test` or `production` | `production` |
| `AUTH_MODE` | `entra` (validate Entra ID tokens) or `dev` (local only) | `entra` |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` | Required when `AUTH_MODE=entra` | none |
| `ENTRA_AUDIENCE` | Expected token audience | `ENTRA_CLIENT_ID` |
| `DATABASE_URL` | SQLAlchemy URL; PostgreSQL in production | required |
| `DEV_AUTH_ROLES` | Roles of the local dev principal | `SecurityAnalyst` |
| `CORS_ORIGINS` | Comma separated origins; `*` is rejected | none |
| `LOG_LEVEL`, `LOG_FORMAT` | Logging verbosity and `json` or `console` output | `INFO`, `json` |
| `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | Provider keys; a provider without one is reported as not configured | none |
| `ABUSEIPDB_CACHE_TTL_SECONDS`, `OTX_CACHE_TTL_SECONDS` | How long a provider answer is reused (60 seconds to 30 days) | `21600`, `43200` |
| `PROVIDER_TIMEOUT_SECONDS` | How long to wait for one provider (1 to 30) | `10` |
| `INVESTIGATE_RATE_LIMIT_PER_MINUTE` | Investigations per analyst per minute, per API process (1 to 600) | `30` |

The defaults are deliberately strict. In production, `AUTH_MODE=dev` is refused, PostgreSQL is
required and a `DATABASE_URL` that still contains `CHANGE_ME` is refused. Provider keys are held as
secrets: they are never logged, never returned by the API and, in Compose, given only to the
`backend` container.

## Repository layout

```text
backend/      FastAPI service (app/, alembic/, tests/) and devtools/, the dev-only demo server
frontend/     React + TypeScript + Vite + Tailwind single-page app, served by nginx in Docker;
              src/motion/ holds the anime.js effects, e2e/ its Playwright browser tests
sensor/       Network sensor (placeholder, not implemented)
infra/        Infrastructure as code (placeholder, not implemented)
docs/         Architecture, security and deployment notes; screenshots/ holds the README images
.github/      CI workflow and Dependabot configuration
docker-compose.yml
.env.example
```

## Security

Security is a design input, not a later phase. The headline controls are fail-closed configuration,
Entra token validation with role checks, secret redaction in logs, a uniform error format that
never echoes input, security headers and a strict Content Security Policy, non-root containers
with all Linux capabilities dropped (and a read-only root filesystem for the API), pinned
dependencies, and automated dependency and static analysis in CI. The threat-intelligence feature
adds strict indicator validation (no server-side requests to internal targets), defensive parsing of
untrusted provider data, provider keys kept server-side, a per-analyst rate limit and an
append-only audit trail. The dashboard shows provider text as plain text, builds links to other
sites only from fixed bases and strictly patterned identifiers, makes no third-party requests, sets
no cookies and keeps nothing in the browser but its effects switch, and its lint rules reject
`dangerouslySetInnerHTML`, `innerHTML` assignment and `eval` (a pattern check, not a guarantee).
Browser tests check those claims, including that the browser really blocks injected scripts, styles,
frames and beacons under the Content Security Policy.
The details, and what is deliberately left for later, are in [docs/security.md](docs/security.md)
and [docs/threat-model.md](docs/threat-model.md).

## Limitations

- **No sign-in in the frontend yet.** The API validates Entra ID tokens and the frontend client can
  attach a bearer token, but there is no MSAL integration. The dashboard therefore works only
  against `AUTH_MODE=dev`, which is for local use; a real tenant needs an Entra app registration
  and the sign-in flow first.
- **TLS and HSTS are the job of the proxy in front of nginx.** The compose stack speaks plain HTTP
  on loopback.
- **Single-instance assumptions.** The rate limiter keeps its counts in memory, per API process, so
  several replicas would each allow the full rate. Nothing shared between replicas exists yet (no
  Redis).
- **The providers have only been tested against recorded responses**, never the live AbuseIPDB and
  OTX services. Their request formats were checked against public documentation and AlienVault's
  client library; some OTX response fields are unconfirmed. See
  [docs/threat-intelligence.md](docs/threat-intelligence.md#verification-status).
- **Scores are advice, not verdicts.** They come from two community and commercial feeds, age with
  the evidence only when an indicator is investigated again, and say nothing about your own
  environment because no internal telemetry is connected yet.
- **The dashboard has not shown real provider evidence.** It has been used against the real API with
  no provider keys (where the only result is "Not assessed") and against the demo server's simulated
  providers; the screens for real evidence were checked with made-up data, by tests and in those
  browser tests. Its charts are hand-built SVG with text equivalents, not a charting library. The only
  time series is the lookup history in CipherForge's own audit log: nothing is charted from network
  telemetry because none is connected. The map shows the country a provider reports for an
  indicator, which is not where anyone is.
- **The overview is computed on every request.** It reads the 2,000 most recent provider answers and
  the 20,000 most recent audit rows of the last 14 days, and says when either bound cut it short.
  That suits a lab; a busier installation would need pre-aggregation or caching (see
  [docs/threat-intelligence.md](docs/threat-intelligence.md#limitations)).
- **The browser tests have not run in CI.** They pass locally (Edge on Windows, simulated providers);
  the workflow job that runs them on Chromium is untested, like the rest of the workflow.
- The container images, Compose file and CI workflow are checked statically and by the CI
  pipeline; see [docs/deployment.md](docs/deployment.md#verification-status).

## Map data

The overview's dot-matrix world map is generated from [Natural Earth](https://www.naturalearthdata.com/)
(public domain, release v5.1.2): a 2-degree land and sea grid from the 1:110m land outline and one
label point per country from the 1:50m country data. The generated files are committed
(`frontend/src/features/overview/worldMask.ts` and `countryCentroids.ts`), so building the app and
loading the page never need the network. To change them, run
`node scripts/build-world-data.mjs` from `frontend/`.

## Credits

- **[anime.js](https://animejs.com)** by Julian Garnier (MIT) animates the interface (version 4.5.0,
  pinned; only the parts the app uses end up in the build).
- **[21st.dev](https://21st.dev) and [GetLayers](https://getlayers.ai)** were design references for
  Phase 3c: a spotlight card, a "tubelight" navigation bar and layered, pointer-reactive backgrounds
  are general ideas both show. No component, prompt or source from either is in this repository.
- **Fonts** (Oxanium and JetBrains Mono, SIL Open Font License) come from the `@fontsource` packages
  and are bundled, never fetched from a font host.
- **Map data**: [Natural Earth](https://www.naturalearthdata.com/), see above.

## Licence

MIT. See [LICENSE](LICENSE).

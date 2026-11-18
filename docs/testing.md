# Testing

This page lists every automated check in the repository and how to run it. You do not need any of it
to *use* CipherForge. It is for people who change the code, and for anyone who wants to know how far
the results can be trusted.

There are three layers (counts are for version 0.5.0):

| Layer | Tool | Where | What it covers |
| --- | --- | --- | --- |
| Backend tests (958) | pytest | `backend/tests/` | The API, indicator checks, the provider collectors (run against recorded answers), the scoring function, the database, deleting indicators and the audit log |
| Frontend unit tests (477) | Vitest | `frontend/src/**/*.test.ts(x)` | Components, helpers and the motion layer |
| End-to-end tests (686) | Playwright | `frontend/e2e/` | The finished dashboard, in a real browser, against the real API |

On Windows PowerShell, script execution is often disabled. Use `npm.cmd` and `npx.cmd` instead of
`npm` and `npx`, and call Python tools through the virtual environment instead of activating it, for
example `.\.venv\Scripts\python.exe -m pytest`.

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

What each one is for: `ruff` checks style and common mistakes in Python, `bandit` looks for risky
Python patterns, `pip-audit` and `npm audit` look for known vulnerabilities in dependencies, `pytest`
and `npm test` run the unit tests, `npm run typecheck` runs the TypeScript compiler and `npm run build`
makes the production build.

`npm run typecheck` checks three groups of files: the app and the build tooling (`npm run
typecheck:app`) and the browser tests in `e2e/`. The Docker image has no browser tests (they are left
out of the build context by `frontend/.dockerignore`), so the image builds with `npm run build:app`,
which is `build` without the check on the tests.

Point `TEST_DATABASE_URL` at a throwaway database: the PostgreSQL tests create and drop tables in it.
Without it those tests are skipped, so a plain `pytest` run ends with `717 passed, 241 skipped`. With
it, 957 pass and 1 is skipped on purpose (SQLite has no `TRUNCATE` statement).

The workflow in `.github/workflows/ci.yml` has four jobs: backend, frontend, dashboard end-to-end
(on Chromium) and a Docker build with a smoke test. It runs on every push to `main`, on every pull
request and when started by hand. See
[Deployment: verification status](deployment.md#verification-status).

### What the first run on GitHub found

The workflow was written before the project had an online repository, so nothing had ever run it.
Its first run failed two of the four jobs. Three separate problems were behind that, and none of
them could be seen on the machine that built the project:

| Job | What failed | Why | The fix |
| --- | --- | --- | --- |
| Docker | The frontend image would not build: `error TS18003: No inputs were found in config file '/app/tsconfig.e2e.json'`. | `npm run build` also type-checks the browser tests, but `frontend/.dockerignore` keeps `e2e/` out of the image, so that check had nothing to read. The build machine had no Docker, so nobody could see it. | The image builds with `npm run build:app`, which skips the check on the browser tests. `npm run build` is unchanged. |
| Dashboard end-to-end | 11 layout tests failed, all at the 390 px phone width. The label "SHA-256" on the *Indicators by type* radar stuck out of its drawing by about 2 px, more than the test allows. | The label sat exactly on the chart's left edge. Chromium on Linux measures text a little wider than Edge on Windows, which pushed the first letter just outside. This was a real weakness of the chart, not only of the test. | The radar works out where every label lands and widens its drawing area when one would cross the edge. With the demo data the label now has at least 6 px to spare at every size measured. Two unit tests cover it. |
| Dashboard end-to-end | 2 paging tests in the Indicators spec failed. | After a click on "previous page" the address changes at once, but the list is redrawn a moment later. The tests read the rows once, in between, and saw the old page. | The tests wait until the rows match what they expect (`expectShown` in `e2e/indicators.spec.ts`) instead of reading them once. |

The other 583 browser tests passed on that first run, on Linux, in Chromium. After the three fixes a
full run passed all four jobs, with every one of the 596 browser tests passing and none needing a
retry (15 to 19 minutes on a GitHub runner).

## Testing the dashboard

Unit tests (`npm test`, Vitest) cover components and helpers. What a person would actually see is
checked by an end-to-end suite in `frontend/e2e/`, written with [Playwright](https://playwright.dev/).
It drives a real browser against the **production build** of the dashboard, served with the
security headers from `frontend/nginx.conf`, which talks to the **real API** on a freshly seeded
copy of the [demo database](../README.md#try-it-without-api-keys). Expected figures are taken from
the API's own answers, not from what the page displays.

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
- The specs share one seeded database and run one after another. A complete run of the 686 tests took
  about 23 minutes on a laptop (an earlier run of 596 tests took about 37, so the time depends on how
  busy the computer is) and, when the suite had 596 tests, 15 to 19 minutes on
  a GitHub runner, so run the spec you are working on, and the whole suite before you commit.

| Spec | What it proves |
| --- | --- |
| `shell` | Pages and navigation, the top bar, the `G` shortcuts, the command palette, the effects switch |
| `overview` | Every figure on the overview equals what the API returned; ranked lists, the details drawer, the map, refreshing, an API that does not answer |
| `indicators` | Search, every filter, sorting, paging, the address bar as the state, the record page |
| `delete` | Deleting indicators from the list (one, a Shift-clicked run, a whole page, a selection too long to list) and from a record. The confirmation asks first, and Cancel, Escape and a click outside leave everything in place. A failure keeps the dialog open and deletes nothing, a second click while it deletes does nothing, and indicators somebody else already deleted are counted while the rest go. Afterwards the indicator is gone from the list, the Overview, the record's address and the API, and the same value can be investigated again as a new record. Text written as an attack is listed as text. Everything works from the keyboard |
| `investigate` | Form validation, a lookup from the form to the evidence, refused and failed lookups, the palette hand-off |
| `status` | A healthy API, a degraded one, an unreachable one, and recovery |
| `journey` | One story across screens: investigate a new value, open its record, find it in the list, see the totals move by exactly what happened |
| `a11y` | axe-core on every screen in many states (loading, empty, failing, drawer and palette open, rows ticked, the delete confirmation open, deleting, failing and done), with motion reduced, on a phone and with the effects on, plus a text-contrast audit against the lightest glass |
| `motion` | The Phase 3c layers with the effects on: the canvas is painted and moving, the lamp sits on the open page's link (to the sub-pixel, on a phone as well) and goes out on a page with none, the switch removes every layer and brings it back without replaying the entrance, the pointer light follows the mouse and not a finger, entrances leave no styles behind, a heading is read out unchanged while it decodes, and every screen runs with no console message or policy violation and no sideways scroll |
| `responsive` | 320 to 1440 px wide, desktop at 200% zoom, and text enlarged to 200%: nothing overflows, is clipped or overlaps, including with rows ticked, the delete confirmation open (also after a failure) and a record after it is deleted |
| `security` | The real response headers, and the browser itself blocking 20 kinds of injected content (inline and `javascript:` code, `data:` and `blob:` scripts, a `<base>` tag, scripts, styles, frames, forms, sockets and beacons to other sites). Also that the API deletes only the ids it is given, refuses a delete-by-filter, and cannot be made to delete by a page on another site |
| `untrusted-data` | Hostile names, values and links in provider data are shown as text and never run or followed |
| `long-data` | Very long values and very large numbers stay inside their boxes, including in the delete confirmation |
| `privacy` | No third-party request, no cookies, no `Referer`, nothing kept in the browser but the effects switch, and the indicator only in the body of the one POST |

Every test also runs under a guard that fails it on a console error or warning, an uncaught
exception, a failed request, an unexpected HTTP error status or a Content Security Policy violation.

### What a green run does not show

- It uses simulated providers, so no real AbuseIPDB or OTX evidence has been through the dashboard.
- The security specs run against a small Node server that stands in for nginx and reads its header
  values from the real `nginx.conf`: the file is checked, nginx is not. The CI `docker` job does
  start the real nginx in its container, but it only checks that the page, the API behind nginx and
  the Content Security Policy header are there. The browser suite does not run against it.
- Automated checks find only part of the accessibility problems. No screen reader or other assistive
  technology was used, and the suite's contrast audit measures chart text against the flat glass
  colour, not against what the animated background shows through it. A one-off script that measured
  every text run on every screen against the live, moving background (phone and desktop) found no
  failure, but that script is not part of the repository.
- **Nobody has judged the look.** The checks measure contrast, layout, motion state and a quiet
  console. They cannot say whether the design is attractive or whether the motion feels right, and
  it has not been tuned on slow devices (switch the effects off there).
- It was run in Edge on Windows and, in CI, in Chromium on Linux. Firefox and Safari were not tried.

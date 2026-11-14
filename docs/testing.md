# Testing

This page lists every automated check in the repository and how to run it. You do not need any of it
to *use* CipherForge. It is for people who change the code, and for anyone who wants to know how far
the results can be trusted.

There are three layers (counts are for version 0.5.0):

| Layer | Tool | Where | What it covers |
| --- | --- | --- | --- |
| Backend tests (867) | pytest | `backend/tests/` | The API, indicator checks, the provider collectors (run against recorded answers), the scoring function, the database and the audit log |
| Frontend unit tests (424) | Vitest | `frontend/src/**/*.test.ts(x)` | Components, helpers and the motion layer |
| End-to-end tests (596) | Playwright | `frontend/e2e/` | The finished dashboard, in a real browser, against the real API |

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

Point `TEST_DATABASE_URL` at a throwaway database: the PostgreSQL tests create and drop tables in it.
Without it those tests are skipped, so a plain `pytest` run ends with `669 passed, 198 skipped`. With
it, 866 pass and 1 is skipped on purpose (SQLite has no `TRUNCATE` statement).

The workflow in `.github/workflows/ci.yml` has four jobs: backend, frontend, dashboard end-to-end
(on Chromium) and a Docker build with a smoke test. The repository has no remote yet, so the
workflow has never run; treat it as untested. See
[Deployment: verification status](deployment.md#verification-status).

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

### What a green run does not show

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

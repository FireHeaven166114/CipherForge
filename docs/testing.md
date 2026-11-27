# Testing

This page lists every automated check in the repository and how to run it. You do not need any of it
to *use* CipherForge. It is for people who change the code, and for anyone who wants to know how far
the results can be trusted.

There are three layers:

| Layer | Tool | Where | What it covers |
| --- | --- | --- | --- |
| Backend tests | pytest | `backend/tests/` | The API and the audit log, indicator checks, the four provider adapters (against canned answers), scoring, the database and its migrations, deleting indicators, the India Standard Time helpers, network monitoring (packets, flows, the rules, live capture, capture files, enrichment, storage and ownership), encrypted file sharing (encryption, storage, names, link rules, the HTTP contract, access control, audit), the deployment files and the demo tools |
| Frontend unit tests | Vitest | `frontend/src/**/*.test.ts(x)` | Components, helpers, hooks and API clients, including the Network, Files and Share screens, and the motion layer |
| End-to-end tests | Playwright | `frontend/e2e/` | The finished dashboard, in a real browser, against the real API |

The number of tests changes with every phase, so the counts live in one place:
[Evidence by capability](#evidence-by-capability) gives the result of the latest full run on the
author's computer and says, for each feature, how far it has been checked. The runners print the
current counts, and so does the CI log.

On Windows PowerShell, script execution is often disabled. Use `npm.cmd` and `npx.cmd` instead of
`npm` and `npx`, and call Python tools through the virtual environment instead of activating it, for
example `.\.venv\Scripts\python.exe -m pytest`.

## Kinds of evidence

A passing test only shows what its kind of test can show, so every test here is one of five kinds.
The kind matters more than the count.

| Kind | What is real | What is replaced | Where | What it needs |
| --- | --- | --- | --- | --- |
| Unit | The code under test | Its neighbours: fake clocks, in-memory fakes, a fake capture source | Most of `backend/tests/` and every `frontend/src/**/*.test.*` | Nothing |
| Canned provider answers | The adapter, the registry, the scoring, the service and a migrated database | The network: each provider "answers" with a response written into the test, shaped as its public documentation describes | `test_collectors.py`, `test_virustotal.py`, `test_threatfox.py`, `test_collector_resilience.py`, `test_intel_providers.py` | Nothing: no key, no quota, no network |
| Integration | The whole application, a migrated database, and real files on disk (the encrypted blobs) | Sign-in tokens (signed with a test key) and, where a test needs it, the clock | `test_*_api.py`, `test_files_*.py`, `test_network_service*.py`, `test_migrations.py`, `test_models.py` | SQLite; PostgreSQL too when `TEST_DATABASE_URL` is set |
| Simulated | The real API and the real dashboard, in a real browser | The four providers, the network interfaces and the packet source; every address and indicator is synthetic | `frontend/e2e/`, through `backend/devtools/demo_server.py` | A built dashboard, and Edge or Chromium |
| Live | The real provider service, or this machine's real network stack | Nothing | `test_live_providers.py`, `test_network_live_capture.py` | An opt-in variable, plus a key or a capture driver and the right to capture. Skipped otherwise |

Canned answers are written by hand from each provider's public documentation; they are not recordings
of the live service. They show that an adapter handles the documented shape and every failure case
(missing keys, rejected keys, rate limits, timeouts, malformed or oversized bodies), and they cannot
show that a provider still answers that way. Only the live tests can, which is why they exist (see
[Opt-in live tests](#opt-in-live-tests)). Nothing in the first four kinds spends a provider's quota or
needs a key.

## Evidence by capability

This section answers two questions: what the latest full run showed, and how far each feature has been
checked. It names what is *not* shown as plainly as what is, and each row links to the page that owns
the details.

### Latest full run

Run on the author's computer (Windows 11, Python 3.12.15, Node.js 26.13.0) on 26 November 2026. A row
that also gives a GitHub Actions result is from the run on Linux (Ubuntu runner) on 27 November 2026,
the first one in which all four jobs passed on this code. The numbers go stale with the next change;
run the command to get current ones.

| Check | Command | Result |
| --- | --- | --- |
| Backend tests | `pytest -q -rs --cov=app` in `backend/` | 2888 passed, 821 skipped, 0 failed, 0 warnings, in 5 min 15 s. Line coverage of `app/`: 98% |
| Backend tests with PostgreSQL | the same command with `TEST_DATABASE_URL` pointing at a PostgreSQL 16.15 server on this computer (started from the `pixeltable-pgserver` package, with a throwaway data folder) | 3699 passed, 10 skipped, 0 failed, 0 warnings, in 16 min 12 s. Line coverage of `app/`: 98%. GitHub Actions ran it on Linux with a PostgreSQL 16 service: 3702 passed, 7 skipped, 0 failed, in 7 min 51 s, coverage 99% |
| What the skips are | the `-rs` output | Without PostgreSQL: 812 are the PostgreSQL copies of database tests (`TEST_DATABASE_URL` is not set); 5 are the opt-in live tests; 4 cannot run on this system (symbolic links twice, POSIX file permissions, SQLite's missing `TRUNCATE`). With PostgreSQL: the same 5 live tests, and 5 that cannot run on this system or this engine (symbolic links twice, POSIX file permissions, SQLite's missing `TRUNCATE`, and one test that reads the SQLite database file). On GitHub (Linux, PostgreSQL) 7 skip: the 5 opt-in live tests, SQLite's missing `TRUNCATE` and the test that reads the SQLite database file; the symbolic-link and file-permission tests run there and pass |
| Backend static checks | `ruff check .`, `ruff format --check .`, `bandit -c pyproject.toml -r app`, the same for `devtools` with `--skip B311`, `pip-audit -r requirements.txt` | Clean: 143 files formatted, no `bandit` finding in about 11,700 lines of `app/` and 1,350 of `devtools/`, no known vulnerable dependency |
| Frontend unit tests | `npm test` in `frontend/` | 126 files, 1506 tests passed, 0 failed, in 2 min 1 s. GitHub Actions: the same 126 files and 1506 tests passed, in 49 s |
| Frontend type check and lint | `npm run typecheck`, `npm run lint` in `frontend/` | Both finished without errors |
| Production build | `npm run build` in `frontend/` | Built (343 modules). The main script is 610 kB (185 kB compressed), which makes Vite warn that one file is larger than 500 kB; there is no other warning. A search of the 12 files in `dist/` for the three secret values in the author's `.env` found none |
| Frontend dependency audit | `npm audit --omit=dev --audit-level=moderate` and `npm audit --audit-level=moderate` in `frontend/` | 0 vulnerabilities in both, across 295 packages (13 of them in what ships). The package proxy used here refused the first attempts that day; a deliberately vulnerable test package showed that it returns real findings, so the empty result is a result. CI runs the same two commands |
| Live provider tests | `CIPHERFORGE_LIVE_TESTS=1 pytest -m live -q -rs` in `backend/` | 2 passed (AbuseIPDB and AlienVault OTX, one real `8.8.8.8` lookup each); 3 skipped: no VirusTotal key, no ThreatFox key, and the capture test, which has its own switch |
| Live capture test | `CIPHERFORGE_LIVE_CAPTURE_TESTS=1 pytest tests/test_network_live_capture.py -q -rs` in `backend/` | 1 passed: a real capture on this computer saw at least one of the five datagrams the test sends to a documentation-range address, dropped none, stopped cleanly and left no thread behind |
| Browser tests | `npm run test:e2e` in `frontend/` (Microsoft Edge, one worker, no retries) | 732 passed, 0 failed, 0 flaky, 0 skipped: 30.5 minutes of testing, 30 min 44 s with the production build the command makes first. This is the second complete run of the day; the first failed 12 tests for five causes, all fixed ([what it found](#what-the-first-complete-run-of-the-new-modules-found)). GitHub Actions ran this version of the suite too, on Linux in Chromium: 732 passed, none failed, none retried, in 19.6 minutes |

### How far each feature has been checked

The labels mean this. **Live verified**: the real service or the real machine facility was used and
the result was checked. **Automated**: tests that pass without the real thing (see
[Kinds of evidence](#kinds-of-evidence)). **By hand**: done once by the author; the repository keeps
no log of it, so it cannot be re-checked from here. **Needs privileged manual verification**: it
cannot be checked without the privileges of the real system. **Blocked**: it cannot be checked here,
and the row says what is missing and how to continue.

| Capability | How far it has been checked | What is still open |
| --- | --- | --- |
| AbuseIPDB and AlienVault OTX lookups | **Live verified**: the opt-in live test passed for both, the author's database holds real stored answers from both, and the network monitor looked up real addresses through both. Their failure handling is **automated** with canned answers | The services' own failure answers (rate limit, outage) were never provoked |
| VirusTotal and ThreatFox lookups | **Automated** only: canned answers written from each provider's documentation, and simulated providers in the browser. Live verification is **blocked**: no key for either was available | Put `VIRUSTOTAL_API_KEY` and `THREATFOX_API_KEY` in `.env`, restart the API and run the live tests ([Opt-in live tests](#opt-in-live-tests)). Until they pass, both adapters are unconfirmed against the real services |
| Indicator checks, the `intel-risk-v1` score, caching and refresh | **Automated**, in the backend tests and in the browser against simulated providers | The score is a fixed formula that was not compared with any labelled data: it says how much evidence there is, not whether an indicator is truly malicious |
| Deleting indicators | **Automated** in the backend tests and the `delete` browser specs; also used by hand on the author's real database | |
| India Standard Time on screen, UTC in storage | **Automated**: backend helpers, frontend unit tests, and browser tests run with the browser's own clock set to UTC, so a page that used the computer's zone would show the wrong hour | India Standard Time is the only zone supported |
| Capture-file analysis | **Automated**: the reader, flows, rules and API in the backend tests, and in the browser a synthetic capture that the test reads for itself with its own packet parser, so the page is checked against facts the server did not produce | Capture files from real networks and other tools were not tried, only files the tests build |
| Detection rules NET-001 to NET-007 | **Automated**, with hand-built flows and the synthetic capture | The thresholds are untuned defaults. No false-positive rate was measured on real traffic |
| Live capture | Windows with Npcap, without elevation: **live verified by hand**, through the API (start, traffic counted, stop, no thread or process left behind), and the opt-in test passed in the latest run. Linux: **needs privileged manual verification**; only its code paths are unit-tested. The browser tests use a simulated source | On Linux, run the API as root or with `CAP_NET_RAW`, then `CIPHERFORGE_LIVE_CAPTURE_TESTS=1 pytest tests/test_network_live_capture.py -q -rs`. macOS, WinPcap and Npcap restricted to administrators were not tried |
| External address enrichment | **Live verified** for AbuseIPDB and OTX during live captures: public addresses from this machine's own traffic were looked up, and the documentation-range destinations in the same runs were not. The rules that decide what may be sent are **automated** | VirusTotal and ThreatFox: **blocked**, as above |
| Encrypted file sharing | **Automated**: encryption, storage, limits, revocation, tampering, audit and the HTTP contract in the backend tests, and the whole journey in the browser (upload, password-protected share, anonymous download, revoke, delete). Also run end to end **by hand** over raw HTTP on a scratch database | No independent review of the design, no published test vectors, no key rotation or recovery. The server does the encryption, so this is not end-to-end encryption ([details](encryption-design.md#what-this-does-not-protect-against)) |
| Sign-in | Development sign-in in every browser test. Entra ID token checking is **automated** with locally signed tokens | Not tried against a real tenant; the dashboard has no sign-in screen of its own |
| Database and migrations | **Automated** on SQLite and on PostgreSQL 16 (a local 16.15, and CI). The upgrade, downgrade and upgrade again were also run **by hand** on a copy of the author's database, and the real one is at the latest revision with its rows intact | A running server on PostgreSQL was tried by hand only up to migration `0002`; migrations `0003` to `0005` and the network and file endpoints are covered on PostgreSQL by the automated tests alone |
| nginx, Docker and Compose | `nginx.conf` **by hand** with a real nginx 1.30.8. The deployment files are **automated**: a test makes settings, `.env.example` and Compose agree. The images and the Compose stack: CI only | [Deployment: verification status](deployment.md#verification-status) |
| Accessibility and security headers | **Automated** in the browser: axe-core, and the browser's own enforcement of the Content Security Policy | No screen reader was used, and the real nginx is not in the browser suite |

## Quality checks

```bash
# Backend (from backend/)
ruff check . && ruff format --check .
bandit -c pyproject.toml -r app -q
bandit -c pyproject.toml -r devtools -q --skip B311   # dev-only demo code; seeded randomness is intended
pip-audit -r requirements.txt
pytest --cov=app                  # SQLite; the PostgreSQL variants are skipped
TEST_DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/test_db pytest
                                  # runs the database tests on PostgreSQL as well

# Frontend (from frontend/)
npm run typecheck && npm run lint && npm test && npm run build
npm audit --omit=dev --audit-level=moderate   # the packages that ship; CI fails on a finding
npm audit --audit-level=moderate              # everything, tools included; CI only reports (see below)
npm run test:e2e                  # real-browser tests, see "Testing the dashboard"
```

What each one is for: `ruff` checks style and common mistakes in Python, `bandit` looks for risky
Python patterns, `pip-audit` and `npm audit` look for known vulnerabilities in dependencies, `pytest`
and `npm test` run the unit tests, `npm run typecheck` runs the TypeScript compiler and `npm run build`
makes the production build.

The frontend is audited twice. The first command looks only at the packages that end up in the
dashboard people use, and CI fails if it finds anything. The second also looks at the tools that build
and test the code (Vite, Vitest, ESLint). CI shows that step but does not fail on it: it was made
non-blocking while an advisory in `picomatch` (GHSA-fc5q-39xc-vjpf) had no fix, and GitHub withdrew
that advisory on 18 November 2026. Both commands reported no vulnerabilities on 26 November 2026
(see [Dependency management](security.md#dependency-management)).

`npm run typecheck` checks three groups of files: the app and the build tooling (`npm run
typecheck:app`) and the browser tests in `e2e/`. The Docker image has no browser tests (they are left
out of the build context by `frontend/.dockerignore`), so the image builds with `npm run build:app`,
which is `build` without the check on the tests.

Point `TEST_DATABASE_URL` at a throwaway database: before and after every PostgreSQL test the suite
drops and recreates that database's `public` schema, so anything else in it is lost. (Reversing the
migrations would not do as a reset: revision `0003` refuses to downgrade while MD5 or SHA-1
indicators are stored.) Without the variable those tests are skipped, so a plain `pytest` run reports
a large number of skips (`-rs` lists each reason) and every database test has run on SQLite only. CI
sets it, so each of those tests runs on SQLite and on PostgreSQL 16. A few tests are skipped on
purpose on one engine or one operating system (SQLite has no `TRUNCATE`, POSIX file permissions do
not exist on Windows, and a Windows account may not be allowed to create symbolic links) and say why.
The whole suite, every PostgreSQL variant included, was also run on the author's computer against a
local PostgreSQL 16.15 (see [Latest full run](#latest-full-run)). Its encrypted-file tests, including
the ones that release parallel downloads at the same instant, therefore ran on both engines.

Tests that touch the machine or the network are kept apart. `pytest` never calls a provider and never
captures a packet unless you ask for it (see [Opt-in live tests](#opt-in-live-tests)). The tests of
file sharing and of network monitoring keep their databases, encrypted blobs and capture files in
pytest's temporary folders.

### Running one area

Every area has its own test modules, so you can run one at a time while you work on it:

```bash
# from backend/ (bash; in PowerShell a glob is not expanded for you:
#   pytest (Get-ChildItem tests/test_files_*.py).FullName)
pytest tests/test_files_*.py                              # encrypted file sharing
pytest tests/test_network_*.py                            # network monitoring
pytest tests/test_virustotal.py tests/test_threatfox.py   # the two newest provider adapters
pytest tests/test_timeutil.py                             # India Standard Time helpers
pytest tests/test_migrations.py tests/test_models.py      # the schema and its migrations
pytest -k concurrent                                      # every test whose name contains a word

# from frontend/
npx vitest run src/components/files src/hooks             # a few folders
npx vitest run -t "wrong password"                        # tests by name
```

`test_network_live_capture.py` matches the second pattern but is skipped unless you switch it on, so
that command never captures anything by itself.

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
retry (15 to 19 minutes on a GitHub runner). Those counts are from that run, in the 0.5.0 era;
later phases added tests.

#### A later failure: a test that raced the page

A later full run on `main` (the documentation restructure, 23 November 2026) passed the backend,
frontend and Docker jobs and failed the browser job: 685 of 686 tests passed in 16.9 minutes, and one
failed on its attempt and again on its retry. It was "a lookup started while another is still
running replaces it" in `e2e/investigate.spec.ts`. The test holds the first lookup open for two
seconds, starts a second one from the command palette and waits for the page to say "Asking the
providers about" the second value. The second lookup was not held, so on a fast runner its answer
arrived before the browser had drawn that line, and the wait ran out after 10 seconds. The page was
behaving correctly; the test assumed it could watch a state that lasts a few milliseconds.

The fix holds the second lookup for 800 ms as well. The rule for every browser test that asserts a
transient state is the same: hold your own request with `page.route` and `pause()` instead of relying
on the demo API being slow. The test had passed on the author's computer and on earlier runs on
GitHub, so the outcome depended on how fast the machine was. The fix was made after the failed run.
Locally the test passed on its own, five times in a row (`--repeat-each=5`), and in the complete
732-test run of 26 November. The first run on GitHub that included it (the next one, below) passed
all 732 tests on Linux, with no retries.

#### The run on GitHub that first included the new modules

The first run on GitHub of the network, file-sharing and four-provider work (26 November 2026)
passed the Docker and browser jobs and failed the backend and frontend jobs. Three problems were
behind that. The author's computer had no PostgreSQL when the tests were written, which hid two of
them, and the third depended on how fast the computer was.

| Job | What failed | Why | The fix |
| --- | --- | --- | --- |
| Backend | 488 of the PostgreSQL variants of database tests failed or errored, from the first test that stored a SHA-1 hash onwards: `RuntimeError: Cannot downgrade: 2 MD5 or SHA-1 indicator(s) are stored`, and counts that were too high (`16 == 4`). | The test fixture emptied the database after every test by running all the migrations backwards. Revision `0003` refuses to go back while MD5 or SHA-1 indicators exist, so the first test that stored one made the reset fail. PostgreSQL runs a downgrade in one transaction, so nothing was undone and every later test started on a dirty database. It was a fault in the fixture, not in the application. | The fixture drops and recreates the `public` schema before and after each test. The downgrade itself stays covered by `test_upgrade_downgrade_and_readiness_on_postgresql`. All 814 PostgreSQL variants then passed against a local PostgreSQL 16.15. |
| Backend | `test_the_committed_sample_capture_is_what_the_generator_writes` | The generator left the hardware source address of the ARP frame unset, and Scapy filled it in from the network adapter of the computer that ran the generator. The committed sample held that adapter's address, so the file differed on every other computer. | The generator sets that address to the same made-up one as the rest of the file, and the sample was regenerated (six bytes changed). A new test checks that the file holds only made-up or broadcast hardware addresses. |
| Frontend | 1 of 1506 tests: "shows the busy state while the providers are asked, and ignores a second press" could not find "Risk score 72 of 100". | After a lookup the alert row shows the answer only until the list around it is read again. The test's alert list kept returning the alert without the lookup, so the score disappeared as soon as that second read arrived. A fast computer saw the text in between; the GitHub runner did not. | The test's list returns the looked-up alert once the lookup is done, as the real server does. With a 300 ms pause added to the old test it failed every time; the new test passes with the same pause. |

The browser job ran all 732 tests in Chromium on Linux in 20.7 minutes with no failure and no retry,
and the Docker job built both images and passed its smoke test with the new Compose file.

After the three fixes the next run on GitHub (27 November 2026) passed all four jobs: the backend
with 3702 passed and 7 skipped in 7 min 51 s (line coverage of `app/` 99%), the frontend with 1506
tests plus the build and both audits, the browser job with 732 tests in 19.6 minutes and no retry,
and Docker. The 7 skips are explained in [Latest full run](#latest-full-run).

### What the first complete run of the new modules found

The four-provider cards, the Network and Files screens and India Standard Time were each tested while
they were built. The first complete run of all 732 browser tests (26 November 2026, Microsoft Edge,
no retries) was the first time everything ran together, and 12 tests failed. There were five causes:
four were defects in the application and one was a group of test expectations that had not kept up.

| Failing tests | What failed | Cause | The fix |
| --- | --- | --- | --- |
| `long-data`, 6 (three widths, two tests each) | The page scrolled sideways (at desktop width: 4,121 px of content in a 1,440 px window) | The *Retry* button on a provider card prints the provider's display name on one line, so a very long name could not wrap. A defect of the four-provider cards | The button text may wrap and is capped at the card's width (`frontend/src/components/intel/ProviderCard.tsx`) |
| `files`, 2 | axe-core: a scrollable region must be reachable from the keyboard | The activity table and the share list scroll sideways on a narrow screen, but their only buttons were disabled and cannot take focus, so a keyboard user could not scroll them | Both are labelled regions that can take focus, the pattern the flow table already used (`ActivityList.tsx`, `ShareList.tsx` in `frontend/src/components/files/`) |
| `responsive`, 1 | The command palette ran past the bottom of a phone held sideways (844 × 390 px) | The two new entries, Network and Files, made its list taller than the screen | The list is capped to the screen height (`frontend/src/components/shell/CommandPalette.tsx`) |
| `motion`, `overview` and `files`, 1 each | The tests' expectations were wrong | The phone tab bar holds five links now and *System status* is in the side rail only; the overview has seven indicator types since MD5 and SHA-1 were added, not five; and in the one-time-link test Edge's own downloads page (`edge://downloads-hub/`) wrote console warnings that the test blamed on the application | The tests were corrected, and the visitor's console listener now ignores messages that come from an `edge://` page. No application change |
| `long-data`, 2 (two of the six above, once they got past the first problem) | axe-core: *target size*, at 390 × 844 px | These two tests had stopped at the sideways scroll and had never reached this check, which ran after the first fix, in the re-run of the failed groups. The links to the ThreatFox entry and to Malpedia on the provider card were 16 px tall; the smallest touch target allowed is 24 px | The links have a minimum height and padding (`ProviderCard.tsx`) |

Re-running the 152 affected tests (6 minutes) found the last row. After its fix the second complete
run passed all 732 tests (see [Latest full run](#latest-full-run)).

## Opt-in live tests

Two test modules talk to the real world. Both carry the pytest marker `live`, both are collected by
every `pytest` run, and both skip themselves unless you switch them on. A normal run, and CI, therefore
never spends a provider's quota and never captures a packet.

| Module | Switch | What it does | What it needs |
| --- | --- | --- | --- |
| `backend/tests/test_live_providers.py` | `CIPHERFORGE_LIVE_TESTS=1` | One lookup per provider (AbuseIPDB, AlienVault OTX, VirusTotal, ThreatFox) about `8.8.8.8`, Google's public resolver. It checks that the adapter understands the real answer: a clean status, a signal between 0 and 1, the fields the dashboard reads, and that the key appears nowhere in the result | The provider's key, as `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `VIRUSTOTAL_API_KEY` or `THREATFOX_API_KEY`, in the environment or in the git-ignored `.env`. A test whose key is missing is skipped, and so is one whose provider reports that the rate limit or quota is used up. A ThreatFox rejection of a configured key fails the test |
| `backend/tests/test_network_live_capture.py` | `CIPHERFORGE_LIVE_CAPTURE_TESTS=1` | Starts a real capture on the interface this machine would use to reach the network, sends five small UDP datagrams to `192.0.2.1` (an address reserved for documentation, RFC 5737, which the internet does not route), and checks that the capture saw them, stopped cleanly and left no thread behind | Npcap on Windows or libpcap on Linux, and the privilege capture needs on that system (see [Network monitoring: requirements](network-monitoring.md#requirements)). It is skipped without a driver, without permission or without a route, and prints nothing about the interface it used |

```powershell
# PowerShell, from backend/
$env:CIPHERFORGE_LIVE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -m live -q -rs

$env:CIPHERFORGE_LIVE_CAPTURE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest tests/test_network_live_capture.py -q -rs
```

```bash
# bash, from backend/
CIPHERFORGE_LIVE_TESTS=1 python -m pytest -m live -q -rs
CIPHERFORGE_LIVE_CAPTURE_TESTS=1 python -m pytest tests/test_network_live_capture.py -q -rs
```

`-rs` prints the reason for each skip, which is how you tell "no key" from "quota used up" from "no
driver". Each provider test sends exactly one request, so running them costs one lookup per
provider. The tests read the keys but never print or assert on them; a failing assertion is written so
that it cannot echo the key.

What a live pass proves: the adapter understood the provider's answer as it is today. What it does not
prove: that every other indicator type, or the provider's failure answers, look the way the adapter
expects. Those are covered by the canned answers above.

## Testing the dashboard

Unit tests (`npm test`, Vitest) cover components and helpers. What a person would actually see is
checked by an end-to-end suite in `frontend/e2e/`, written with [Playwright](https://playwright.dev/).
It drives a real browser against the **production build** of the dashboard, served with the
security headers from `frontend/nginx.conf`, which talks to the **real API** on a freshly seeded
copy of the [demo database](../README.md#try-it-without-api-keys). Expected figures are taken from
the API's own answers, not from what the page displays.

What is simulated and what is real in that setup (`backend/devtools/demo_server.py`):

| Part | In the browser tests |
| --- | --- |
| The API, the database, the scoring, the audit log | Real |
| The four threat-intelligence providers | Simulated: answers written for the demo, no key, no network. A value containing `rate-limit` or `provider-error` makes every provider that takes it answer with a rate-limit or a server error, and one containing `otx-down`, `virustotal-down` or `threatfox-down` makes only that provider fail. That is how the browser tests reach the failure screens. See [Things to try in the demo](user-guide.md#things-to-try-in-the-demo) |
| Network interfaces and live capture | Simulated: two made-up interfaces (`Simulated office LAN`, `Simulated quiet link`) and a packet source that produces synthetic traffic. Nothing is captured from this machine |
| Reading a capture file | Real: the sample file `frontend/e2e/data/synthetic-network.pcap` goes through the real PCAP reader, flow builder, detection rules and storage. Its addresses are private, reserved for documentation, or one invented IPv6 "attacker" from address space that has not been allocated; the well-known resolvers `8.8.8.8` and `1.1.1.1` stand in for clean traffic. `python -m devtools.synthetic_network` writes the file again, byte for byte, from `backend/devtools/synthetic_network.py` |
| Encrypted file sharing | Real: the real encryption, a random master key written to `backend/.demo/e2e.key`, and encrypted files in `backend/.demo/e2e-files/`. A rebuild of the demo database deletes both |
| Sign-in | Development sign-in (`AUTH_MODE=dev`): every request is made by one fixed user, `dev-user`. Microsoft Entra ID token checking is covered by the backend tests, not by the browser |

The demo server refuses to start unless its database is a `.db` file directly inside `backend/.demo/`,
so it cannot touch a real database. Invented network data exists only in tests and in this demo
tooling, never in the application itself, and the demo server says so when it starts
(`demo_mode` with `providers`, `network` and `data` marked as simulated or synthetic).

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
- The specs share one seeded database and run one after another. A complete run of the 732 tests took
  about 31 minutes on the author's Windows laptop (the 686 tests that existed before the network and
  file-sharing work took about 23, and an earlier run of 596 took about 37, so the time depends on how
  busy the computer is). On a GitHub runner the 686 tests took 16.9 minutes. So run the spec you are
  working on, and the whole suite before you commit. Locally there are no retries; CI allows one
  (`retries` in `frontend/playwright.config.ts`).

| Spec | What it proves |
| --- | --- |
| `shell` | Pages and navigation, the top bar, the `G` shortcuts, the command palette, the effects switch |
| `overview` | Every figure on the overview equals what the API returned; ranked lists, the details drawer, the map, refreshing, an API that does not answer |
| `indicators` | Search, every filter, sorting, paging, the address bar as the state, the record page |
| `delete` | Deleting indicators from the list (one, a Shift-clicked run, a whole page, a selection too long to list) and from a record. The confirmation asks first, and Cancel, Escape and a click outside leave everything in place. A failure keeps the dialog open and deletes nothing, a second click while it deletes does nothing, and indicators somebody else already deleted are counted while the rest go. Afterwards the indicator is gone from the list, the Overview, the record's address and the API, and the same value can be investigated again as a new record. Text written as an attack is listed as text. Everything works from the keyboard |
| `investigate` | Form validation, a lookup from the form to the evidence, refused and failed lookups, the palette hand-off |
| `providers` | One provider down while the others answer (each of AlienVault OTX, VirusTotal and ThreatFox in turn): the failed provider's card says so and offers Retry, the other two keep their answers and the score counts only the providers that answered. Retry asks again only for what failed and shows the stored answers again, and the cards keep showing India Standard Time in a browser set to another time zone |
| `status` | A healthy API, a degraded one, an unreachable one, and recovery |
| `network` | Capture-file analysis and live monitoring against the simulated packet source: a file is analysed and every number on the page is checked against the file read by the test itself; the alerts can be filtered; private, loopback and documentation addresses are analysed but never looked up; packet contents are counted but never stored or shown; wrong files are refused with the reason; the history opens and deletes sessions only after asking; a capture is started and stopped from the page and nothing keeps capturing afterwards; a start the server refuses is explained. Also hostile text, API errors, every screen width and axe-core |
| `files` | Journey D in a real browser: upload, share with a password, download anonymously, revoke and delete. A file that was tampered with is never released, the failure states of the public link are readable and release nothing, hostile file names stay plain text, the public page talks only to the share API and shows the one-time link once, and both the file screens and the public page pass axe-core |
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

- It uses simulated providers, so no real provider answer has been through the dashboard in an
  automated run, and VirusTotal and ThreatFox have not been called for real at all (see
  [Evidence by capability](#evidence-by-capability)).
- It uses a simulated packet source. A live capture has never run inside a browser test: it was run by
  hand, through the API, on one Windows computer without elevated privileges, and never on Linux. The
  capture-file analysis in the browser is real, but its input is one synthetic file.
- Every browser test signs in as the same development user, so the browser cannot show that one
  person's files and capture sessions are hidden from another. The backend tests do, with two users
  (`test_files_security.py`, `test_network_api.py`, `test_network_service_sessions.py`).
- It runs on SQLite. PostgreSQL is covered by the backend tests, which use it locally and in CI (the
  author ran the application against PostgreSQL by hand only up to Phase 3c, before the network and
  file tables existed).
- The security specs run against a small Node server that stands in for nginx and reads its header
  values from the real `nginx.conf`: the file is checked, nginx is not. A real nginx was run against
  a copy of the file by hand (see [Deployment: verification status](deployment.md#verification-status)),
  and the CI `docker` job starts the real nginx in its container, but it only checks that the page,
  the API behind nginx and the Content Security Policy header are there. The browser suite does not
  run against it.
- The encryption tests check the stored format by decrypting it independently with the `cryptography`
  package and check that every kind of tampering is refused. They do not replace an independent review
  of the design and they use no published test vectors (see
  [Encryption design: how it is tested](encryption-design.md#how-it-is-tested)).
- Automated checks find only part of the accessibility problems. No screen reader or other assistive
  technology was used, and the suite's contrast audit measures chart text against the flat glass
  colour, not against what the animated background shows through it. A one-off script that measured
  every text run on every screen against the live, moving background (phone and desktop) found no
  failure, but that script is not part of the repository.
- **Nobody has judged the look.** The checks measure contrast, layout, motion state and a quiet
  console. They cannot say whether the design is attractive or whether the motion feels right, and
  it has not been tuned on slow devices (switch the effects off there).
- It was run in Edge on Windows and, in CI, in Chromium on Linux. Firefox and Safari were not tried.

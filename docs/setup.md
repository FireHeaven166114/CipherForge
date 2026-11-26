# Setup

Full installation, configuration and troubleshooting detail for all three ways of running
CipherForge. Start with the [README](../README.md) if you have not already: it explains what the
project is and gives the fastest path to seeing it work. Come back here for prerequisites, every
setting, and what to do when something does not start.

| I want to | Go to |
| --- | --- |
| See every screen with no setup | [Path A](#path-a-try-it-without-api-keys) |
| Run the real application on my computer | [Path B](#path-b-run-the-real-application) |
| Get real answers from the four threat-intelligence providers | [Add your API keys](#add-your-api-keys-optional) |
| Run everything in Docker | [Path C](#path-c-run-everything-in-docker) |
| Start the API or the dashboard again, or build for production | [Development and production commands](#development-and-production-commands) |
| Create or update the database, check its version, take a backup or go back a version | [Database setup and migrations](#database-setup-and-migrations) |
| Look up a setting | [Environment variables](#environment-variables) |
| Turn on encrypted file sharing | [Generate the master key for file sharing](#generate-the-master-key-for-file-sharing) |
| Capture live network traffic | [Live capture prerequisites](#live-capture-prerequisites-optional) |
| Check which time zone is used | [Time zone](#time-zone) |
| Fix an error | [Common setup problems](#common-setup-problems) |

## Prerequisites

| You need | What for | Where to get it |
| --- | --- | --- |
| **Python 3.12 or newer** | Runs the API | <https://www.python.org/downloads/>. On Windows, tick **Add python.exe to PATH** in the installer. |
| **Node.js 22.22 or newer** (24 is recommended) | Builds and serves the dashboard. It includes `npm`. | <https://nodejs.org/en/download> |
| **A web browser** | You use CipherForge in it | Any modern browser. The browser tests (`npm run test:e2e`) drive Microsoft Edge on your computer and Chromium in the CI workflow. See [Testing](testing.md#testing-the-dashboard). |
| **About 400 MB of free disk space** | The Python and Node packages (a rough figure) | |

Optional:

- **Docker Desktop**, only for [Path C](#path-c-run-everything-in-docker):
  <https://www.docker.com/products/docker-desktop/>
- **Free API keys** for AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox, only if you want real
  answers. None is required, and you can add any of them. See
  [Add your API keys](#add-your-api-keys-optional).
- **A master key**, only if you want to use encrypted file sharing. You make it yourself with one
  command: [Generate the master key](#generate-the-master-key-for-file-sharing).
- **A packet-capture driver and the right privileges**, only for live network capture: Npcap on
  Windows, libpcap or raw packet sockets on Linux. Analysing a saved capture file needs neither. See
  [Live capture prerequisites](#live-capture-prerequisites-optional).
- **Git**, only if you get the project through a Git repository.

You also need **the project folder**: the folder that contains `backend`, `frontend` and `docs`. Put
it somewhere you can find it, for example `C:\Users\you\cipherforge`. Every command in this guide
starts from that folder.

Check your tools. On Windows PowerShell:

```powershell
python --version
node --version
npm.cmd --version
```

On macOS or Linux:

```bash
python3 --version
node --version
npm --version
```

Each command should print a version number: Python 3.12 or higher and Node v22.22.0 or higher. If one
says "not found", see [Common setup problems](#common-setup-problems).

## Three ways to run it

**Start with Path A.**

| | **Path A:** [try it without API keys](#path-a-try-it-without-api-keys) | **Path B:** [run the real application](#path-b-run-the-real-application) | **Path C:** [run everything in Docker](#path-c-run-everything-in-docker) |
| --- | --- | --- | --- |
| Best for | Learning every screen, with data already in it | Real lookups of your own indicators | People who already use Docker |
| What you see | Invented data and pretend providers, clearly labelled | Your own lookups. Real providers if you add keys. | The same as B, with the PostgreSQL database |
| Accounts and keys | None | Optional and free | Optional and free |
| You need | Python and Node | Python and Node | Docker |
| Rough time | About 10 minutes | About 15 minutes | About 10 minutes, plus the first build |
| Run by the author | Yes | Yes | **Not on a personal computer.** Docker was not available on the build machine. The CI workflow builds and starts the stack: see [Verification status](deployment.md#verification-status). |

Paths A and B both use port 8000 for the API, so run only one of them at a time. The demo shows a
banner at the top of every screen ("Simulated providers: this is demo data, not real threat
intelligence"); the real application does not. That is how you can tell which one you are looking at.

What the optional parts do in each path:

| | **Path A** (demo) | **Path B** | **Path C** (Docker) |
| --- | --- | --- | --- |
| Threat-intelligence providers | All four are simulated | Real. Only providers that have a key answer. | The same as B |
| Network monitoring: saved capture files | Analysed for real | Analysed for real | Analysed for real |
| Network monitoring: live capture | Simulated. Nothing is captured. | Real, once a driver and privileges are in place | Not available. See [Docker](network-monitoring.md#docker). |
| Encrypted file sharing | Works, with a throwaway key | Off until you set a master key | Off until you set a master key |

### Open a terminal in the project folder

A **terminal** is a window where you type commands. For Paths A and B you will use **two**: Terminal 1
runs the API and Terminal 2 runs the dashboard. Keep both open while you use CipherForge.

- **Windows:** open the project folder in File Explorer, click the address bar, type `powershell` and
  press Enter. (In Visual Studio Code: **Terminal, New Terminal**.)
- **macOS or Linux:** open your terminal app and move to the folder, for example `cd ~/cipherforge`.

To check you are in the right place, list the folder (`dir` on Windows, `ls` on macOS or Linux). You
should see `backend`, `frontend` and `docs`.

The commands differ slightly by system. This guide always shows both versions.

| | Windows (PowerShell) | macOS or Linux |
| --- | --- | --- |
| Start Python | `python` | `python3` |
| Python inside the project's private environment | `.\.venv\Scripts\python.exe` | `.venv/bin/python` |
| Start npm | `npm.cmd` | `npm` |
| Copy a file | `Copy-Item .env.example .env` | `cp .env.example .env` |
| Set a variable for this terminal | `$env:NAME = "value"` | `export NAME=value` |

The guide runs the environment's Python by its full path instead of "activating" the environment.
PowerShell often blocks the activation script, and this way works the same everywhere.

### Path A: try it without API keys

This runs the real application in **demo mode**. Three things are different. The four providers
(AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox) are **simulated**, so nothing is sent to any of
them. The database is filled with about two weeks of invented lookups, so every screen has something
to show. And network monitoring uses a simulated interface list and packet source, so nothing is
captured from your network. You need no `.env` file and no keys.

**Step 1. In Terminal 1, install and start the demo API.**

Windows (PowerShell):

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn devtools.demo_server:create_demo_app --factory
```

macOS or Linux:

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m uvicorn devtools.demo_server:create_demo_app --factory
```

What these lines do:

- `cd backend` moves into the backend folder. Stay in it for the rest of Terminal 1.
- `python -m venv .venv` creates a **virtual environment**: a private folder (`backend/.venv`) that
  holds this project's Python packages, so nothing else on your computer is touched. You do this
  once.
- `pip install -r requirements-dev.txt` downloads and installs the packages. It takes a few minutes
  the first time.
- `python -m uvicorn ... --factory` starts the API. **uvicorn** is the program that runs Python web
  apps, and `--factory` tells it to build the app by calling `create_demo_app`.

The first start prints a lot of lines while it creates the invented data. The API is ready when the
last lines look like this (your times, the number in brackets and the counts will differ):

```text
00:58:25 INFO     cipherforge.demo: demo_seeded lookups=233 rejected=4 indicators=135
00:58:25 INFO     uvicorn.error: Started server process [23976]
00:58:25 INFO     uvicorn.error: Waiting for application startup.
00:58:25 INFO     cipherforge.app: startup version=0.5.0 environment=development auth_mode=dev
00:58:25 INFO     uvicorn.error: Application startup complete.
00:58:25 INFO     uvicorn.error: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Leave this terminal open. From now on it prints one line for every request the dashboard makes. That
is normal.

To check it, open <http://127.0.0.1:8000/health> in your browser. It should show
`{"status":"ok","service":"cipherforge-api","version":"0.5.0"}`.

**Step 2. In Terminal 2, start the dashboard.** Open a second terminal in the project folder, then:

Windows (PowerShell):

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

macOS or Linux:

```bash
cd frontend
npm ci
npm run dev
```

`npm ci` installs the exact package versions listed in `package-lock.json` (a few minutes the first
time). `npm run dev` starts the dashboard's web server, which is called Vite. You should see something
like:

```text
> cipherforge-frontend@0.5.0 dev
> vite

  VITE v8.3.5  ready in 1700 ms

  ➜  Local:   http://127.0.0.1:5173/
```

**Step 3. Open <http://127.0.0.1:5173> in your browser.** You should see the Overview: a banner
saying the providers are simulated, numbers on the tiles, charts, and **API ONLINE** in the top bar.
The navigation lists Overview, Investigate, Indicators, Network, Files and System status. A labelled
picture of the Overview is in [user-guide.md](user-guide.md), along with things to try.

If the top bar says **API OFFLINE**, the API in Terminal 1 is not running. Check that terminal.

**Good to know about the demo**

- **Everything is invented.** The demo's own indicators use the names the internet reserves for
  examples (`example.com`, `.org`, `.net`). Its "malicious" addresses are IPv6 addresses from space
  nobody has been given, and its only IPv4 addresses are well-known public DNS servers, shown as
  clean. A test checks that this list cannot accuse a real host. **If you type something of your own,
  the simulated providers invent an answer for that too** (the same answer every time). It says
  nothing about the real thing, so never use the demo to judge a real indicator.
- **No sign-in is needed.** You are a local `SecurityAnalyst`. Set `CIPHERFORGE_DEMO_ROLES` to
  change the roles.
- **The invented data lives in `backend/.demo/demo.db`** (Git ignores it). The demo refuses to use
  any other place, so it cannot be pointed at a real database. It is rebuilt at start-up when its
  newest lookup is more than a day old, so the "last 14 days" charts always have data.
- **Network monitoring is simulated.** The Network screen offers two pretend interfaces ("Simulated
  office LAN" and "Simulated quiet link") and plays back made-up packets. Nothing is captured from
  your computer. A saved capture file that you upload is analysed for real. See
  [Trying it without a real capture](network-monitoring.md#trying-it-without-a-real-capture).
- **File sharing works, with a throwaway key.** The demo makes its own random master key, so you can
  upload and share files straight away. The key (`backend/.demo/demo.key`) and the encrypted files
  (`backend/.demo/demo-files/`) sit beside the demo database, and a rebuild deletes all three. Do not
  keep anything you care about in the demo.
- **The demo loosens the request limits** (lookups, uploads, new share links and link downloads: 600
  per minute each) so that clicking around does not trip them. The real application's defaults are
  in [Environment variables](#environment-variables).
- **It is for development and learning only.** The demo code is kept out of the Docker image and the
  real application never imports it.

### Path B: run the real application

This is CipherForge without the pretend parts. It starts empty and every lookup is real. It works
with no API keys at all (every result will then say **Not assessed**), and you can
[add free keys](#add-your-api-keys-optional) afterwards.

**Step 1. Create your settings file.** In the project folder:

Windows (PowerShell):

```powershell
Copy-Item .env.example .env
```

macOS or Linux:

```bash
cp .env.example .env
```

`.env` holds your settings. Git ignores it, so your keys cannot be committed by accident. (File
Explorer may hide files that start with a dot. That is normal.)

**Step 2. Choose a database.** Open `.env` in a text editor (on Windows, run `notepad .env`). Find the
line that starts with `DATABASE_URL=` and replace it with this one:

```text
DATABASE_URL=sqlite+pysqlite:///./cipherforge.db
```

SQLite keeps everything in one file (`backend/cipherforge.db`), which is ideal for trying things out.
Leave all the other lines alone, and save the file. For PostgreSQL, use
[Docker](#path-c-run-everything-in-docker).

**Step 3. In Terminal 1, set up and start the API.** Skip the first three commands if you already ran
them for Path A.

Windows (PowerShell):

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory
```

macOS or Linux:

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m uvicorn app.main:create_app --factory
```

`alembic upgrade head` creates the tables in the database. This is called a **migration**. Run it
once now, and again after you update the project. On a new SQLite database it prints:

```text
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 0001_baseline, Baseline: establishes Alembic version tracking. No application tables yet.
INFO  [alembic.runtime.migration] Running upgrade 0001_baseline -> 0002_threat_intel, Threat intelligence: sources, indicators, provider observations and the audit log.
INFO  [alembic.runtime.migration] Running upgrade 0002_threat_intel -> 0003_hash_indicators, MD5 and SHA-1 file hashes as indicator types.
INFO  [alembic.runtime.migration] Running upgrade 0003_hash_indicators -> 0004_network_monitoring, Network monitoring: capture sessions, flows and alerts.
INFO  [alembic.runtime.migration] Running upgrade 0004_network_monitoring -> 0005_encrypted_files, Encrypted file sharing: encrypted files and their share links.
```

What each step does, how to check the database's version, and how to take a backup before an update
are in [Database setup and migrations](#database-setup-and-migrations).

Run both `alembic` and `uvicorn` from the `backend` folder. The database path in `.env` is relative to
the folder you run the command from, so running one of them from somewhere else would quietly create
a second, empty database.

The API is ready when you see this (your times and the number in brackets will differ):

```text
23:57:32 INFO     uvicorn.error: Started server process [19652]
23:57:32 INFO     uvicorn.error: Waiting for application startup.
23:57:32 INFO     cipherforge.app: startup version=0.5.0 environment=development auth_mode=dev
23:57:32 INFO     uvicorn.error: Application startup complete.
23:57:32 INFO     uvicorn.error: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Check it in your browser. <http://127.0.0.1:8000/health> should show `{"status":"ok", ...}`, and
<http://127.0.0.1:8000/ready> should show `{"status":"ready","checks":{"database":"ok"}}`. The second
one proves the API can reach its database. <http://127.0.0.1:8000/docs> is an interactive page where
you can try every endpoint. (It exists only while `ENVIRONMENT` is not `production`.)

**Step 4. In Terminal 2, start the dashboard.** This is the same as Step 2 of Path A:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

(On macOS or Linux, use `npm` instead of `npm.cmd`.)

**Step 5. Open <http://127.0.0.1:5173>.** This is a brand-new installation, so the Overview is empty:

![The Overview of a brand-new installation: every headline tile shows 0, a panel says Nothing here yet, the providers panel says none is configured, and the platform modules are listed](screenshots/first-run-empty.png)

1. **The headline tiles** all show 0, because nothing has been investigated.
2. **"Nothing here yet"** is where the highest-risk and latest indicators will appear.
3. **The providers panel** says that no provider is configured. Until you add a key, every
   investigation comes back as **Not assessed**.
4. **Platform modules** shows what the project is made of. Threat intelligence, Network monitoring
   and Secure file sharing are **LIVE**. Incident management and Administration are **PLANNED**.

The pictures in this guide were taken with an earlier version of the dashboard, before VirusTotal,
ThreatFox, network monitoring and file sharing were added, so your screen lists more providers and
modules than they do.

**Step 6. Make your first investigation.** Click **Investigate an indicator**, click the **IPv4**
example (`8.8.8.8`) and press **Investigate**. With no keys you will see this:

![A first investigation with no API keys: the gauge says Not assessed, and the provider cards say Not configured](screenshots/first-run-no-keys.png)

1. **The gauge** says **Not assessed** instead of showing a number.
2. **The explanation** says that no provider answered, so this is not a clean result: nothing was
   checked.
3. **Each provider card** says **Not configured**: no key is set on the server for that provider. For
   `8.8.8.8` your screen shows four cards: AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox.

This is correct, not a bug. CipherForge cannot say anything about an indicator until at least one
provider answers.

### Add your API keys (optional)

To get real answers, add the free keys. You can add any of them, none is required, and a provider
with no key is simply skipped. If you look up a kind of indicator that a provider does not handle, its
card says **Not supported**, which is normal.

| Provider | It handles | Get a key | Setting in `.env` |
| --- | --- | --- | --- |
| **AbuseIPDB** | IPv4 and IPv6 addresses | Create a free account at <https://www.abuseipdb.com/register> and sign in. Then open the **API** tab of your account, <https://www.abuseipdb.com/account/api> (this page shows an error until you are signed in), and create a key | `ABUSEIPDB_API_KEY` |
| **AlienVault OTX** | IP addresses, domains, URLs, and MD5, SHA-1 and SHA-256 hashes | Create a free account at <https://otx.alienvault.com>. Your key (the "OTX Key") is shown on <https://otx.alienvault.com/settings> | `OTX_API_KEY` |
| **VirusTotal** | IP addresses, domains, URLs, and MD5, SHA-1 and SHA-256 hashes | Sign in to your VirusTotal account (or create a free one). Your key is on <https://www.virustotal.com/gui/my-apikey> | `VIRUSTOTAL_API_KEY` |
| **ThreatFox** (abuse.ch) | IP addresses, domains, URLs, and MD5 and SHA-256 hashes (not SHA-1) | Get an Auth-Key from abuse.ch at <https://auth.abuse.ch/> | `THREATFOX_API_KEY` |

1. Open `.env` and paste each key after the `=`, with no spaces and no quotes. Add only the lines for
   the providers you want:

   ```text
   ABUSEIPDB_API_KEY=paste-your-key-here
   OTX_API_KEY=paste-your-key-here
   VIRUSTOTAL_API_KEY=paste-your-key-here
   THREATFOX_API_KEY=paste-your-key-here
   ```

2. Save the file. In Terminal 1 press `Ctrl+C` to stop the API, then start it again with the last
   command of Step 3 (the one with `uvicorn`). You do not need to run `alembic` again.
3. Investigate `8.8.8.8` again. A provider that now answers shows **Answered** (or **No data**)
   instead of **Not configured**.

Keep your keys private. Never paste them into a chat, a screenshot or a commit. CipherForge keeps
them on the server, never writes them to its logs and never sends them to the browser. Free accounts
have limits, so use the "Ask the providers again" option sparingly. CipherForge saves every answer and
reuses it until it goes stale (24 hours for VirusTotal; the other lifetimes are in
[Environment variables](#environment-variables)).

Two things to know about VirusTotal and network monitoring:

- The free VirusTotal key allows 4 requests per minute and 500 per day, and VirusTotal keeps every
  indicator you look up. Do not look up confidential indicators with it.
- Network monitoring looks up the public addresses it sees in traffic with the providers that have a
  key. Private, loopback and other non-public addresses are never sent. Set
  `EXTERNAL_ENRICHMENT_ENABLED=false` if you do not want any address from your traffic sent out.

> **What has been checked against the real services.** AbuseIPDB and AlienVault OTX have been called
> for real: the opt-in live test passed for both, with one lookup of `8.8.8.8` each. VirusTotal and
> ThreatFox have never been called live, because no keys were available. Their adapters follow the
> providers' official API documentation and are tested only against hand-written sample answers, and
> their live tests were skipped for lack of keys. The full status is in
> [Verification status](threat-intelligence.md#verification-status).

If you have a VirusTotal or ThreatFox key, you can continue that check yourself:

1. Put `VIRUSTOTAL_API_KEY` or `THREATFOX_API_KEY` (or both) in `.env`, as shown above. Git ignores
   that file.
2. In PowerShell, from the `backend` folder:

   ```powershell
   $env:CIPHERFORGE_LIVE_TESTS="1"; .\.venv\Scripts\python.exe -m pytest -m live -q -rs
   ```

   On macOS or Linux: `CIPHERFORGE_LIVE_TESTS=1 .venv/bin/python -m pytest -m live -q -rs`.

Each provider test sends one request. A provider with no key, or whose quota is used up, is skipped
and not failed, and `-rs` prints the reason for each skip. [Opt-in live tests](testing.md#opt-in-live-tests)
explains what a pass proves. Whatever the result, do one real lookup with your own key before you rely
on the output. If a card shows **Error**, see the **Threat-intelligence providers** group in
[Common setup problems](#common-setup-problems).

### Path C: run everything in Docker

Docker runs the database, the API and the dashboard in containers, so you do not need to install
Python or Node. It uses PostgreSQL. This section covers the first run; [deployment.md](deployment.md)
has the full detail: every service, configuration, migrations, backups and what to do before exposing
CipherForge to a network.

> **Checked by the automatic tests, not by hand.** Docker was not available on the machine this
> project was built on, so these steps were not run on a personal computer. The `docker` job of the
> GitHub Actions workflow builds both images, starts the whole stack on a Linux machine and checks
> that the dashboard and the API answer, so it is expected to work. Docker Desktop on Windows or
> macOS was not tried. If something fails, use Path A or B. Details:
> [deployment.md](deployment.md#verification-status).

1. Install **Docker Desktop** and start it. Wait until it says it is running.
2. In the project folder, create your settings file (Windows: `Copy-Item .env.example .env`;
   macOS or Linux: `cp .env.example .env`).
3. Open `.env` and replace the value of `POSTGRES_PASSWORD` with a random one made of **letters and
   digits only**. The password is placed inside a web address, so symbols cause trouble. To make one:

   Windows (PowerShell):

   ```powershell
   -join ((48..57) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
   ```

   macOS or Linux:

   ```bash
   openssl rand -hex 24
   ```

   Do this **before the first start**. PostgreSQL stores the password when it first creates its data,
   so changing it later means deleting the data with `docker compose down --volumes`.
4. Build and start everything:

   ```bash
   docker compose up --build
   ```

   The first run downloads images and builds the project, which takes a few minutes. Compose starts
   four things in order: **postgres** (the database), **migrate** (creates the tables, then exits),
   **backend** (the API) and **frontend** (nginx, which serves the dashboard and forwards `/api`,
   `/health` and `/ready` to the API).
5. Open <http://localhost:3000>.

Everything is bound to `127.0.0.1`, so only your own computer can reach it. The template uses
`AUTH_MODE=dev` (no sign-in), which is only safe for this kind of local use. To add API keys, put
them in `.env` as described in [Add your API keys](#add-your-api-keys-optional), stop the stack with
`Ctrl+C` and start it again with `docker compose up`.

| Port on your computer | What is there | Setting in `.env` |
| --- | --- | --- |
| 3000 | The dashboard | `FRONTEND_PORT` |
| 8000 | The API | `BACKEND_PORT` |
| 5432 | PostgreSQL | `POSTGRES_PORT` |

Three things are different in Docker:

- **The tables are created for you.** The `migrate` service runs `alembic upgrade head` before the API
  starts, and the API does not start if it fails. Take a backup before you bring up a new version:
  see [Database setup and migrations](#database-setup-and-migrations).
- **Encrypted file sharing** needs `CIPHERFORGE_MASTER_KEY` in `.env`. Make one as shown in
  [Generate the master key](#generate-the-master-key-for-file-sharing), then run `docker compose up`
  again. The encrypted files are kept in the `encrypted_files` Docker volume.
- **Live network capture is not available**, because the API container has every privilege removed.
  Saved capture files can still be analysed. See [Docker](network-monitoring.md#docker).

## Stop it and start it again

- **Stop:** click in a terminal and press `Ctrl+C`. Do this in both terminals. For Docker, press
  `Ctrl+C` in the terminal that runs `docker compose up`, or run `docker compose down`.
- **Start again later:** you do not need to install anything again. Open two terminals in the project
  folder and run only the start commands. For Path B, use `app.main:create_app` instead of
  `devtools.demo_server:create_demo_app`.

  Terminal 1 (Windows):

  ```powershell
  cd backend
  .\.venv\Scripts\python.exe -m uvicorn devtools.demo_server:create_demo_app --factory
  ```

  Terminal 1 (macOS or Linux):

  ```bash
  cd backend
  .venv/bin/python -m uvicorn devtools.demo_server:create_demo_app --factory
  ```

  Terminal 2 (Windows: `npm.cmd`; macOS or Linux: `npm`):

  ```powershell
  cd frontend
  npm.cmd run dev
  ```

- **Your data stays.** Path B keeps everything in `backend/cipherforge.db`, and its encrypted files
  (if you use file sharing) in `backend/data/encrypted-files/`. Path A keeps its invented data in
  `backend/.demo/demo.db`, with its throwaway key and encrypted files beside it. Docker keeps the
  database in one Docker volume and the encrypted files in another: `docker compose down` keeps both
  and `docker compose down --volumes` deletes both.
- **Start again from nothing.** Path B: stop the API and delete `backend/cipherforge.db`, then run
  `alembic upgrade head` again. If you used file sharing, also delete `backend/data/encrypted-files/`,
  because those files cannot be opened without the database rows that hold their keys. Path A: set
  `CIPHERFORGE_DEMO_RESET=1` for one start and the demo rebuilds its data at once (Windows:
  `$env:CIPHERFORGE_DEMO_RESET = "1"`, then `Remove-Item Env:CIPHERFORGE_DEMO_RESET` afterwards;
  macOS or Linux:
  `CIPHERFORGE_DEMO_RESET=1 .venv/bin/python -m uvicorn devtools.demo_server:create_demo_app --factory`).
  Docker: `docker compose down --volumes`. To remove only some indicators, delete them in the
  dashboard instead: see [Deleting indicators](user-guide.md#deleting-indicators).

## Development and production commands

Run each command from the folder in the second column. The Windows commands are for PowerShell. The
Python commands use the project's private environment in `backend/.venv`, as in Path B. Creating that
environment and installing the packages for the first time is covered in
[Path A](#path-a-try-it-without-api-keys) and [Path B](#path-b-run-the-real-application).

| What | Folder | Windows (PowerShell) | macOS or Linux |
| --- | --- | --- | --- |
| Start the API | `backend` | `.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory` | `.venv/bin/python -m uvicorn app.main:create_app --factory` |
| Start the demo API (Path A) | `backend` | `.\.venv\Scripts\python.exe -m uvicorn devtools.demo_server:create_demo_app --factory` | `.venv/bin/python -m uvicorn devtools.demo_server:create_demo_app --factory` |
| Start the dashboard (development server) | `frontend` | `npm.cmd run dev` | `npm run dev` |
| Install or update the API's packages | `backend` | `.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt` | `.venv/bin/python -m pip install -r requirements-dev.txt` |
| Install or update the dashboard's packages | `frontend` | `npm.cmd ci` | `npm ci` |
| Build the dashboard for production | `frontend` | `npm.cmd run build` | `npm run build` |
| Start everything in Docker | project folder | `docker compose up --build` | `docker compose up --build` |

- **The API** listens on <http://127.0.0.1:8000> unless you pass `--port` (see
  [Free a port or use another one](#free-a-port-or-use-another-one)). Run a single API process: the
  rate limits are counted in memory, so every extra process would allow its own share.
- **The dashboard's development server** runs on <http://127.0.0.1:5173>. It passes `/api`, `/health`
  and `/ready` on to the API (at `http://127.0.0.1:8000`, or at `VITE_DEV_PROXY_TARGET`), so
  `CORS_ORIGINS` can stay empty. If port 5173 is busy, it stops with an error instead of choosing
  another port.
- **`requirements-dev.txt`** adds the test and lint tools to `requirements.txt`. The Docker image
  installs only `requirements.txt`.
- **The commands that run the tests** are under [Run the tests](#run-the-tests). The linters, the
  security checks and the type checks are in [testing.md](testing.md#quality-checks), and the
  browser tests are explained in [Testing the dashboard](testing.md#testing-the-dashboard).

### Build the dashboard for production

`npm run build` checks the TypeScript types and then builds the dashboard. The finished files are
written to `frontend/dist/`. Git ignores that folder. The dashboard is a single-page app, so the web
server in front of it must send unknown paths to `index.html` and pass `/api/`, `/health` and `/ready`
on to the API. `frontend/nginx.conf` does both, and it is what the Docker image uses. It also raises
the upload limit to 500 MB for file uploads and capture files (`/api/v1/files` and
`/api/v1/network/pcap`). The API's own limits, `MAX_ENCRYPTED_FILE_SIZE_MB` and
`NETWORK_MAX_PCAP_SIZE_MB`, still apply.

`npm run build:app` is the same build without the type check of the end-to-end test files. The Docker
image uses it. `npm run preview` serves the finished build on your computer for a quick look. It is
not a production server.

### Build and run in Docker

`docker compose up --build` builds both images, starts PostgreSQL, runs the migrations, and then starts
the API and the dashboard. The dashboard image builds the dashboard inside Docker and serves it with
nginx, so you do not run `npm run build` yourself: the built files stay inside the image, in
`/usr/share/nginx/html`. The ports, the first start and the checks are in
[Path C](#path-c-run-everything-in-docker). Take a backup before you bring up a new version: see
[Database setup and migrations](#database-setup-and-migrations).

### Run the tests

[testing.md](testing.md) explains what each kind of test proves and what it does not. These are the
commands. Run the backend ones from `backend` and the dashboard ones from `frontend`.

Windows (PowerShell):

```powershell
# from backend/
.\.venv\Scripts\python.exe -m pytest

$env:TEST_DATABASE_URL = "postgresql+psycopg://user:password@localhost:5432/test_db"
.\.venv\Scripts\python.exe -m pytest
Remove-Item Env:TEST_DATABASE_URL

$env:CIPHERFORGE_LIVE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -m live -q -rs
Remove-Item Env:CIPHERFORGE_LIVE_TESTS

$env:CIPHERFORGE_LIVE_CAPTURE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest tests/test_network_live_capture.py -q -rs
Remove-Item Env:CIPHERFORGE_LIVE_CAPTURE_TESTS

# from frontend/
npm.cmd test
npm.cmd run test:e2e
```

macOS or Linux:

```bash
# from backend/
.venv/bin/python -m pytest
TEST_DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/test_db .venv/bin/python -m pytest
CIPHERFORGE_LIVE_TESTS=1 .venv/bin/python -m pytest -m live -q -rs
CIPHERFORGE_LIVE_CAPTURE_TESTS=1 .venv/bin/python -m pytest tests/test_network_live_capture.py -q -rs

# from frontend/
npm test
npm run test:e2e
```

| Command | What it runs |
| --- | --- |
| `pytest` | The backend unit and API tests on SQLite. It never calls a real provider and never captures real packets: the two opt-in modules below skip themselves unless you switch them on. Tests that need PostgreSQL are skipped. |
| `pytest` with `TEST_DATABASE_URL` | The same tests, plus the PostgreSQL variants. Point it at a **throwaway database**: the tests create and drop its tables. The user, password and database name above are placeholders. |
| `pytest -m live` with `CIPHERFORGE_LIVE_TESTS=1` | One real lookup per provider, about Google's public resolver `8.8.8.8`. The keys come from the environment or from `.env`. A provider without a key is skipped, and each lookup uses one request of that provider's quota. |
| `pytest tests/test_network_live_capture.py` with `CIPHERFORGE_LIVE_CAPTURE_TESTS=1` | A real capture on this computer: five small datagrams are sent to a documentation address (`192.0.2.1`) and the test checks that the capture saw them. It needs a driver and capture privileges, and is skipped without them: see [Live capture prerequisites](#live-capture-prerequisites-optional). |
| `npm test` | The dashboard's unit tests (Vitest). |
| `npm run test:e2e` | Builds the dashboard, then drives a real browser (Edge locally, Chromium in CI) against it and the demo API. It uses its own ports, 8100 for the API and 4180 for the web server, so a development stack on 8000 and 5173 can stay up. |

### Before it faces a network

Compose and `.env.example` are set up for your own computer. Before anyone else can reach the stack,
read [Before exposing it beyond your machine](deployment.md#before-exposing-it-beyond-your-machine).
In short:

- With `ENVIRONMENT=production`, the API refuses to start with `AUTH_MODE=dev`, with SQLite, or with a
  `DATABASE_URL` that still says `CHANGE_ME`. It also switches the `/docs` page off.
- The dashboard cannot sign in to Microsoft Entra ID yet, so it cannot be used against an API that
  requires sign-in (see [Limitations](../README.md#limitations)).
- CipherForge has no built-in HTTPS. A reverse proxy in front of the dashboard has to provide it.

## Database setup and migrations

CipherForge's tables are created and changed by **migrations**: numbered scripts that a tool called
Alembic runs in order. The API never creates tables itself. A new database has to be migrated before
the API can use it, and an existing one has to be migrated again after every update that brings a new
migration. Docker does this for you: its `migrate` service runs before the API starts.

### Create or update the database

Run the commands from the `backend` folder, where `alembic.ini` is. Alembic reads `DATABASE_URL` from
`.env` through the same settings as the API, so a wrong setting shows up as the same
`ConfigurationError`. A relative SQLite path is read from the folder you run the command in.

| What | Windows (PowerShell) | macOS or Linux |
| --- | --- | --- |
| Create or update the database | `.\.venv\Scripts\python.exe -m alembic upgrade head` | `.venv/bin/python -m alembic upgrade head` |
| Show the revision the database is at | `.\.venv\Scripts\python.exe -m alembic current` | `.venv/bin/python -m alembic current` |
| List every revision | `.\.venv\Scripts\python.exe -m alembic history` | `.venv/bin/python -m alembic history` |
| Go back one revision | `.\.venv\Scripts\python.exe -m alembic downgrade -1` | `.venv/bin/python -m alembic downgrade -1` |

`head` means the newest migration. When the database is already up to date, `upgrade head` changes
nothing.

### The five migrations

| Revision | What upgrading does | What going back does |
| --- | --- | --- |
| `0001_baseline` | Starts version tracking. It creates no tables. | Nothing to undo. |
| `0002_threat_intel` | Creates the tables for sources, indicators, provider observations and the audit log. Database triggers make the audit log append-only. | Drops those tables, **including the audit log**. |
| `0003_hash_indicators` | Lets an indicator be an MD5 or SHA-1 hash as well. Existing rows are not touched. | Refused while any MD5 or SHA-1 indicator is stored. Delete them first. |
| `0004_network_monitoring` | Creates the tables for capture sessions, flows and alerts. | Drops those three tables and their data. |
| `0005_encrypted_files` | Creates the tables for encrypted files and their share links. | Drops both tables. The encrypted files on disk stay, but they can never be opened, because their keys were in the dropped rows. |

### Check which version the database is at

Run the `current` command above. A database that is up to date prints `0005_encrypted_files (head)`.
If it prints an older revision, run `upgrade head`. If it prints no revision at all, the database has
never been migrated.

### Back up before you update

Take a backup before you upgrade a database that holds data you want to keep. Stop the API first.

- **SQLite (Path B).** Copy `backend/cipherforge.db` to a safe place. In `backend`, on Windows:
  `Copy-Item cipherforge.db cipherforge-before-update.db`. On macOS or Linux:
  `cp cipherforge.db cipherforge-before-update.db`. Keep the copy's name ending in `.db`: Git ignores
  those names, but it does not ignore `.bak` or `.sql` files. Better still, move the copy out of the
  project folder.
- **PostgreSQL in Docker (Path C).** Docker migrates when you run `docker compose up`, so back up
  before `docker compose up --build`. If the stack is not running, start only the database with
  `docker compose up -d postgres`. Then run this (from [Backups](deployment.md#backups)):

  ```bash
  docker compose exec postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > backup.sql
  ```

  On Windows, run it in Git Bash or WSL: Windows PowerShell 5.1 saves the file in a format that `psql`
  cannot read. Move `backup.sql` out of the project folder, because the dump holds your data and Git
  does not ignore `.sql` files.
- **PostgreSQL somewhere else.** Use that server's own backup tools.
- **Encrypted files and the master key.** If you use file sharing, back up the encrypted files with the
  database: the folder `backend/data/encrypted-files/`, or the `encrypted_files` Docker volume. Keep the
  master key too, in a different place. A backup is only useful when the database, the encrypted files
  and the key belong together: see [Storage and cleanup](file-sharing.md#storage-and-cleanup).

### Update an existing installation

1. Stop the API (`Ctrl+C`).
2. Back up, as above.
3. Put the new version of the project in place (for example with `git pull`).
4. Install the packages again: the API's in `backend`, and the dashboard's in `frontend` (the commands
   are in [Development and production commands](#development-and-production-commands)).
5. Run `upgrade head` from `backend`.
6. Start the API and open <http://127.0.0.1:8000/ready>. It should show
   `{"status":"ready","checks":{"database":"ok"}}`.

With Docker, steps 4 and 5 are done for you: `docker compose up --build` rebuilds the images and runs
the `migrate` service first.

### If a migration fails

Alembic prints the error at the end of its output. Find it in this table.

| What you see | Likely cause | What to do |
| --- | --- | --- |
| `ConfigurationError: Invalid configuration - NAME: ...` | A setting in `.env` is wrong. Alembic reads the same settings as the API. | Fix the setting named in the message (`DATABASE_URL` is the usual one) and run the command again. |
| An `OperationalError` about connecting, about a password, or `unable to open database file` | The database cannot be reached. The exact wording depends on the database. | SQLite: run from `backend` and check that the folder in `DATABASE_URL` exists. PostgreSQL: check that the server is running and that the host, port, user and password are right (URL-encode symbols in the password). |
| `permission denied` from PostgreSQL | The database user may not create tables, functions or triggers. Migration 0002 creates a function and triggers. | Run the migration with a user that may create them in this database. |
| `RuntimeError: SQLite foreign key enforcement is on, so rebuilding threat_indicators would delete its provider observations...` | Migration 0003 was run on a SQLite connection that had foreign keys switched on. The `alembic` command does not do that. | Run the migration with the command in this guide, not from your own script. |
| `Can't locate revision identified by '...'` | A newer version of CipherForge already upgraded this database, and you are running older code. | Run the version that matches the database, or restore the backup you took before the upgrade. Do not edit the version table by hand. |
| `RuntimeError: Cannot downgrade: N MD5 or SHA-1 indicator(s) are stored. Delete them first, or stay on this revision.` | You tried to go back past migration 0003 while such indicators exist. | Delete those indicators in the dashboard ([Deleting indicators](user-guide.md#deleting-indicators)), or stay on this revision. |
| Docker: the `migrate` service exits with an error, and the API never starts | Any of the causes above. | `docker compose logs migrate` shows the error. Fix it, then run `docker compose up` again, or `docker compose run --rm migrate`. |

After a failure, run the `current` command to see where the database is.

- **PostgreSQL:** Alembic normally runs the whole upgrade in one transaction, so a failed run leaves
  the database as it was. Fix the cause and run the command again.
- **SQLite:** Alembic cannot undo steps on SQLite (its log says `Will assume non-transactional DDL`),
  so a run that fails half-way can leave the finished steps in place. If the database holds nothing you
  want to keep, delete the file and run the command again. Otherwise restore your backup, fix the
  cause and run it again.

### Go back to an earlier version

Every migration has a downgrade. Use the `downgrade -1` command above to undo the newest one, or name
the revision you want to stay at, for example `alembic downgrade 0004_network_monitoring`. Check the
result with `current`.

Going back **deletes data**, as the table of migrations shows. Back up first. Going back past
`0002_threat_intel` deletes the audit log, and `alembic downgrade base` removes every table. A
downgrade does not change the code: run the older version of CipherForge that matches the database.

With Docker, run the same commands in the `migrate` service, for example
`docker compose run --rm migrate alembic current`, or
`docker compose run --rm migrate alembic downgrade -1`.

## Environment variables

CipherForge reads its settings from the `.env` file in the project folder, whichever folder you start
the API from. It is the file you made by copying `.env.example`. **After you change a setting, stop
the API (`Ctrl+C`) and start it again.**

- **Default** is what CipherForge uses when the setting is missing from `.env`. The defaults lean
  towards safety. If you leave out `ENVIRONMENT` and `AUTH_MODE`, you get `production` and `entra`,
  which refuse the shortcuts that are fine on your own computer. `.env.example` sets the relaxed
  values for local use, and the tables say where the template differs from the default.
- A wrong value stops the API from starting. The last line of the error names the setting but never
  shows its value, for example
  `ConfigurationError: Invalid configuration - PROVIDER_TIMEOUT_SECONDS: Input should be less than or equal to 30`.
  If several settings are wrong, they are listed one after another, separated by semicolons.
- Sizes in settings that end in `_MB` count 1 MB as 1,048,576 bytes (1024 x 1024).
- Docker Compose reads `.env` too and passes the settings on with the same defaults. Two settings are
  not taken from `.env` there: `DATABASE_URL` (built from the `POSTGRES_*` settings) and
  `ENCRYPTED_FILE_STORAGE_PATH` (always the `encrypted_files` volume). The one-shot `migrate` job gets
  only the application, authentication, CORS and database settings. The provider keys and the master
  key go to the `backend` service only.

**Application**

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `ENVIRONMENT` | `production` (the template sets `development`) | `development`, `test`, `production` | `production` is strict: it needs PostgreSQL, refuses `AUTH_MODE=dev`, refuses a database URL that still contains `CHANGE_ME`, and switches the `/docs` and `/openapi.json` pages off. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | How much the API writes to its log. |
| `LOG_FORMAT` | `json` (the template sets `console`) | `console`, `json` | `console` is easy to read. `json` is for log tools. |
| `APP_NAME`, `APP_VERSION` | `cipherforge-api`, and the project's version | Text | The service name and version that `/health` reports. The version is also in the start-up log line. Neither is in `.env.example`, and you normally leave them out. |

**Authentication**

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `AUTH_MODE` | `entra` (the template sets `dev`) | `dev`, `entra` | `dev`: no sign-in, and everyone is a local developer. `entra`: the API checks Microsoft Entra ID sign-in tokens and needs both IDs below. `dev` is refused when `ENVIRONMENT=production`. The dashboard cannot sign in yet, so it needs `dev` (see [Limitations](../README.md#limitations)). |
| `DEV_AUTH_ROLES` | `SecurityAnalyst` | A comma-separated list of `Admin`, `SecurityAnalyst` and `User` | The roles the local developer has in `dev` mode. Threat-intelligence lookups and network monitoring need `SecurityAnalyst` or `Admin`. Encrypted file sharing accepts all three. |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` | Empty | A GUID | Identify your Microsoft Entra ID tenant and app. Both are required when `AUTH_MODE=entra`. |
| `ENTRA_AUDIENCE` | The value of `ENTRA_CLIENT_ID` | Text | The audience a sign-in token must carry. A blank value counts as not set. |

**Database**

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `DATABASE_URL` | None: the API will not start without it. The template points at a local PostgreSQL. | `postgresql+psycopg://user:password@host:5432/name` or `sqlite+pysqlite:///./cipherforge.db` | Where the data is kept. SQLite is for trying things out. PostgreSQL is for real use, and `ENVIRONMENT=production` requires it. If the password has symbols, URL-encode them (`@` becomes `%40`). A relative SQLite path is read from the folder you run the command in. Docker ignores this setting and builds its own from the `POSTGRES_*` settings. |

**Browser access (CORS)**

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `CORS_ORIGINS` | Empty | A comma-separated list of web addresses (origins), such as `https://dashboard.example.com`. `*` is refused. | Other web addresses that may call the API from a browser. A trailing `/` is removed. Leave it empty when the dashboard reaches the API through its own web server, as Vite and nginx both do. |

**Threat-intelligence providers**

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `THREATFOX_API_KEY` | Empty: the provider is off and shows **Not configured** | Text without spaces or control characters, ASCII only | The provider keys. Spaces around a key are removed. The keys are never written to the logs or sent to the browser. See [Add your API keys](#add-your-api-keys-optional). |
| `ABUSEIPDB_CACHE_TTL_SECONDS` | `21600` (6 hours) | 60 to 2592000 (30 days) | How long a saved AbuseIPDB answer counts as fresh, in seconds. |
| `OTX_CACHE_TTL_SECONDS` | `43200` (12 hours) | 60 to 2592000 | The same for AlienVault OTX. |
| `VIRUSTOTAL_CACHE_TTL_SECONDS` | `86400` (24 hours) | 60 to 2592000 | The same for VirusTotal. |
| `THREATFOX_CACHE_TTL_SECONDS` | `21600` (6 hours) | 60 to 2592000 | The same for ThreatFox. |
| `PROVIDER_TIMEOUT_SECONDS` | `10` | 1 to 30 | How many seconds to wait for AbuseIPDB or OTX before giving up on it. |
| `VIRUSTOTAL_TIMEOUT_SECONDS`, `THREATFOX_TIMEOUT_SECONDS` | `15` | 1 to 30 | How many seconds one lookup may take in total, retries included. |
| `VIRUSTOTAL_MAX_RETRIES`, `THREATFOX_MAX_RETRIES` | `2` | 0 to 5 | How many times to retry after a timeout, a connection failure, an HTTP 502, 503 or 504 answer, or a 429 that asks for a wait of 10 seconds or less. A rejected key (401, 403) or a rejected request (400, 422) is never retried. |
| `VIRUSTOTAL_BASE_URL` | `https://www.virustotal.com/api/v3` | An `https` address, with no user name, password, query or fragment. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`. | The provider's address. Change it only to point at a test server. A trailing `/` is removed. |
| `THREATFOX_BASE_URL` | `https://threatfox-api.abuse.ch/api/v1` | The same rules | The same for ThreatFox. |
| `INVESTIGATE_RATE_LIMIT_PER_MINUTE` | `30` | 1 to 600 | One limit per signed-in user and minute, shared by investigations, capture-file uploads, alert look-ups and interface-list refreshes. Each API process counts in memory, so a restart resets the count. The file-sharing limits are in the **Encrypted file sharing** table below. All limits are listed in [Rate limits](api.md#rate-limits). |

**Time zone** (more in [Time zone](#time-zone))

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `APP_TIMEZONE` | `Asia/Kolkata` | `Asia/Kolkata`, the only value accepted | Names the zone in which times are shown to people. Any other value stops the API from starting. |

**Network monitoring** (the full story is in [network-monitoring.md](network-monitoring.md))

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `EXTERNAL_ENRICHMENT_ENABLED` | `true` | `true` or `false` | Whether public IP addresses seen in traffic are looked up with the configured providers. Private, loopback, link-local, multicast, reserved and unspecified addresses are never sent. When it is `false`, nothing is sent, and asking for an alert to be looked up fails with `enrichment_disabled` (HTTP 409, "External enrichment is switched off on this server."). |
| `NETWORK_RETENTION_HOURS` | `72` | 1 to 2160 | How many hours flows and alerts are kept before they are deleted. |
| `MAX_ACTIVE_FLOWS` | `10000` | 100 to 1000000 | The most flows tracked at once. This is an upper bound on memory use. |
| `MONITORING_BUFFER_SIZE` | `10000` | 100 to 1000000 | The most packets waiting to be processed. When the buffer is full, new packets are dropped and counted instead of growing memory. |
| `NETWORK_MAX_PCAP_SIZE_MB` | `50` | 1 to 500 | The largest PCAP or PCAPNG file accepted for offline analysis, in MB. |
| `NETWORK_ENRICHMENT_MAX_IPS` | `25` | 1 to 200 | How many public addresses are looked up per monitoring session. |
| `NETWORK_ENRICHMENT_MAX_PER_MINUTE` | `4` | 1 to 60 | How many lookups start per minute. The default stays inside the free VirusTotal quota of 4 requests per minute. Raise it only if your keys allow more. |
| `FLOW_IDLE_TIMEOUT_SECONDS` | `60` | 5 to 3600 | How many seconds without packets before a flow is closed and stored. |
| `NETWORK_MAX_STORED_FLOWS` | `20000` | 100 to 1000000 | How many flow rows are kept per session. Beyond that, the oldest are dropped first. |
| `KNOWN_MALICIOUS_MIN_SCORE` | `61` | 1 to 100 | A public address whose CipherForge risk score is at least this raises a known-malicious-address alert (rule NET-005). 61 is the start of the "high" band. |

**Detection thresholds.** These are development starting points, not security standards. Tune them to
the network you monitor. What each rule does is in [detection-engine.md](detection-engine.md), and
[Thresholds and settings](detection-engine.md#thresholds-and-settings) explains how to choose them.

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `PORT_SCAN_THRESHOLD` | `20` | 2 to 65535 | NET-001 port scan: one source contacts at least this many different destination ports within the window. |
| `PORT_SCAN_WINDOW_SECONDS` | `60` | 1 to 3600 | The window for NET-001. |
| `CONNECTION_RATE_THRESHOLD` | `100` | 2 to 1000000 | NET-002 connection rate: one source opens at least this many new flows within the window. |
| `CONNECTION_RATE_WINDOW_SECONDS` | `60` | 1 to 3600 | The window for NET-002. |
| `SYN_RATE_THRESHOLD` | `200` | 2 to 10000000 | NET-003 SYN rate: one source sends at least this many TCP SYN packets (without ACK) within the window. |
| `SYN_RATE_WINDOW_SECONDS` | `10` | 1 to 3600 | The window for NET-003. |
| `SUSPICIOUS_PORT_THRESHOLD` | `25` | 2 to 1000000 | NET-006 suspicious port: one source attempts at least this many connections to the ports in `SUSPICIOUS_PORTS` within the window. |
| `SUSPICIOUS_PORT_WINDOW_SECONDS` | `60` | 1 to 3600 | The window for NET-006. |
| `SUSPICIOUS_PORTS` | `23,135,139,445,1433,3389,4444,5900,6667,31337` | A comma-separated list of port numbers, each 1 to 65535 | The ports NET-006 watches. The list is sorted and duplicates are removed. |
| `HIGH_VOLUME_THRESHOLD_MB` | `50` | 1 to 1000000 | NET-004 high volume: one source sends at least this many megabytes within the window. |
| `HIGH_VOLUME_WINDOW_SECONDS` | `60` | 1 to 3600 | The window for NET-004. |
| `EXPECTED_PROTOCOLS` | `tcp,udp,icmp,icmpv6,igmp` | A comma-separated list of protocol names: letters, digits and hyphens, up to 16 characters each (capitals become lower case) | Protocols that raise no NET-007 "unexpected protocol" alert. |

**Encrypted file sharing** (more in [file-sharing.md](file-sharing.md#turning-it-on))

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `CIPHERFORGE_MASTER_KEY` | Empty: file sharing is off | 32 random bytes written as base64url text: 44 characters ending in `=` (the `=` may be left off). See [Generate the master key](#generate-the-master-key-for-file-sharing). | The key behind file sharing. One key does all of these jobs, and it is not split into separate keys: it wraps every file's own key, it is part of the key of every password-protected link, and the fingerprint stored with each file (which detects a wrong key) is computed with it. See [The master key](encryption-design.md#the-master-key). A blank value leaves file sharing off. A malformed value stops the API from starting. |
| `ENCRYPTED_FILE_STORAGE_PATH` | `data/encrypted-files` | A folder path. A relative path is read from the `backend` folder. | Where encrypted files are written. A blank value means the default. Docker ignores this setting and always uses the `encrypted_files` volume. |
| `MAX_ENCRYPTED_FILE_SIZE_MB` | `25` | 1 to 100 | The largest upload, in MB. The file is encrypted in memory, so keep this modest. |
| `DEFAULT_SHARE_EXPIRY_HOURS` | `24` | 1 to 8760, and not more than `MAX_SHARE_EXPIRY_HOURS` | How many hours a new share link stays valid by default. If it is larger than `MAX_SHARE_EXPIRY_HOURS` the API does not start: the error says `DEFAULT_SHARE_EXPIRY_HOURS must not exceed MAX_SHARE_EXPIRY_HOURS`. So if you set the maximum below 24, set the default lower too. |
| `MAX_SHARE_EXPIRY_HOURS` | `720` | 1 to 8760, and not less than `DEFAULT_SHARE_EXPIRY_HOURS` | The longest lifetime a user may choose for a link. |
| `MAX_SHARE_DOWNLOADS` | `100` | 1 to 10000 | The most downloads a user may allow for one share link. |
| `FILE_UPLOAD_RATE_LIMIT_PER_MINUTE` | `10` | 1 to 600 | Uploads per minute, for each signed-in user. |
| `SHARE_CREATE_RATE_LIMIT_PER_MINUTE` | `10` | 1 to 600 | New share links per minute, for each signed-in user. |
| `SHARE_DOWNLOAD_RATE_LIMIT_PER_MINUTE` | `30` | 1 to 600 | Link requests per minute, for each client network (IPv6 clients are counted by their /64). |
| `SHARE_PASSWORD_ATTEMPT_LIMIT` | `5` | 1 to 100 | How many wrong passwords one share link accepts in 15 minutes before it refuses further attempts. |

The rate limits are counted in memory by each API process, so a restart resets them. Run one API
process.

**Docker only** (see [Path C](#path-c-run-everything-in-docker))

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `POSTGRES_USER` | `cipherforge` | A PostgreSQL user name | The database user. Compose builds `DATABASE_URL` from `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`. |
| `POSTGRES_PASSWORD` | None: Compose stops with "Set POSTGRES_PASSWORD in .env". The template has `CHANGE_ME_local_only`, which you should change. | Letters and digits only, because it is placed inside a web address | The database password. PostgreSQL stores it when it first creates its data, so set it before the first start. |
| `POSTGRES_DB` | `cipherforge` | A database name | The name of the database. |
| `FRONTEND_PORT`, `BACKEND_PORT`, `POSTGRES_PORT` | `3000`, `8000`, `5432` | A free port number | The ports on your computer. All three are published on `127.0.0.1` only. |
| `FORWARDED_ALLOW_IPS` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` (the line is commented out in the template) | A comma-separated list of addresses or networks | Which senders the API trusts to say where a request really came from (the `X-Forwarded-For` header). That address goes into the audit log. Uvicorn, the web server, reads it from the environment, so it is not one of the application's own settings. |

**Demo and dashboard development only** (not read by the real API, and not in `.env.example`)

| Variable | Default | Valid values | What it does |
| --- | --- | --- | --- |
| `CIPHERFORGE_DEMO_RESET` | Not set | `1` | Set it for one start to rebuild the demo's invented data. |
| `CIPHERFORGE_DEMO_DB` | `demo.db` | A `.db` file directly inside `backend/.demo/` | Use another demo database. |
| `CIPHERFORGE_DEMO_ROLES` | `SecurityAnalyst` | The same comma-separated roles as `DEV_AUTH_ROLES` | The roles of the demo's user. |
| `VITE_DEV_PROXY_TARGET` | `http://127.0.0.1:8000` | A web address | Where the dashboard's development server sends API requests. Set it in the terminal that runs `npm run dev`, not in `.env`. |

How the settings reach the containers is in [Configuration](deployment.md#configuration), and what to
change before the stack faces a network is in
[Before exposing it beyond your machine](deployment.md#before-exposing-it-beyond-your-machine).

## Generate the master key for file sharing

Encrypted file sharing stays off until the server has a **master key**: 32 random bytes. It wraps the
key of every stored file and is also part of the key that protects a password-protected link. One key
does these jobs; it is not split into separate keys (see
[The master key](encryption-design.md#the-master-key)). You make it yourself, once. If you will not
share files, skip this section, because nothing else in CipherForge uses the key. How the feature
works is in [file-sharing.md](file-sharing.md#turning-it-on).

**Step 1. Make the key.** Run one command from the `backend` folder. It uses the virtual environment
from [Path B](#path-b-run-the-real-application), and it needs no extra package.

Windows (PowerShell):

```powershell
.\.venv\Scripts\python.exe -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

macOS or Linux:

```bash
.venv/bin/python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

It prints one line of 44 characters that ends in `=`. That line is the key. Every run prints a new
one, so copy the one you got.

**Step 2. Put it in `.env`.** Open `.env` in the project folder and paste the key after the `=`:

```text
CIPHERFORGE_MASTER_KEY=<paste the generated key here>
```

Type it as printed, with no spaces and no quotes. Then stop the API (`Ctrl+C`) and start it again.
With Docker, put the key in the same `.env` file and run `docker compose up` again: Compose passes it
to the `backend` container only.

**Step 3. Check it.** Open <http://127.0.0.1:8000/api/v1/files/status> in your browser. (With the
template's `AUTH_MODE=dev` no sign-in is needed.) The answer contains `"configured":true`, followed by
the size, expiry and download limits. While it says `false`, the Files screen shows "Encrypted files
are not set up on this server" instead of the upload form.

**What the API does with the value**

| What is in `CIPHERFORGE_MASTER_KEY` | What happens |
| --- | --- |
| Nothing: the line is blank or missing | The API starts and file sharing is off. Requests answer `503 feature_not_configured` ("Encrypted file sharing is not configured on this server."). |
| Not 32 bytes of base64url text. That includes a key that is too short or too long, a hex string, and ordinary base64 with `+` or `/` in it | The API does not start. The last line of the error is `ConfigurationError: Invalid configuration - CIPHERFORGE_MASTER_KEY: must be 32 random bytes encoded as base64url`. The key itself is never printed. |
| 32 bytes, but with too few different values, such as one repeated character | The API does not start: `... CIPHERFORGE_MASTER_KEY: does not look random; generate a new key`. |
| A valid key that is not the one that encrypted the files already stored | The API starts. Those files answer `503 encryption_key_mismatch` ("The server's encryption key does not match the stored data."). Nothing is changed or marked damaged, and putting the original key back fixes it. |

**Keep the key safe**

- **Never commit it and never share it.** Git ignores `.env`, but a key pasted into a chat, a ticket
  or a screenshot is out of your hands.
- **Back it up, away from the server.** Files cannot be recovered without it. A backup of the
  encrypted files only helps when the key that encrypted them is backed up with it: see
  [Storage and cleanup](file-sharing.md#storage-and-cleanup).
- **In production, use a managed secret store** (for example Azure Key Vault) and give the API the key
  as the environment variable `CIPHERFORGE_MASTER_KEY`, instead of a file. See
  [Before exposing it beyond your machine](deployment.md#before-exposing-it-beyond-your-machine).
- **There is no key rotation yet.** Nothing re-encrypts stored files under a new key. If you change
  the key, files made under the old one stay unreadable until the old key is back.

## Live capture prerequisites (optional)

Network monitoring works in two ways, and only one of them needs anything extra.

- **Analysing a saved capture file** (`.pcap`, `.pcapng` or `.cap`) needs no driver and no special
  privileges. It works in all three paths. If that is all you want, skip this section.
- **Capturing live traffic** needs three things on the computer that runs the API:
  - **A packet-capture driver.** On Windows this is **Npcap**. On Linux it is **libpcap**, or
    Scapy's own raw packet sockets, which need no extra package. [Requirements](network-monitoring.md#requirements)
    and [Privileges](network-monitoring.md#privileges) say on which systems live capture has been run
    and on which it has not.
  - **Enough privileges** for the account that starts the API to open a network interface. What is
    enough depends on the system and, on Windows, on how Npcap was installed.
  - **Scapy**, the Python package that does the capturing. It is in `requirements.txt`, so the
    install in [Path B](#path-b-run-the-real-application) already covers it.

What each system needs, and what the API reports when it looks for a driver:

| System | Driver | What the API reports | Privileges |
| --- | --- | --- | --- |
| Windows | **Npcap**, from the Npcap project: <https://npcap.com/#download>. The installer's "WinPcap API-compatible Mode" is not needed. | `npcap`. A WinPcap-compatible driver that is not Npcap shows as `winpcap`: capture is tried, but that combination was not tried. No capture driver, or no Scapy, shows as `none`: live capture is off and the code is `capture_backend_missing`. | A normal user account is enough, unless the Npcap installer's option **Restrict Npcap driver's access to Administrators only** was selected: then start the API from an elevated terminal ("Run as administrator"). A non-elevated API process captured through Npcap on the author's computer. |
| Linux | **libpcap** (for example the `libpcap-dev` package), or nothing: Scapy's own raw packet sockets work without it. | `libpcap` when Scapy uses it, otherwise `native` (raw packet sockets). Both can capture. | Permission to open packet sockets: run the API as root, or give the process the `CAP_NET_RAW` capability. A narrow capability on a dedicated account is safer than root. |
| macOS and others | Not tested. | | |

Live capture was run against a real interface on Windows only. The Linux paths are covered by unit
tests that fake the platform and the sniffer, not by a live run. If the operating system refuses
access, the session ends as `capture_permission_denied` and nothing is captured.

The API looks for a driver once, the first time anything asks (opening the Network screen does), and
keeps the answer until it stops. **Restart the API after you install or change a driver.** To see what
it found, open <http://127.0.0.1:8000/api/v1/network/status> (with the template's `AUTH_MODE=dev` no
sign-in is needed). `backend.name` is `npcap`, `winpcap`, `libpcap`, `native` or `none`, and
`backend.available` says whether live capture can be tried. The Network screen shows the same.

The installation steps and the privilege details are in
[network-monitoring.md](network-monitoring.md#requirements):
[Installing Npcap on Windows](network-monitoring.md#installing-npcap-on-windows),
[Installing libpcap on Linux](network-monitoring.md#installing-libpcap-on-linux) and
[Privileges](network-monitoring.md#privileges). Problems with capture are in the **Network
monitoring and capture files** group of [Common setup problems](#common-setup-problems).

Two setups differ. The API container in [Path C](#path-c-run-everything-in-docker) has every
privilege removed, so it cannot capture live traffic, although it still analyses saved files (see
[Docker](network-monitoring.md#docker)). The offline demo in
[Path A](#path-a-try-it-without-api-keys) replaces the driver with a simulation: its interfaces are
named "Simulated office LAN" and "Simulated quiet link", and nothing is captured from your computer.
For real live capture, run the API on your computer as in Path B.

## Time zone

CipherForge stores and sends every time as UTC, and shows people India Standard Time, written as
`DD-MM-YYYY hh:mm:ss A IST` (for example `25-11-2026 09:49:00 AM IST`). `APP_TIMEZONE` names that
zone. It accepts only `Asia/Kolkata`, and any other value stops the API from starting. The zone data
comes from the `tzdata` package, which `requirements.txt` installs, because Windows has no time-zone
database of its own. Without it the API stops at start-up with a message that names the package: see
[Common setup problems](#common-setup-problems). The rule and its reasons are in
[Time handling](architecture.md#time-handling-utc-storage-ist-display).

## Common setup problems

Find what you see in the left column. Commands are for Windows PowerShell, with the macOS and Linux
version where it differs. If your problem is not here, read the last lines in Terminal 1 (the API):
it prints a line for every problem and the line names the cause.

The groups follow the order in which problems appear: installing, starting, using the dashboard, then
the threat-intelligence providers, network monitoring and capture files, the database and its
migrations, and encrypted file sharing. Where the API sends an error code (`error.code`, see
[Error format](api.md#error-format)), the first column gives it in backticks with the HTTP status,
next to the title the dashboard shows in bold.

Every row gives what you see (the symptom), the likely cause and what to do. The first three groups
write the cause and the fix together in the second column. The later groups give each its own
column. The longer explanations are in the document that owns the topic, and the rows link to it. This
index points to the group that holds each problem:

| If you see | Group |
| --- | --- |
| A VirusTotal card that says **Not configured** (no API key) | [Threat-intelligence providers](#threat-intelligence-providers) |
| **Rate limited** on a provider card, for example VirusTotal | [Threat-intelligence providers](#threat-intelligence-providers) |
| A ThreatFox card with **Authentication failure**, **Timeout**, **Provider unavailable** or another error | [Threat-intelligence providers](#threat-intelligence-providers) |
| `capture_backend_missing`: Npcap is not installed (Windows), or libpcap or Scapy is missing (Linux) | [Network monitoring and capture files](#network-monitoring-and-capture-files) |
| `capture_permission_denied` | [Network monitoring and capture files](#network-monitoring-and-capture-files) |
| "No capture interfaces found" | [Network monitoring and capture files](#network-monitoring-and-capture-files) |
| `invalid_capture_file`, `capture_truncated`, `analysis_timeout` or `analysis_failed`: a capture file that cannot be read | [Network monitoring and capture files](#network-monitoring-and-capture-files) |
| `alembic upgrade head` fails, or `500 internal_error` after an update | [Database and migrations](#database-and-migrations) and [If a migration fails](#if-a-migration-fails) |
| `feature_not_configured`, or a start-up error that names `CIPHERFORGE_MASTER_KEY` (the master key is missing or invalid) | [Encrypted file sharing](#encrypted-file-sharing) |
| `500 internal_error` when you upload a file or create a link (the encryption or the record failed) | [Encrypted file sharing](#encrypted-file-sharing) |
| `file_unavailable`: the file failed its authentication-tag (integrity) check | [Encrypted file sharing](#encrypted-file-sharing) |
| `share_expired`, `share_revoked` or `share_limit_reached` | [Encrypted file sharing](#encrypted-file-sharing) |

### While installing

| What you see | What to do |
| --- | --- |
| `npm.ps1 cannot be loaded because running scripts is disabled on this system` | Windows blocks script files by default. Type `npm.cmd` instead of `npm`, and `npx.cmd` instead of `npx`. This guide already does. |
| `python` is "not recognized", or it opens the Microsoft Store | Python is not installed, or Windows cannot find it. Install Python 3.12 or newer from <https://www.python.org/downloads/> and tick **Add python.exe to PATH**. Close the terminal and open a new one. |
| `pip install` stops with an error | Check `python --version`. It must say 3.12 or higher. If you installed a newer Python after creating `backend/.venv`, delete that folder (`Remove-Item -Recurse -Force .venv`) and create it again. |
| A warning that mentions `EBADENGINE` when you run `npm ci` | Your Node.js is older than 22.22. Install a newer one from <https://nodejs.org/en/download>. |
| `ModuleNotFoundError: No module named 'app'` (or `'devtools'`) | You are in the wrong folder. Run the Python commands from the `backend` folder. |

### While starting

| What you see | What to do |
| --- | --- |
| `Error: Port 5173 is already in use` (dashboard), or `[Errno 10048] ... only one usage of each socket address` (API) | Something already uses that port, often an earlier CipherForge that is still running. Paths A and B both use port 8000, so run only one at a time. Stop the old one, or [use another port](#free-a-port-or-use-another-one). |
| Red text with `NativeCommandError` after `alembic upgrade head` | Harmless in Windows PowerShell 5.1: it paints normal messages red. If the last lines say `Running upgrade ...`, it worked. |
| A long `Traceback` that ends with `ConfigurationError: Invalid configuration - NAME: ...` | A setting in `.env` is wrong. `NAME` is the setting, or `SETTINGS` when the problem is a combination of settings; the message after it says which (for example `DEFAULT_SHARE_EXPIRY_HOURS must not exceed MAX_SHARE_EXPIRY_HOURS`). Fix it using the [Environment variables](#environment-variables) tables and start again. |
| The last line is `ConfigurationError: Invalid configuration - DATABASE_URL: Field required` | `DATABASE_URL` has no default, so the API cannot start without it. Either there is no `.env`, it is not in the project folder (the one with `docker-compose.yml`, not `backend`), or it has no `DATABASE_URL=` line. Create `.env` as in Step 1 of [Path B](#path-b-run-the-real-application), choose a database in Step 2, and start again. |
| The last line is `RuntimeError: The Asia/Kolkata time zone is not available. Install the 'tzdata' package ...` | Windows has no system time-zone database, so the API reads it from the `tzdata` Python package, which is missing from this virtual environment. Install it with `.\.venv\Scripts\python.exe -m pip install tzdata` (macOS or Linux: `.venv/bin/python -m pip install tzdata`), or repeat the install command in Step 3 of [Path B](#path-b-run-the-real-application). See [Time zone](#time-zone). |
| The API starts, but your data is gone, or the tables are missing | You ran `alembic` and `uvicorn` from different folders, so each used its own SQLite file. Run both from the `backend` folder. If your data is there but one screen fails after you updated the project, you probably skipped `alembic upgrade head`: see [Database setup and migrations](#database-setup-and-migrations). |
| Docker says it cannot connect to the daemon, or that `docker` is not found | Docker Desktop is not installed or not running. Start it and wait until it says it is running. |
| Docker says a port is already allocated | Another program uses port 3000, 8000 or 5432. Change `FRONTEND_PORT`, `BACKEND_PORT` or `POSTGRES_PORT` in `.env`. |

### While using the dashboard

| What you see | What it means and what to do |
| --- | --- |
| **API OFFLINE** in the top bar, or **Could not reach the API** | The dashboard cannot talk to the API. Is Terminal 1 still running? Does <http://127.0.0.1:8000/health> answer? If the API uses another port, see [below](#free-a-port-or-use-another-one). |
| **The request timed out** | The API or a provider was slow. Try again in a moment. |
| **Not signed in** | The API wants a sign-in, and the dashboard cannot sign in yet. Put `AUTH_MODE=dev` and `ENVIRONMENT=development` in `.env`, then restart the API. |
| **Access denied**. On the Network page the title is **Security analyst role needed**, on the Files page the text is "Your account is not allowed to do this." (HTTP 403) | The signed-in role is not allowed to do this. Threat-intelligence and network monitoring need the `SecurityAnalyst` or `Admin` role, and file sharing accepts `User`, `SecurityAnalyst` or `Admin`. In development mode the role comes from `DEV_AUTH_ROLES`, which defaults to `SecurityAnalyst`: set `DEV_AUTH_ROLES=SecurityAnalyst` in `.env`, then restart the API. The roles are described in [Roles](api.md#roles). |
| **That request was not accepted** (HTTP 422) | CipherForge refused the indicator, for example a private address, or a SHA-512 hash (MD5, SHA-1 and SHA-256 are accepted). The line under the title says why. See [What you can type](user-guide.md#what-you-can-type). |
| **Rate limit reached** (HTTP 429 `rate_limited`). The Network and Files pages say **Too many requests** | You went over a per-user limit. Investigations, capture-file uploads, alert look-ups and interface-list refreshes share one limit, `INVESTIGATE_RATE_LIMIT_PER_MINUTE` (30 a minute unless you changed it). File uploads and share creation have their own limits. Wait for the number of seconds the notice shows. All limits are in [Rate limits](api.md#rate-limits). |
| **The API reported an error** (any HTTP status of 500 or above, for example `500 internal_error`) | The API had a problem. Try again shortly. If it keeps happening, read Terminal 1, and quote the **Reference** shown at the bottom of the notice. It appears as `correlation_id` in the API's log lines for that request. If it began right after you updated the project, the database may be missing a migration: see the **Database and migrations** group below. |
| The delete box stays open and shows a red notice | The deletion did not happen, so nothing was deleted. The causes are the ones in the rows above (the API is offline, a time-out, or a role that is not allowed). Fix the cause and press the red button again, or press **Cancel**. |
| **Unexpected response from the API** | The dashboard and the API are different versions. Update both to the same version. |
| The **System status** screen says the database is **Unavailable** (or `/ready` answers `503` with `"database":"unavailable"`) | The API cannot reach its database. `/ready` only checks that a trivial query runs, so it does not tell you whether the tables exist. For Path B, check that `DATABASE_URL` points at your SQLite file and that the folder that file is in exists. For Docker, check that the `postgres` container is running (`docker compose ps`). A database that is reachable but missing a migration shows up as errors on other screens: see the **Database and migrations** group below. |
| Every result says **Not configured** or **Not assessed**, or a provider card says **Rate limited**, **Error** or **Not supported** | These come from the providers, not from the dashboard. Find the status in the **Threat-intelligence providers** group below. |
| The Overview says **Nothing here yet** | Normal on a new installation. Investigate something and it fills in. |

### Threat-intelligence providers

Each provider card on an investigation shows a status. A failed lookup also shows a reason badge and a
sentence from the server. **Not assessed** and **No data** mean that no provider gave a verdict. They
never mean "safe". How the providers are used is described in
[Threat intelligence](threat-intelligence.md).

| What you see | Likely cause | What to do |
| --- | --- | --- |
| Every result says **Not assessed**. On the Overview, the **Intelligence providers** panel says "No threat-intelligence provider is configured" | No provider has an API key, so none was asked. | Add at least one key ([Add your API keys](#add-your-api-keys-optional)), restart the API, and investigate again. |
| A **VirusTotal** card says **Not configured**: "VirusTotal is not configured (no API key set)." | `VIRUSTOTAL_API_KEY` is empty or missing, or you set it but did not restart the API. Without a key CipherForge makes no request to VirusTotal. | Put your key after `VIRUSTOTAL_API_KEY=` in `.env`, save the file, and restart the API (Docker: press `Ctrl+C` in the terminal, then run `docker compose up` again). Then investigate again. |
| The API stops at start-up and the last line is `ConfigurationError: Invalid configuration - VIRUSTOTAL_API_KEY: must not contain whitespace or control characters`. The same line can name `ABUSEIPDB_API_KEY`, `OTX_API_KEY` or `THREATFOX_API_KEY`. | The key contains a space, a line break or another character that cannot be part of a key. Spaces at the very start or end are removed, but a space inside the key is not. | Copy the key again, on one line, with nothing around it. An empty value is allowed and means "not configured". |
| A card says **Rate limited**: "VirusTotal rate limit reached; try again in about 30 seconds." or "VirusTotal rate limit reached; try again later." | The provider's quota is used up. `.env.example` says the free VirusTotal key allows 4 requests per minute and 500 per day. | Wait, then press **Retry VirusTotal** on the card. CipherForge itself retries only when the provider asks for a wait of 10 seconds or less, at most `VIRUSTOTAL_MAX_RETRIES` times (default 2). Leave "Ask the providers again, even if a stored answer is recent" unticked: answers are kept for `VIRUSTOTAL_CACHE_TTL_SECONDS` (default 86400), and a forced refresh spends quota and is ignored for an answer that is less than a minute old. Network monitoring asks the providers too: lower `NETWORK_ENRICHMENT_MAX_PER_MINUTE` (default 4) or `NETWORK_ENRICHMENT_MAX_IPS` (default 25), or set `EXTERNAL_ENRICHMENT_ENABLED=false`. |
| A **ThreatFox** card says **Error** with the badge **Authentication failure**: "ThreatFox rejected the configured credentials." There is no Retry button. | ThreatFox did not accept the key in `THREATFOX_API_KEY`. It answered with HTTP 401 or 403, or with a status that says the request is unauthorised or forbidden. CipherForge never retries this. | Get an Auth-Key from abuse.ch at <https://auth.abuse.ch/>, set `THREATFOX_API_KEY` in `.env`, restart the API, and investigate again. A failed lookup is not stored, so the next investigation asks ThreatFox again. The other providers show the same sentence, with their own name, when they refuse their key. |
| A card says **Error** with the badge **Timeout** or **Provider unavailable**: "ThreatFox did not respond in time.", "Could not reach ThreatFox." or "ThreatFox returned an unexpected HTTP status (503)." | The provider was slow or down, this computer cannot reach it (no internet, or a proxy or firewall in the way), or the provider reported a temporary failure. | Check that this computer can reach the provider's site, then press the **Retry** button on the card (for example **Retry ThreatFox**). VirusTotal and ThreatFox are retried automatically after a time-out, a connection failure, or HTTP 502, 503 or 504, up to `VIRUSTOTAL_MAX_RETRIES` or `THREATFOX_MAX_RETRIES` times (default 2). AbuseIPDB and AlienVault OTX are not retried automatically. If a provider is only slow, raise its time-out: `PROVIDER_TIMEOUT_SECONDS` (AbuseIPDB and OTX), `VIRUSTOTAL_TIMEOUT_SECONDS` or `THREATFOX_TIMEOUT_SECONDS`, each from 1 to 30 seconds. |
| A card says **Error** with the badge **Malformed response**: "ThreatFox returned invalid JSON.", "Unexpected response format from ThreatFox." or "ThreatFox response was too large to process." | CipherForge could not read what came back. It may not have come from the provider (for example a page from a proxy), or the provider changed its format. | Press the **Retry** button on the card. If it keeps happening, look for a proxy between this computer and the provider. If there is none, the provider may have changed its format. The other providers are not affected: a bad answer from one provider affects only that provider's card. |
| A card says **Error** with the badge **Invalid input**: "ThreatFox rejected the search term as invalid." or "VirusTotal rejected the request as invalid (400)." | The provider did not accept this indicator, although CipherForge did. Asking again gives the same answer, so there is no Retry button. | Check the indicator for typing mistakes and investigate the corrected value. |
| A card says **Not supported**: for example "ThreatFox does not accept sha1 indicators." | This provider does not handle this type of indicator. That is normal, not a failure. | Nothing to fix. The table in [Add your API keys](#add-your-api-keys-optional) shows what each provider handles. |

### Network monitoring and capture files

Live capture needs a packet-capture driver and enough privileges on the computer that runs the API.
Analysing a saved capture file needs neither, so uploading a file is also a quick way to see whether
the module itself works (see
[Trying it without a real capture](network-monitoring.md#trying-it-without-a-real-capture)). The
install steps and the privilege details are in [Requirements](network-monitoring.md#requirements),
not here. The API looks for a driver once, the first time it needs one, and remembers the answer, so
**restart the API after you install a driver**. A title in bold is what the dashboard shows. Text in
quotes is the API's own message, which you see when you call the API directly. The codes are explained
in [When something goes wrong](network-monitoring.md#when-something-goes-wrong), and the request
errors are listed with their HTTP status in [Error codes](api.md#error-codes).

| What you see | Likely cause | What to do |
| --- | --- | --- |
| The **Live capture** panel says **Live capture is not available** ("No packet-capture library was detected on the server..."), **Capture backend** says **Not available**, and **Start capture** is disabled. A start request sent to the API is refused with HTTP 503 `capture_backend_missing`: "No packet-capture driver was found. Install Npcap (Windows) or libpcap (Linux), then restart the API." | On Windows the capture driver is Npcap. It is not installed on the computer that runs the API, or you installed it after the API started. | Install it by following [Installing Npcap on Windows](network-monitoring.md#installing-npcap-on-windows), then restart the API. The "WinPcap API-compatible Mode" option of the installer is not needed. If Npcap is already installed and the notice stays, check that Scapy is installed, as in the next row (on Windows: `.\.venv\Scripts\python.exe -m pip show scapy`). Analysing a saved capture file does not need Npcap. |
| The same **Live capture is not available** notice, or HTTP 503 `capture_backend_missing`, on Linux. | libpcap is optional on Linux, because Scapy can capture with raw packet sockets instead, so a missing libpcap alone does not cause this. Scapy, the Python package that captures, may be missing from the API's virtual environment. Or a capture failed with an error that mentions libpcap, which the API reports as a missing driver. | In `backend`, run `.venv/bin/python -m pip show scapy`. If pip says the package was not found, repeat the install command in Step 3 of [Path B](#path-b-run-the-real-application). To use libpcap, follow [Installing libpcap on Linux](network-monitoring.md#installing-libpcap-on-linux). Restart the API: **Capture backend** then says **Available**. |
| You run CipherForge in Docker ([Path C](#path-c-run-everything-in-docker)) and live capture does not work, although uploading a capture file does. | By design. The API container runs with all Linux capabilities dropped and a read-only file system, so it lacks the raw-socket privileges that live capture needs. | Run the API on your computer as in [Path B](#path-b-run-the-real-application) when you want live capture. See [Docker](network-monitoring.md#docker). Saved capture files can still be analysed in the container. |
| **Packet capture not permitted** (HTTP 503 `capture_permission_denied`): "The operating system refused packet capture to the CipherForge server process. Start the API with the privileges capture needs (see docs/network-monitoring.md)." The **Live capture** panel shows **The operating system refused packet capture**. | The account that runs the API in Terminal 1 may not capture on this system. The account you use in the browser does not matter. What is enough differs by system, and on Windows it depends on how Npcap was installed. | On Windows, if the Npcap installer's option **Restrict Npcap driver's access to Administrators only** was selected, start the API from an elevated terminal ("Run as administrator"). With that option left off, a normal user can capture. On Linux, run the API as root or give the process the `CAP_NET_RAW` capability. Then start the API again from a terminal that has the privilege, and read [Privileges](network-monitoring.md#privileges) for the detail. Use the narrowest privilege that works: that section explains why running the API as root only to capture is a risk. Analysing a saved capture file does not need any of this. |
| The interface list says **None available**, with "No capture interfaces found. Refresh the list after connecting or enabling one." **Start capture** is disabled: "There is no interface to capture on." | The API sends an empty list when the capture driver is missing or refused (**Capture backend** says **Not available**: see the rows above), when no network adapter is up, or when it could not read the list. In the last case Terminal 1 has a line `interface_listing_failed`, and its `error` field names the type of the fault. Placeholder adapters that cannot capture are left out. | Connect or enable a network adapter and press **Refresh interfaces**. The API keeps the list for 30 seconds, and refreshing reloads it but counts against a rate limit ([Rate limits](api.md#rate-limits)). If **Capture backend** says **Not available**, deal with the driver first. |
| **Interface unavailable** (HTTP 503 `interface_unavailable`): "The selected network interface is not available. It may have been disconnected or disabled." Or **Interface not found** (HTTP 404 `interface_not_found`): "That network interface was not found. Choose one from the list." | The interface you chose is no longer there: it was disconnected, disabled or removed after the list was loaded, or the driver reports it as down. | Press **Refresh interfaces**, choose an interface that is listed, and start again. |
| **Another analysis is in progress** (HTTP 409 `analysis_already_running`): "Another capture file is being analysed. Wait for it to finish." Or **A capture is already running** (HTTP 409 `capture_already_running`): "A capture is already running. Only one capture can run at a time." Or **No capture to stop** (HTTP 409 `capture_not_running`): "You have no capture running." | The application analyses one capture file at a time and runs one live capture at a time, for all users together. Only the user who started a live capture can stop it, so **No capture to stop** also appears when the running capture belongs to someone else. | Wait for the analysis to finish, then upload again. A live capture is stopped by the user who started it (**Stop capture**), and it also ends when the API is stopped. Start yours after that. |
| **Capture stopped by an error** (HTTP 503 `capture_failed`): "Packet capture stopped because of an error. The server log has the details." In the panel: **The last capture failed**. Or a session says **Session ended early** (`interrupted`): "The application stopped while this session was running, so it ended early." Or **Results may be incomplete** (`results_incomplete`): "Some results could not be stored because the database was unavailable, so the totals may be incomplete." | `capture_failed` is the catch-all for a fault that is not a missing driver, a refused permission or a missing interface. `interrupted` is set the next time the API starts, after the API process died while a session was running (a clean stop ends the capture normally). `results_incomplete`: the database could not take part of what the session recorded. | For `capture_failed`, read Terminal 1: the lines `capture_start_failed` and `capture_source_failed` have an `error` field that names the type of the fault. For `interrupted`, start a new session. For `results_incomplete`, make sure the database is reachable (the **System status** screen, and the **Database and migrations** group below), then capture or upload again. |
| **Invalid file name** (HTTP 422 `invalid_filename`): "Only .pcap, .pcapng and .cap files can be analysed." The same code has three other messages: "A capture file name is required.", "The file name is not valid UTF-8." and "The file name is not usable." | The name does not end in `.pcap`, `.pcapng` or `.cap` (capital letters are fine), is only an extension, or is missing or unreadable. The dashboard's file picker offers the same three. | Rename the file so that it ends in one of those extensions, then upload it again. Renaming changes only the name: a file that is not a capture is still refused, as **Not a readable capture file**. |
| **File too large** (HTTP 413 `file_too_large`): "The capture file is larger than the 50 MB limit." The number is your `NETWORK_MAX_PCAP_SIZE_MB`. | The file is bigger than `NETWORK_MAX_PCAP_SIZE_MB` (default 50, from 1 to 500). The size the upload announces is checked before the file is read. | Upload a smaller capture, or raise `NETWORK_MAX_PCAP_SIZE_MB` in `.env` and restart the API ([Environment variables](#environment-variables)). An analysis is stopped after 600 seconds, whatever the size of the file. |
| **Upload interrupted** (HTTP 400 `upload_interrupted`): "The request body was not received completely." Or **Upload size not valid** (HTTP 400 `invalid_content_length`): "The Content-Length header is invalid." Or **Upload type not accepted** (HTTP 415 `unsupported_media_type`): "Upload the raw capture file as application/octet-stream." | The upload stopped before the whole file arrived, or the request was not a raw upload. The dashboard builds that request itself. | In the dashboard, check the connection, reload the page and upload again. Tell an administrator if it keeps happening. If you call the API yourself, send the file as the raw body: see [Analysing a capture file](network-monitoring.md#analysing-a-capture-file). |
| **Not a readable capture file** (HTTP 422 `invalid_capture_file`): "The file is not a readable PCAP or PCAPNG capture, or it holds no complete packet." An empty upload gets the same code with "The upload is empty." No session is created. The same code can also end a session that was accepted but could not be read. | The file is not a PCAP or PCAPNG capture (a file of another kind that was renamed, for example), is empty, or holds no complete packet. | Check that the file really is a capture, or save it again from the tool that made it, and upload it again. Nothing is kept from a refused file. |
| A finished session carries the notice **Capture file cut short**: "The capture file is cut short or damaged after some point. Everything before that point was analysed." | The file ends in the middle of a packet, or is damaged after some point, for example after an interrupted copy or capture. The analysis still completes. | The totals cover only the packets before that point. Copy or capture the file again if you need the rest. |
| A session ended with **Analysis timed out**: "The analysis took too long and was stopped. The results so far are kept." | An analysis is stopped after 600 seconds. The limit is fixed: no setting changes it. | Use the results that were kept, or analyse a smaller capture. |
| **Analysis failed** (HTTP 503 `analysis_failed`, or a session that ended with that code): "The capture file could not be analysed. The server log has the details." | An unexpected fault while the file was analysed or the analysis was started. Terminal 1 then has a line `pcap_analysis_failed` or `pcap_launch_failed`, and its `error` field names the type of the fault. With no such line, Scapy, the Python package that reads capture files, may be missing. | Check that Scapy is installed: in `backend`, run `.\.venv\Scripts\python.exe -m pip show scapy` (macOS or Linux: `.venv/bin/python -m pip show scapy`). If pip says the package was not found, repeat the install command in Step 3 of [Path B](#path-b-run-the-real-application). Restart the API and upload the file again. |

### Database and migrations

The API never creates tables itself. A database that was never migrated, or that lacks the newest
migrations, shows up as errors on the screens that use the missing tables. The steps, the backup and
the five migrations are in [Database setup and migrations](#database-setup-and-migrations).

| What you see | Likely cause | What to do |
| --- | --- | --- |
| `alembic upgrade head` ends with an error instead of `Running upgrade ...` lines. In Docker, the `migrate` service exits with an error and the API never starts. | A wrong setting, a database that cannot be reached, a database made by a newer version, or a missing permission. Red text on its own is not an error: see the `NativeCommandError` row under **While starting**. | Find the error in the table under [If a migration fails](#if-a-migration-fails). On SQLite, a run that failed half-way can leave steps in place, so restore the backup you took before updating, then run it again. In Docker, `docker compose logs migrate` shows the error. |
| **The API reported an error** (HTTP 500 `internal_error`) on some screens, soon after an update, while <http://127.0.0.1:8000/ready> still says `ready`. | The code is newer than the database: a migration was not applied, so a table or column that the code needs does not exist. `/ready` only checks that the database answers a trivial query. The screens that use a missing table fail. | Stop the API and back up ([Back up before you update](#back-up-before-you-update)). In `backend`, run `alembic upgrade head`, then `alembic current`: a database that is up to date prints `0005_encrypted_files (head)`. Start the API again. In Docker, `docker compose up --build` runs the `migrate` service first. Terminal 1 names the failing request in a line `unhandled_exception`, with its path and a traceback. Some file and share routes log only the type of the database error (`error_type`) instead, because the text of a database error can contain key material. |

### Encrypted file sharing

File sharing is off until the server has a master key, and it needs a folder that the API can write to.
The key is explained in [Generate the master key for file sharing](#generate-the-master-key-for-file-sharing).
The order in which a share link is checked is in
[The checks, in order](file-sharing.md#the-checks-in-order), and the password problems
(`password_required`, `invalid_password` and `too_many_attempts`) are in
[When something goes wrong](file-sharing.md#when-something-goes-wrong). A title in bold is what the
dashboard shows, on the Files page for the owner or on the public page for a person who opens a link.
That public page never names a setting. Text in quotes right after a code is the API's message. Text in
quotes that the Files page shows or says is the dashboard's own wording, which differs from the API's.

| What you see | Likely cause | What to do |
| --- | --- | --- |
| The Files page shows **Encrypted files are not set up on this server**: "Uploading and sharing are switched off because the server has no master key." The API answers HTTP 503 `feature_not_configured`: "Encrypted file sharing is not configured on this server." `GET /api/v1/files/status` says `"configured":false`. A person who opens a link sees **Sharing is not available right now**. | `CIPHERFORGE_MASTER_KEY` is blank or missing in the environment that the API runs in, or you set it but did not restart the API. | Make a key as in [Generate the master key for file sharing](#generate-the-master-key-for-file-sharing), put it in `.env` and restart the API (Docker: press `Ctrl+C`, then run `docker compose up` again). If files were uploaded before, use their **original** key. Until the right key is set, the files you stored earlier stay in the list, but their names cannot be read. |
| The API stops at start-up, and the last line is `ConfigurationError: Invalid configuration - CIPHERFORGE_MASTER_KEY: must be 32 random bytes encoded as base64url`, or `... CIPHERFORGE_MASTER_KEY: does not look random; generate a new key`. | The value is not 32 bytes of base64url text (for example a hex string, a key that was cut short, or ordinary base64 with `+` or `/` in it), or it is 32 bytes with too few different values, such as one repeated character. The message never shows the key. | If no file was uploaded yet, generate a new key as in [Generate the master key for file sharing](#generate-the-master-key-for-file-sharing). If files already exist, fix the typo in your **original** key instead: a new key cannot open them. |
| HTTP 503 `encryption_key_mismatch`: "The server's encryption key does not match the stored data." The Files page says "The server's master key does not match the one that protects these files, so nothing was changed. An administrator must check CIPHERFORGE_MASTER_KEY." A person who opens a link sees **Sharing is not available right now**. | The API started with a valid key that is not the one that encrypted these files: the key was replaced, or a backup was restored without its key. The API still starts, and nothing is changed or marked damaged. | Put the original key back in `.env` (or your secret store) and restart the API. Do not generate a new one: files encrypted under the old key stay unreadable. If the original key is lost, those files cannot be recovered. See **Keep the key safe** in [Generate the master key for file sharing](#generate-the-master-key-for-file-sharing). |
| HTTP 503 `storage_unavailable`: "File storage is temporarily unavailable." The Files page says "The server could not reach its encrypted storage. Try again shortly." Nothing is stored. A person who opens a link sees **Sharing is not available right now**. | The API cannot create, read or write the folder for the encrypted files: the account that runs it may lack the permission, the path may be wrong, or the disk may be full. Terminal 1 has a line `blob_write_failed`, `blob_read_failed` or `blob_delete_failed` with the `file_id`. | Check `ENCRYPTED_FILE_STORAGE_PATH` (default `backend/data/encrypted-files`), its permissions and the free disk space, then try again. In Docker the folder is the `encrypted_files` volume, and `docker-compose.yml` fixes its path. See [Storage and cleanup](file-sharing.md#storage-and-cleanup). |
| The Files page refuses the file before it is sent. For example "That file is 30.2 MB, which is over the 25.0 MB limit.", "That file is empty, so there is nothing to encrypt.", "That file has no name. Rename it and try again.", "That file name is too long. Rename the file with a shorter name and try again." or "That file name contains a character that cannot be sent. Rename the file and try again." If the server refuses it, the page says "That file is larger than the 25.0 MB limit. Choose a smaller file." (HTTP 413 `file_too_large`), "That file is empty, so there is nothing to encrypt." (HTTP 422 `empty_file`) or "That file name cannot be used. Rename the file and try again." (HTTP 422 `invalid_filename`). The 25.0 MB is this server's own limit. | The file broke a rule in [Uploading a file](file-sharing.md#uploading-a-file). The size limit is `MAX_ENCRYPTED_FILE_SIZE_MB` (default 25, from 1 to 100). A reverse proxy in front of the API has a size limit of its own: if the page says a file is too large although it is under the limit, the proxy may be refusing it. The nginx in the Docker dashboard allows 500 MB on both upload routes ([The nginx front door](deployment.md#the-nginx-front-door)). | Choose a smaller file, or raise `MAX_ENCRYPTED_FILE_SIZE_MB` in `.env` and restart the API. Rename a file whose name cannot be used. |
| The Files page says "The upload did not finish, so nothing was stored. Try again." (HTTP 400 `upload_interrupted` or `invalid_content_length`), "The server refused this kind of upload. Reload the page and try again." (HTTP 415 `unsupported_media_type`), or "Too many requests. Try again in ..." (HTTP 429 `rate_limited`). | The connection dropped before the whole file arrived, or the request was not a raw upload. Uploads are also limited per user: `FILE_UPLOAD_RATE_LIMIT_PER_MINUTE` (default 10 a minute). | Check the connection and try again: nothing was stored. If the 415 keeps coming back, reload the page and tell an administrator. After a 429, wait for the time the page shows. |
| HTTP 503 `service_busy` with a `Retry-After` of 2 seconds: "The server is busy. Try again shortly." The Files page says "The server is busy encrypting other files. Try again in ...". A person who opens a link sees **The server is busy**: "Many files are being opened at once. Wait a moment and try again." | Creating or opening a password-protected link needs a slow calculation, and every slot for it stayed busy for ten seconds. Links without a password do not need it. | Wait a moment and try again. |
| HTTP 500 `internal_error` while you upload a file or create a link. The Files page says "The API reported an error. Try again shortly." The API's own message is "The request could not be completed." or "An internal error occurred." The file or link is not in the list afterwards. | The server could not finish encrypting the file or could not record the result, so nothing was kept. "The request could not be completed." means the database refused the write: Terminal 1 has a line `file_create_failed` (upload), `share_create_failed` (new link) or `share_reserve_failed` (counting a download), and its `error_type` names the kind of database error, for example a table that does not exist because a migration was not applied. An upload's encrypted copy is deleted again, so no half-stored file is left. "An internal error occurred." means any other unexpected fault, including one inside the encryption itself: Terminal 1 has `unhandled_exception` with the path of the request and a traceback. | Read Terminal 1 around the time of the request. The **Reference** at the bottom of the notice is the `correlation_id` on those log lines. If a migration is missing, run `alembic upgrade head`: see [Database setup and migrations](#database-setup-and-migrations). A file is encrypted in memory in one piece, so keep `MAX_ENCRYPTED_FILE_SIZE_MB` modest on a small server. A key problem does not look like this: a missing, malformed or wrong master key gives the first three rows of this group, and a storage problem gives `storage_unavailable`. If `blob_cleanup_failed` also appears, one encrypted copy stayed in the storage folder without a database record: see [Storage and cleanup](file-sharing.md#storage-and-cleanup). |
| HTTP 409 `file_unavailable`: "This file is no longer available." The Files page shows the notice **Integrity problem**: "This file failed its integrity check, so CipherForge will not release it and it cannot be shared. Links made for it already answer with an error. Delete it and upload the original again." A person who opens a link sees **This file could not be verified and was not released**. | The stored data did not verify. The authentication tag (the check value that proves the data was not changed) failed, the encrypted file on disk is missing or has an unexpected size, or the key stored for the file did not open. The file is quarantined for good (its status becomes `corrupt`), no download is used up, and the audit trail has a `FILE_INTEGRITY_FAILED` entry. A wrong master key does not cause this: it gives `encryption_key_mismatch`. | Delete the file and upload the original again. Restoring the encrypted file from a backup does not clear the quarantine. To see why it failed, read Terminal 1: the line `file_integrity_failed` has the `file_id` and a `reason` (`authentication_failed`, `blob_invalid` or `wrapped_key_invalid`). If you restored a backup, the database and the encrypted files must come from the same moment: see [Storage and cleanup](file-sharing.md#storage-and-cleanup) and [Integrity failures](file-sharing.md#integrity-failures). |
| HTTP 410 `share_expired`: "This link has expired." A person who opens the link sees **This link has expired**. | The time the owner chose for the link has passed. A new link lasts `DEFAULT_SHARE_EXPIRY_HOURS` (default 24) unless the owner picks another time, up to `MAX_SHARE_EXPIRY_HOURS` (default 720). The server's clock decides. | The owner creates a new link, with a longer time if needed. An expired link cannot be reopened. |
| HTTP 410 `share_revoked`: "This link has been revoked." A person who opens the link sees **This link has been revoked**. | The owner turned the link off. A link that is both revoked and expired reports `share_revoked`, because that check comes first. | The owner creates a new link if the person should still have access. |
| HTTP 410 `share_limit_reached`: "This link has reached its download limit." A person who opens the link sees **This link has reached its download limit**. | Every download the link allowed has been used. A new link allows one download unless the owner asks for more (the form starts at 1), so a link that was opened once to test it may already be used up. A download counts only after the file has been decrypted and checked, so a failed attempt does not use one up. | The owner creates a new link with a higher limit, up to `MAX_SHARE_DOWNLOADS` (default 100). |
| HTTP 404 `share_not_found`: "This link does not exist." A person who opens the link sees **This link does not work**. | The link was copied incompletely, it never existed, or its file was deleted (deleting a file removes its links). A cut-off link gets the same answer as one that never existed. | Ask the owner for the whole link, or for a new one. |

### Free a port or use another one

To **free a port** (here 8000), first look for the terminal where CipherForge is still running and press
`Ctrl+C`. If you cannot find it, find the program that holds the port and stop it.

Windows (PowerShell):

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object LocalPort, OwningProcess
Stop-Process -Id 12345    # type the OwningProcess number you saw, instead of 12345
```

macOS or Linux:

```bash
lsof -i :8000             # shows the PID
kill 12345                # type that PID, instead of 12345
```

To **use another port** instead, start the API on port 8001, and tell the dashboard where it is.

Windows (PowerShell). Terminal 1, in `backend`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --port 8001
```

Terminal 2, in `frontend`:

```powershell
$env:VITE_DEV_PROXY_TARGET = "http://127.0.0.1:8001"
npm.cmd run dev
```

macOS or Linux. Terminal 1, in `backend`:

```bash
.venv/bin/python -m uvicorn app.main:create_app --factory --port 8001
```

Terminal 2, in `frontend`:

```bash
VITE_DEV_PROXY_TARGET=http://127.0.0.1:8001 npm run dev
```

(For the demo, use `devtools.demo_server:create_demo_app` instead of `app.main:create_app`.) If the
dashboard's own port 5173 is the one in use, add `-- --port 5174` to the last command, for example
`npm.cmd run dev -- --port 5174`, and open <http://127.0.0.1:5174>.

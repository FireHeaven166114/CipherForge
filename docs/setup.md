# Setup

Full installation, configuration and troubleshooting detail for all three ways of running
CipherForge. Start with the [README](../README.md) if you have not already: it explains what the
project is and gives the fastest path to seeing it work. Come back here for prerequisites, every
setting, and what to do when something does not start.

## Prerequisites

| You need | What for | Where to get it |
| --- | --- | --- |
| **Python 3.12 or newer** | Runs the API | <https://www.python.org/downloads/>. On Windows, tick **Add python.exe to PATH** in the installer. |
| **Node.js 22.22 or newer** (24 is recommended) | Builds and serves the dashboard. It includes `npm`. | <https://nodejs.org/en/download> |
| **A web browser** | You use CipherForge in it | Any modern browser. The automated tests use Microsoft Edge. |
| **About 400 MB of free disk space** | The Python and Node packages | |

Optional:

- **Docker Desktop**, only for [Path C](#path-c-run-everything-in-docker):
  <https://www.docker.com/products/docker-desktop/>
- **Two free API keys** (AbuseIPDB and AlienVault OTX), only if you want real answers. See
  [Add your API keys](#add-your-api-keys-optional).
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
| Time | About 10 minutes | About 15 minutes | About 10 minutes, plus the first build |
| Run by the author | Yes | Yes | **No.** Docker was not available when the project was written. |

Paths A and B both use port 8000 for the API, so run only one of them at a time. The demo shows a
banner at the top of every screen ("Simulated providers: this is demo data, not real threat
intelligence"); the real application does not. That is how you can tell which one you are looking at.

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

This runs the real application in **demo mode**. Two things are different. The two providers are
**simulated** (nothing is sent to AbuseIPDB or OTX), and the database is filled with about two weeks
of invented lookups, so every screen has something to show. You need no `.env` file and no keys.

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

The first start prints about 500 lines while it creates the invented data. The API is ready when the
last lines look like this (your times and the number in brackets will differ):

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
A labelled picture of this screen is in [docs/USER-GUIDE.md](user-guide.md), along with things to try.

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
once now, and again after you update the project. On a new database it prints:

```text
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 0001_baseline, Baseline: establishes Alembic version tracking. No application tables yet.
INFO  [alembic.runtime.migration] Running upgrade 0001_baseline -> 0002_threat_intel, Threat intelligence: sources, indicators, provider observations and the audit log.
```

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
you can try every endpoint.

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
4. **Platform modules** shows what the project is made of. Threat intelligence is **LIVE**. The
   others are **PLANNED**.

**Step 6. Make your first investigation.** Click **Investigate an indicator**, click the **IPv4**
example (`8.8.8.8`) and press **Investigate**. With no keys you will see this:

![A first investigation with no API keys: the gauge says Not assessed, and both provider cards say Not configured](screenshots/first-run-no-keys.png)

1. **The gauge** says **Not assessed** instead of showing a number.
2. **The explanation** says that no provider answered, so this is not a clean result: nothing was
   checked.
3. **The first provider card** says **Not configured**: no AbuseIPDB key is set on the server.
4. **The second provider card** says the same for AlienVault OTX.

This is correct, not a bug. CipherForge cannot say anything about an indicator until at least one
provider answers.

### Add your API keys (optional)

To get real answers, add the free keys. You can add one or both.

| Provider | It handles | Get a key | Setting in `.env` |
| --- | --- | --- | --- |
| **AbuseIPDB** | IPv4 and IPv6 addresses | Create a free account at <https://www.abuseipdb.com/register> and sign in. Then open the **API** tab of your account, <https://www.abuseipdb.com/account/api> (this page shows an error until you are signed in), and create a key | `ABUSEIPDB_API_KEY` |
| **AlienVault OTX** | IP addresses, domains, URLs and SHA-256 hashes | Create a free account at <https://otx.alienvault.com>. Your key (the "OTX Key") is shown on <https://otx.alienvault.com/settings> | `OTX_API_KEY` |

1. Open `.env` and paste each key after the `=`, with no spaces and no quotes:

   ```text
   ABUSEIPDB_API_KEY=paste-your-key-here
   OTX_API_KEY=paste-your-key-here
   ```

2. Save the file. In Terminal 1 press `Ctrl+C` to stop the API, then start it again with the last
   command of Step 3 (the one with `uvicorn`). You do not need to run `alembic` again.
3. Investigate `8.8.8.8` again. A provider that now answers shows **Answered** (or **No data**)
   instead of **Not configured**.

Keep your keys private. Never paste them into a chat, a screenshot or a commit. CipherForge keeps
them on the server, never writes them to its logs and never sends them to the browser. Free accounts
have daily limits, so use the "Ask the providers again" option sparingly.

> **An honest note.** The provider code has been tested against recorded sample answers only, never
> against the live services, because the author used no keys. If a card shows **Error**, see
> [Common setup problems](#common-setup-problems).

### Path C: run everything in Docker

Docker runs the database, the API and the dashboard in containers, so you do not need to install
Python or Node. It uses PostgreSQL. This section covers the first run; [deployment.md](deployment.md)
has the full detail: every service, configuration, migrations, backups and what to do before exposing
CipherForge to a network.

> **Checked by the automatic tests, not by hand.** Docker was not available where this project was
> written, so nobody has followed these steps on a personal computer. GitHub's automatic checks do
> build both images and start the whole stack on a Linux machine, and confirm that the page and the
> API answer, so it is expected to work. Docker Desktop on Windows or macOS was not tried. If
> something fails, use Path A or B. Details:
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

- **Your data stays.** Path B keeps everything in `backend/cipherforge.db`. Path A keeps its invented
  data in `backend/.demo/demo.db`. Docker keeps the database in a Docker volume: `docker compose down`
  keeps it and `docker compose down --volumes` deletes it.
- **Start again from nothing.** Path B: stop the API and delete `backend/cipherforge.db`, then run
  `alembic upgrade head` again. Path A: set `CIPHERFORGE_DEMO_RESET=1` for one start and the demo
  rebuilds its data at once (Windows: `$env:CIPHERFORGE_DEMO_RESET = "1"`, then
  `Remove-Item Env:CIPHERFORGE_DEMO_RESET` afterwards; macOS or Linux:
  `CIPHERFORGE_DEMO_RESET=1 .venv/bin/python -m uvicorn devtools.demo_server:create_demo_app --factory`).
  To remove only some indicators, delete them in the dashboard instead:
  see [Deleting indicators](user-guide.md#deleting-indicators).

## Environment variables

CipherForge reads its settings from the `.env` file in the project folder, the one you made by copying
`.env.example`. **After you change a setting, stop the API (`Ctrl+C`) and start it again.**

- The defaults lean towards safety. If you leave out `ENVIRONMENT` and `AUTH_MODE`, you get
  `production` and `entra`, which refuse the shortcuts that are fine on your own computer.
  `.env.example` sets the relaxed values for local use.
- A wrong value stops the API from starting. The last line of the error names the setting but never
  shows its value, for example
  `ConfigurationError: Invalid configuration - PROVIDER_TIMEOUT_SECONDS: Input should be less than or equal to 30`.

**The basics**

| Setting | What it does | If you leave it out |
| --- | --- | --- |
| `ENVIRONMENT` | `development`, `test` or `production`. `production` is strict: it needs PostgreSQL, refuses `AUTH_MODE=dev`, refuses a database URL that still contains `CHANGE_ME` and switches the `/docs` page off. | `production` (the template sets `development`) |
| `LOG_LEVEL` | How much the API writes to its log: `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. | `INFO` |
| `LOG_FORMAT` | `console` is easy to read. `json` is for log tools. | `json` (the template sets `console`) |

**Who may use it**

| Setting | What it does | If you leave it out |
| --- | --- | --- |
| `AUTH_MODE` | `dev`: no sign-in, and everyone is a local developer. `entra`: the API checks Microsoft Entra ID sign-in tokens. `dev` is refused when `ENVIRONMENT=production`. The dashboard cannot sign in yet, so it needs `dev` (see [Limitations](../README.md#limitations)). | `entra` (the template sets `dev`) |
| `DEV_AUTH_ROLES` | The roles the local developer has in `dev` mode, separated by commas: `Admin`, `SecurityAnalyst` or `User`. Lookups need `SecurityAnalyst` or `Admin`. | `SecurityAnalyst` |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` | Identify your Microsoft Entra ID tenant and app. Both are required when `AUTH_MODE=entra`. | empty |
| `ENTRA_AUDIENCE` | The audience a sign-in token must carry. | The value of `ENTRA_CLIENT_ID` |

**Database and browser access**

| Setting | What it does | If you leave it out |
| --- | --- | --- |
| `DATABASE_URL` | Where the data is kept. SQLite (`sqlite+pysqlite:///./cipherforge.db`) is for trying things out. PostgreSQL (`postgresql+psycopg://user:password@host:5432/name`) is for real use. If the password has symbols, URL-encode them (`@` becomes `%40`). | The API will not start. The template points at a local PostgreSQL. |
| `CORS_ORIGINS` | Other web addresses that may call the API from a browser, separated by commas. Leave it empty when the dashboard reaches the API through its own web server, as Vite and nginx both do. `*` is refused. | Empty |

**Providers and limits**

| Setting | What it does | If you leave it out |
| --- | --- | --- |
| `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | The provider keys. A provider with no key is skipped and shown as **Not configured**. The keys are never written to the logs or sent to the browser. | Empty |
| `ABUSEIPDB_CACHE_TTL_SECONDS`, `OTX_CACHE_TTL_SECONDS` | How long a saved answer counts as fresh, in seconds: from 60 up to 30 days (2592000). | 21600 (6 hours) and 43200 (12 hours) |
| `PROVIDER_TIMEOUT_SECONDS` | How long to wait for one provider before giving up on it: 1 to 30 seconds. | 10 |
| `INVESTIGATE_RATE_LIMIT_PER_MINUTE` | How many investigations one user may start per minute: 1 to 600. Each API process counts in memory, so a restart resets the count. | 30 |

**Docker only** (see [Path C](#path-c-run-everything-in-docker))

| Setting | What it does | In `.env.example` |
| --- | --- | --- |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | Used to create the PostgreSQL database. Compose builds `DATABASE_URL` from them. The password must be letters and digits only. | `cipherforge`, `CHANGE_ME_local_only` (change it), `cipherforge` |
| `FRONTEND_PORT`, `BACKEND_PORT`, `POSTGRES_PORT` | The ports on your computer. | 3000, 8000, 5432 |
| `FORWARDED_ALLOW_IPS` | Which senders the API trusts to say where a request really came from (the `X-Forwarded-For` header). That address goes into the audit log. | Not in the file. Compose uses the private address ranges. |

**Demo and dashboard development only**

| Setting | What it does | If you leave it out |
| --- | --- | --- |
| `CIPHERFORGE_DEMO_RESET` | Set to `1` for one start to rebuild the demo's invented data. | Not set |
| `CIPHERFORGE_DEMO_DB` | Use another demo database. It must be a `.db` file directly inside `backend/.demo/`. | `demo.db` |
| `CIPHERFORGE_DEMO_ROLES` | The roles of the demo's user. | `SecurityAnalyst` |
| `VITE_DEV_PROXY_TARGET` | Where the dashboard's development server sends API requests. Set it in the terminal that runs `npm run dev`, not in `.env`. | `http://127.0.0.1:8000` |

The full list, with the reasons for each rule, is in [deployment.md](deployment.md).

## Common setup problems

Find what you see in the left column. Commands are for Windows PowerShell, with the macOS and Linux
version where it differs. If your problem is not here, read the last lines in Terminal 1 (the API):
it prints a line for every problem and the line names the cause.

**While installing**

| What you see | What to do |
| --- | --- |
| `npm.ps1 cannot be loaded because running scripts is disabled on this system` | Windows blocks script files by default. Type `npm.cmd` instead of `npm`, and `npx.cmd` instead of `npx`. This guide already does. |
| `python` is "not recognized", or it opens the Microsoft Store | Python is not installed, or Windows cannot find it. Install Python 3.12 or newer from <https://www.python.org/downloads/> and tick **Add python.exe to PATH**. Close the terminal and open a new one. |
| `pip install` stops with an error | Check `python --version`. It must say 3.12 or higher. If you installed a newer Python after creating `backend/.venv`, delete that folder (`Remove-Item -Recurse -Force .venv`) and create it again. |
| A warning that mentions `EBADENGINE` when you run `npm ci` | Your Node.js is older than 22.22. Install a newer one from <https://nodejs.org/en/download>. |
| `ModuleNotFoundError: No module named 'app'` (or `'devtools'`) | You are in the wrong folder. Run the Python commands from the `backend` folder. |

**While starting**

| What you see | What to do |
| --- | --- |
| `Error: Port 5173 is already in use` (dashboard), or `[Errno 10048] ... only one usage of each socket address` (API) | Something already uses that port, often an earlier CipherForge that is still running. Paths A and B both use port 8000, so run only one at a time. Stop the old one, or [use another port](#free-a-port-or-use-another-one). |
| Red text with `NativeCommandError` after `alembic upgrade head` | Harmless in Windows PowerShell 5.1: it paints normal messages red. If the last lines say `Running upgrade ...`, it worked. |
| A long `Traceback` that ends with `ConfigurationError: Invalid configuration - NAME: ...` | A setting in `.env` is wrong. `NAME` is the setting. Fix it using the [Environment variables](#environment-variables) tables and start again. |
| The API starts, but your data is gone, or the tables are missing | You ran `alembic` and `uvicorn` from different folders, so each used its own SQLite file. Run both from the `backend` folder. |
| Docker says it cannot connect to the daemon, or that `docker` is not found | Docker Desktop is not installed or not running. Start it and wait until it says it is running. |
| Docker says a port is already allocated | Another program uses port 3000, 8000 or 5432. Change `FRONTEND_PORT`, `BACKEND_PORT` or `POSTGRES_PORT` in `.env`. |

**While using the dashboard**

| What you see | What it means and what to do |
| --- | --- |
| **API OFFLINE** in the top bar, or **Could not reach the API** | The dashboard cannot talk to the API. Is Terminal 1 still running? Does <http://127.0.0.1:8000/health> answer? If the API uses another port, see [below](#free-a-port-or-use-another-one). |
| **The request timed out** | The API or a provider was slow. Try again in a moment. |
| **Not signed in** | The API wants a sign-in, and the dashboard cannot sign in yet. Put `AUTH_MODE=dev` and `ENVIRONMENT=development` in `.env`, then restart the API. |
| **Access denied** | Your role is not allowed to look things up, or to delete them. Set `DEV_AUTH_ROLES=SecurityAnalyst` in `.env`, then restart the API. |
| **That request was not accepted** | CipherForge refused the indicator, for example a private address or an MD5 hash. The line under the title says why. See [What you can type](user-guide.md#what-you-can-type). |
| **Rate limit reached** | You started more than 30 investigations in a minute. Wait for the number of seconds the notice shows. |
| **The API reported an error** | The API had a problem. Try again shortly. If it keeps happening, read Terminal 1, and quote the reference code shown in the notice. It also appears in the API's log for that request. |
| The delete box stays open and shows a red notice | The deletion did not happen, so nothing was deleted. The causes are the ones in the rows above (the API is offline, a time-out, or a role that is not allowed). Fix the cause and press the red button again, or press **Cancel**. |
| **Unexpected response from the API** | The dashboard and the API are different versions. Update both to the same version. |
| The **System status** screen says the database is **Unavailable** (or `/ready` answers `503`) | The API cannot reach its database. For Path B, check that `DATABASE_URL` points at your SQLite file and that you ran `alembic upgrade head` from `backend`. For Docker, check that the `postgres` container is running. |
| Every result says **Not configured** or **Not assessed** | No API key is set. Follow [Add your API keys](#add-your-api-keys-optional) and restart the API. |
| A provider card says **Rate limited** | The provider's daily allowance is used up. Wait, or try tomorrow. |
| A provider card says **Error** | The provider could not be asked, or sent back something unusable. Try again, and check that the key is right. The provider code has never been run against the live services (see [Limitations](../README.md#limitations)), so please treat a persistent error as a bug to look into. |
| The Overview says **Nothing here yet** | Normal on a new installation. Investigate something and it fills in. |

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

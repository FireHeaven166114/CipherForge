# CipherForge

**Intelligence. Detection. Encryption.**

CipherForge is a small **security operations centre (SOC)** that runs on your own computer. Today it
does one job: you give it something suspicious (an IP address, a website name, a web link or a file
fingerprint) and it tells you **how risky that thing looks, and why**.

It asks two well-known security services what they know, shows their answers side by side, turns them
into **one risk score from 0 to 100** with the working shown, and keeps a permanent record of every
check. You use it in your web browser.

![The CipherForge Overview screen on a desktop: a navigation rail on the left, five headline tiles, and the Threat pulse and Risk posture panels over a dark animated background](docs/screenshots/overview.png)

*The Overview screen in demo mode, so the numbers are invented. The background moves; this is one frame.*

> **Use it responsibly.** What exists today only sends the text you type to two outside services. The
> project also plans network tools such as packet capture and honeypots. When those are built, run
> them only on systems and networks you own or are explicitly allowed to test.

**New here?** Read these four parts in order: [What is CipherForge?](#what-is-cipherforge),
[How it works](#how-it-works), [Get it running](#get-it-running) and
[Using the dashboard](#using-the-dashboard). In a hurry?
[Try it without API keys](#try-it-without-api-keys) takes about 10 minutes and needs no accounts.

## Contents

1. [What is CipherForge?](#what-is-cipherforge)
2. [Words you will see](#words-you-will-see)
3. [How it works](#how-it-works): [the big picture](#the-big-picture),
   [one investigation, step by step](#what-happens-when-you-investigate-something),
   [how the score is made](#how-the-score-is-made),
   [what is built and what is planned](#what-is-built-and-what-is-planned)
4. [What you need before you start](#what-you-need-before-you-start)
5. [Get it running](#get-it-running): [open a terminal](#open-a-terminal-in-the-project-folder),
   [try it without API keys](#try-it-without-api-keys),
   [run the real application](#run-the-real-application),
   [run everything in Docker](#run-everything-in-docker),
   [stop it and start it again](#stop-it-and-start-it-again)
6. [Using the dashboard](#using-the-dashboard)
7. [Using the API directly](#using-the-api-directly)
8. [Settings](#settings)
9. [When something goes wrong](#when-something-goes-wrong)
10. [Tests and quality checks](#tests-and-quality-checks)
11. [Project layout](#project-layout)
12. [Security in plain words](#security-in-plain-words)
13. [Limitations](#limitations)
14. [More documentation](#more-documentation)
15. [Map data](#map-data), [Credits](#credits) and [Licence](#licence)

## What is CipherForge?

### The problem

Security teams ask "is this bad?" all day long. It might be an address in a log file, a link in an
email or a file someone downloaded. Checking each one by hand on several websites is slow, and the
websites do not always agree.

### What CipherForge does about it

1. You enter one **indicator**: an IP address, a domain name, a web link or a file hash.
2. CipherForge asks up to two outside **providers**, AbuseIPDB and AlienVault OTX, what they know.
3. It shows **each provider's answer on its own card**. If the providers disagree, you see that.
4. It combines the answers into **one score from 0 to 100** and shows the working, line by line.
5. It lists **what is not known** and suggests **next steps**.
6. It **saves** the result so you can search it later, and writes a permanent entry in an
   **audit log**.

### The four screens

| Screen | What it is for |
| --- | --- |
| **Overview** | The home screen. Live figures: how many indicators you have checked, how many look risky, a world map, trends and the latest lookups. |
| **Investigate** | Where you type in an indicator and read the result. |
| **Indicators** | A searchable list of everything you have checked, with a page for each one. |
| **System status** | Shows whether the API is running and can reach its database. |

### What it is not

- **It is not antivirus.** It never looks at your files or scans your computer. A file hash is just a
  fingerprint that you type in.
- **It never acts on its own.** It does not block, isolate or change anything. It only advises.
- **It does not give verdicts.** A score is advice based on two sources. You decide what to do.
- **It is not finished.** The network sensor, detection rules, alerts, cases and encrypted file
  sharing are planned but not built. See
  [What is built and what is planned](#what-is-built-and-what-is-planned).

### One promise: "Not assessed" never means "safe"

If neither provider can answer (for example because no API key is set), CipherForge shows
**Not assessed**. It never shows "0, all clear". Nothing was checked, so nothing can be said. You
will see this wording all over the dashboard.

## Words you will see

| Word | What it means |
| --- | --- |
| **Indicator** (also **IOC**, "indicator of compromise") | One thing you want to check: an IP address, a domain, a URL or a file hash. |
| **IP address** | A number that identifies a computer on a network. **IPv4** looks like `8.8.8.8`. **IPv6** is the newer, longer kind and contains colons. |
| **Domain** | A website name such as `example.com`. |
| **URL** | A full web address such as `https://example.com/path`. |
| **SHA-256 hash** | A 64-character fingerprint of a file. The same file always gives the same fingerprint, so you can ask about a file without sending the file. |
| **Defanged** | Written in a deliberately broken way, such as `hxxp://example[.]com`, so that nobody clicks it by accident. CipherForge accepts these and fixes them. |
| **Threat intelligence** | Information that other people have collected about known bad addresses, websites, files and attackers. |
| **Provider** | An outside service that CipherForge asks. There are two today: AbuseIPDB and AlienVault OTX. |
| **API key** | A password-like code that a provider gives you (free) so it knows who is asking. CipherForge keeps it on the server and never shows it on screen. |
| **Risk score** | CipherForge's number from 0 to 100. Higher means more evidence of danger. |
| **Classification** | The score put into a named band: Informational, Low, Medium, High or Critical. |
| **Confidence** | How much fresh evidence stands behind the score. It is **not** the chance that the indicator is bad. |
| **Not assessed** | No provider answered, so nothing can be said. It is not the same as safe. |
| **Cache** | Saved answers that CipherForge reuses for a few hours, so it does not ask the providers again and again and use up your daily allowance. |
| **Audit log** | A permanent diary of every check: what, when and by whom. Entries cannot be edited or deleted. |
| **Demo mode** | A special way to start CipherForge with made-up data and pretend ("simulated") providers, so you can explore without any keys. |
| **API** | The part of CipherForge that does the work. The dashboard and other programs talk to it. |
| **Dashboard** | The web pages you see in your browser. They show what the API sends them. |
| **Database** | Where CipherForge saves everything. **PostgreSQL** is for serious use. **SQLite** keeps everything in one file and is handy for quick tries. |
| **Terminal** | A window where you type commands. On Windows this guide uses PowerShell. |
| **SOC** | Security operations centre: a team that watches for attacks and responds to them. CipherForge is a small, learning-sized version of the tools such teams use. |
| **MITRE ATT&CK** | A public catalogue of attacker techniques, each with a code such as `T1059`. The Overview lists the techniques that providers mention. |

## How it works

### The big picture

![How CipherForge fits together: a browser shows the dashboard; a web server (nginx or Vite) serves it and forwards API calls to the CipherForge API; the API checks who you are, validates the indicator, reuses saved answers or asks AbuseIPDB and AlienVault OTX, scores the result and keeps an audit trail; everything is stored in a database; Microsoft Entra ID sign-in tokens can be validated](docs/images/architecture.svg)

**How to read the picture.** Cyan boxes are CipherForge's own parts. The green box is the database.
Orange boxes are outside services that you do not control (the dashed one is used only when real
Microsoft sign-in is switched on). The amber line at the bottom lists what is not built yet. Each
arrow is a question or an answer. The API is the only part that talks to outside services.

**The parts, in plain words**

| Part | What it does | Where it lives in the code |
| --- | --- | --- |
| **1. Your browser** | Shows the dashboard. It is just a web page, so a browser is all you need to use CipherForge. | none |
| **2. The web server** | Serves the dashboard pages and passes requests for data on to the API. While you are trying things it is **Vite** (port 5173). In Docker it is **nginx** (port 3000). | `frontend/` (`vite.config.ts`, `nginx.conf`) |
| **3a. Gatekeeper** | Checks who you are (a sign-in token and a role) and how many lookups you have made this minute (at most 30). | `backend/app/security/` |
| **3b. Input checks** | Cleans up what you typed, works out what kind of indicator it is, and refuses private or internal addresses before anything leaves your computer. | `backend/app/services/normalization.py` |
| **3c. Intel engine** | Reuses saved answers that are still fresh, asks the providers for the rest, and scores the evidence. | `backend/app/services/intel_service.py`, `backend/app/collectors/`, `backend/app/correlation/scoring.py` |
| **3d. Audit trail** | Writes down every lookup. The database refuses to change or delete these rows. | `backend/app/services/audit.py` |
| **4. The database** | Saves indicators, each provider's answers and the audit log. | `backend/app/models/`, `backend/alembic/` |
| **5. The providers** | **AbuseIPDB** (IP addresses only) and **AlienVault OTX** (IP addresses, domains, URLs and SHA-256 hashes). | `backend/app/collectors/abuseipdb.py`, `otx.py` |
| **6. Microsoft Entra ID** (optional) | Microsoft's sign-in service. Only when `AUTH_MODE=entra`, the API downloads Microsoft's public keys to check sign-in tokens. In the default local mode (`AUTH_MODE=dev`) there is no sign-in and you are a local developer. | `backend/app/security/auth.py` |

**The same picture as text**

```text
   You, in a web browser
           |
           v
   Web server              serves the pages, forwards data requests
   (Vite or nginx)
           |
           v
   CipherForge API         gatekeeper -> input checks -> intel engine -> audit trail
   (Python, port 8000)
           |
           +------------------+--------------------+
           |                  |                    |
           v                  v                    v
   Database              AbuseIPDB           AlienVault OTX
   (saves everything)    (outside service)   (outside service)
```

### What happens when you investigate something

![The steps of one investigation: the browser sends the indicator to the API; the API checks your sign-in, role and rate limit and cleans up the input; it asks the database for fresh saved answers; it asks the providers for what is missing; it saves the new answers; it scores the evidence; it saves the score and an audit record; and it sends the result back to the browser](docs/images/investigation-flow.svg)

1. **You press Investigate.** The browser sends the indicator to the API
   (`POST /api/v1/intel/investigate`).
2. **The gatekeeper checks you.** Are you signed in? Is your role allowed (`SecurityAnalyst` or
   `Admin`)? Have you used up your 30 lookups this minute?
3. **The input is cleaned up and checked.** Spaces are trimmed, defanged forms are repaired and the
   kind of indicator is worked out. Private and internal addresses, such as `192.168.1.10`, are
   refused here, before anything is sent anywhere.
4. **The API asks the database:** do we already have a fresh saved answer?
5. **The database replies** with any answers that are still fresh. Fresh means less than 6 hours old
   for AbuseIPDB and less than 12 hours old for OTX (you can change both).
6. **The API asks the providers for what is missing,** both at the same time, waiting at most 10
   seconds for each. A provider with no key is skipped (it shows as *Not configured*). A provider
   that cannot handle this kind of indicator is skipped too (*Not supported*).
7. **The providers answer, or fail.** One provider failing never stops the other.
8. **The API saves the new answers.** Failures are not saved.
9. **It scores the evidence** into a number from 0 to 100 (see the next section).
10. **It saves the score and writes the audit record,** the permanent diary entry.
11. **The result goes back to your browser,** and you see it.

If no provider answers, the result says **Not assessed**, never "clean".

### How the score is made

The score is plain arithmetic. No AI model is involved and nothing is hidden: every point can be
traced to a line in the **How the score was built** panel (the method is called `intel-risk-v1`).

```text
  For each provider that answered:
        points = 45 x evidence strength x recency weight
                          |
                          v
  + 8 points when two providers independently back each other up
  + 5 points for each malware family they name (at most 10)
                          |
                          v
  If fewer than two providers back it up, the score never goes above 60
  The score never goes above 100
                          |
                          v
  Score 0 to 100  ->  a named band (see the table below)
```

- **Evidence strength** (0 to 1) says how strong a provider's own evidence is. For AbuseIPDB it is
  its "abuse confidence" divided by 100, lowered when there are very few reports. For OTX it grows
  with the number of community reports ("pulses") that mention the indicator.
- **Recency weight** makes newer evidence count more. Activity in the last 7 days counts fully (1.0),
  the last 30 days 0.9, 90 days 0.7, 180 days 0.5, anything older 0.3, and evidence with no date 0.6.
- A provider **backs it up** when its evidence strength times its recency weight is at least 0.4.
- **One source alone can never push the score above 60.** A single source can be wrong; two that
  agree are much stronger evidence.

| Score | Band | What CipherForge suggests |
| --- | --- | --- |
| 0 to 20 | **Informational** | No action needed from this evidence alone. If the indicator came from an alert, check your own logs before closing it. |
| 21 to 40 | **Low** | Treat it as context, not a finding. Check your own logs. |
| 41 to 60 | **Medium** | Investigate: search your own logs and alerts for it. |
| 61 to 80 | **High** | Prioritise the investigation. |
| 81 to 100 | **Critical** | Escalate for immediate review by an analyst. |

**Confidence** is separate from the score. Each provider that answered recently adds 35 points (an
older answer adds 15), two providers that back each other up add 20 more, and the most it can reach
is 90. CipherForge is never 100% sure.

**A worked example** (the invented address `2100:3946:b9d8::e0f4` in the demo):

| Line in the panel | Points |
| --- | --- |
| AbuseIPDB evidence (strength 0.94, recent: 45 x 0.94 x 1.0) | +42 |
| AlienVault OTX evidence (strength 1.00, recent: 45 x 1.00 x 1.0) | +45 |
| Independent corroboration (two sources agree) | +8 |
| Malware family association (three families named, capped at +10) | +10 |
| Maximum score (the total, 105, is pulled back to 100) | -5 |
| **Score** | **100, Critical** |

Its confidence is 90: two fresh answers (70) plus 20 for the two sources agreeing. The method is
written out in full in [docs/threat-intelligence.md](docs/threat-intelligence.md#scoring-intel-risk-v1).

### What is built and what is planned

| Area | Status |
| --- | --- |
| Threat intelligence: AbuseIPDB and OTX lookups, the cache, the score and the audit log | **Built and tested** |
| The dashboard: Overview, Investigate, Indicators, System status, command palette and the animated "Aurora Forge" look | **Built** |
| Demo mode with simulated providers (for development and learning) | **Built** |
| Microsoft Entra ID sign-in checks in the API | **Built on the API side.** The dashboard cannot sign in yet, so it works with `AUTH_MODE=dev` only |
| Docker Compose stack and the automated build pipeline | **Built and checked by GitHub's automatic checks**, but never run on the author's own computer (see [Limitations](#limitations)) |
| Network sensor (packet capture), detection rules, correlation, alerts, cases, encrypted file sharing, background workers, Azure deployment | **Planned, not started** |

The history of the project, phase by phase, is in [docs/project-status.md](docs/project-status.md).
How the planned modules would plug in is in [docs/architecture.md](docs/architecture.md).

## What you need before you start

| You need | What for | Where to get it |
| --- | --- | --- |
| **Python 3.12 or newer** | Runs the API | <https://www.python.org/downloads/>. On Windows, tick **Add python.exe to PATH** in the installer. |
| **Node.js 22.22 or newer** (24 is recommended) | Builds and serves the dashboard. It includes `npm`. | <https://nodejs.org/en/download> |
| **A web browser** | You use CipherForge in it | Any modern browser. The automated tests use Microsoft Edge. |
| **About 400 MB of free disk space** | The Python and Node packages | |

Optional:

- **Docker Desktop**, only for [Path C](#run-everything-in-docker):
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
says "not found", see [When something goes wrong](#when-something-goes-wrong).

## Get it running

There are three ways to run CipherForge. **Start with Path A.**

| | **Path A:** [try it without API keys](#try-it-without-api-keys) | **Path B:** [run the real application](#run-the-real-application) | **Path C:** [run everything in Docker](#run-everything-in-docker) |
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

### Try it without API keys

**Path A.** This runs the real application in **demo mode**. Two things are different. The two
providers are **simulated** (nothing is sent to AbuseIPDB or OTX), and the database is filled with
about two weeks of invented lookups, so every screen has something to show. You need no `.env` file
and no keys.

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
A labelled picture of this screen is in [Using the dashboard](#using-the-dashboard), along with
things to try.

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

### Run the real application

**Path B.** This is CipherForge without the pretend parts. It starts empty and every lookup is real.
It works with no API keys at all (every result will then say **Not assessed**), and you can
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
[Docker](#run-everything-in-docker).

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

![The Overview of a brand-new installation: every headline tile shows 0, a panel says Nothing here yet, the providers panel says none is configured, and the platform modules are listed](docs/screenshots/first-run-empty.png)

1. **The headline tiles** all show 0, because nothing has been investigated.
2. **"Nothing here yet"** is where the highest-risk and latest indicators will appear.
3. **The providers panel** says that no provider is configured. Until you add a key, every
   investigation comes back as **Not assessed**.
4. **Platform modules** shows what the project is made of. Threat intelligence is **LIVE**. The
   others are **PLANNED**.

**Step 6. Make your first investigation.** Click **Investigate an indicator**, click the **IPv4**
example (`8.8.8.8`) and press **Investigate**. With no keys you will see this:

![A first investigation with no API keys: the gauge says Not assessed, and both provider cards say Not configured](docs/screenshots/first-run-no-keys.png)

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
> [When something goes wrong](#when-something-goes-wrong).

### Run everything in Docker

**Path C.** Docker runs the database, the API and the dashboard in containers, so you do not need to
install Python or Node. It uses PostgreSQL.

> **Checked by the automatic tests, not by hand.** Docker was not available where this project was
> written, so nobody has followed these steps on a personal computer. GitHub's automatic checks do
> build both images and start the whole stack on a Linux machine, and confirm that the page and the
> API answer, so it is expected to work. Docker Desktop on Windows or macOS was not tried. If
> something fails, use Path A or B. Details:
> [docs/deployment.md](docs/deployment.md#verification-status).

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

### Stop it and start it again

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

## Using the dashboard

Open <http://127.0.0.1:5173> for Paths A and B, or <http://localhost:3000> for Path C.

The pictures in this section come from the demo (Path A), so the indicators and numbers in them are
**invented**. Yours will look different. The numbered markers were added to the pictures to match the
numbered lists under them. They are not on the real screen.

### The screens

Use the menu on the left to move around. On a phone it becomes a bar along the bottom.

| Menu item | Address | What it is for |
| --- | --- | --- |
| **Overview** | `/` | Figures, charts and a map for everything you have checked. |
| **Investigate** | `/investigate` | Type in an indicator and read the result. |
| **Indicators** | `/indicators` | A searchable list of everything you have checked. |
| *(click any indicator)* | `/indicators/…` | The saved record of one indicator. |
| **System status** | `/status` | Is the API running, and can it reach its database? |

Every screen has its own address, so you can bookmark it. The Indicators list keeps your search and
filters in the address too.

### A five-minute walk

Try this on Path A. It touches every screen.

1. On the **Overview**, read the five tiles at the top, then scroll down through the charts.
2. Click **Investigate an indicator**.
3. Under "Fill with an example", click **IPv4**, then press **Investigate**. The result is calm: a
   score of 0 and **Informational**.
4. Investigate `2100:3946:b9d8::e0f4`. This invented address comes back **Critical**, with a score of
   100. Scroll down to read each provider's card and "How the score was built".
5. Open **Indicators** in the menu. Try the search box and the filters, then click an indicator to
   open its saved record.
6. On the record, press **Re-check with providers**. It asks the providers again and updates the
   record.
7. Open **System status** and press **Refresh**.
8. Press `Ctrl K` (`Cmd K` on a Mac), type `8.8.8.8` and look at the options.

On Path B with no keys, every result comes back **Not assessed**. That is correct.

### The Overview screen

![The Overview in demo mode, with seven numbered markers](docs/screenshots/tour-overview.png)

1. **The menu.** One item for each screen.
2. **The command palette button.** Opens a quick-jump box. See
   [Shortcuts and the command palette](#shortcuts-and-the-command-palette).
3. **The Effects switch.** Turns the animated visuals on or off. See
   [Visual effects and small screens](#visual-effects-and-small-screens).
4. **API ONLINE.** The dashboard can reach the API. It changes to **API DEGRADED** (the API is up, but
   something it needs is not healthy) or **API OFFLINE** (the API cannot be reached). Click it to
   open System status.
5. **The five tiles.** *Indicators tracked*, *Lookups, last 24 hours*, *High-risk indicators* (High
   and Critical together), *Critical indicators* (score above 80) and *Not assessed* (no provider
   answered, which "is not the same as clean"). The first two also show the change since the 24 hours
   before. **Click a tile** to open the list of indicators behind it.
6. **Investigate an indicator.** The quickest way to start a lookup. Next to it, "Live · refreshed
   14:32:05" shows when the figures were last updated, and **Refresh** updates them now. They also
   update by themselves every minute.
7. **Threat pulse and Risk posture.** Threat pulse shows the lookups per day and how many of them
   ended High or Critical. Risk posture is a ring that shows how your indicators are spread across
   the risk bands.

On wide screens the top bar also shows who you are: your role and the sign-in mode ("Dev auth").

Scroll down for more panels:

| Panel | What it shows |
| --- | --- |
| **Provider-reported countries**, **Top countries** | A dot map and a ranked list of the countries that providers report for IP addresses. This is *not* where an attacker is, and domains, URLs and hashes have no country. |
| **Malware families** | Families of malware that providers link to your indicators. |
| **ATT&CK techniques** | MITRE ATT&CK codes (such as `T1059`) that providers mention. |
| **Provider tags** | Labels that providers attached, such as `botnet`. |
| **Indicator types by risk** | A grid of how many indicators of each type sit in each risk band. |
| **Indicator mix** | A radar shape showing how your indicators are split by type. |
| **Lookup activity** | A grid of lookups per hour of the day (UTC) over the last days. |
| **Intelligence providers** | Which providers are set up, what each one handles, and whether it is **Configured**, **Not configured** or **Simulated**. |
| **Highest risk**, **Latest investigations** | The top-scoring and the newest indicators. Click one to open its record. |
| **Platform modules** | The parts of the full platform. Only Threat intelligence is **LIVE**. The rest are **PLANNED**. |

**Click a country, a malware family, an ATT&CK technique or a tag** and a drawer slides in from the
right. It shows how many indicators match, the highest risk among them and the highest-risk ones,
each with a link to its record. For a technique it also links to the MITRE ATT&CK page. Press `Esc`
to close it.

Every chart also has a text version of its numbers, for people who use screen readers. If you ever
have a very large number of lookups, the Overview uses only the most recent ones and prints a note
saying so.

### The Investigate screen

![The Investigate form, with five numbered markers](docs/screenshots/tour-investigate-form.png)

1. **The input box.** Type or paste one indicator. A chip underneath (here "Looks like IPv4") shows
   what CipherForge thinks you typed.
2. **Fill with an example.** One click puts a sample of each type in the box.
3. **Ask the providers again, even if a stored answer is recent.** Normally CipherForge reuses an
   answer it saved a few hours ago, which protects your daily allowance with the providers. Tick the
   box to ask again anyway. This uses allowance. (An answer less than a minute old is reused
   regardless.)
4. **Before you send.** A reminder that the indicator is sent to each configured provider, which is
   outside your organisation. Do not enter internal host names or links that contain secret tokens.
5. **Investigate.** Starts the lookup.

#### What you can type

| Type | Example | Who is asked |
| --- | --- | --- |
| IPv4 address | `8.8.8.8` | AbuseIPDB and AlienVault OTX |
| IPv6 address | `2001:4860:4860::8888` | AbuseIPDB and AlienVault OTX |
| Domain | `example.com` | AlienVault OTX only |
| URL | `https://example.com/path` | AlienVault OTX only |
| SHA-256 hash | 64 characters made of `0-9` and `a-f` | AlienVault OTX only |

Only one provider can answer about a domain, a URL or a hash. The rules need two providers to back
each other up before a score can pass 60, so for these types **the score never goes above 60
(Medium)**.

CipherForge cleans up what you type. It accepts "defanged" text such as `hxxp://example[.]com` and
`1.2.3[.]4`, and it writes names in a standard form, so different spellings of the same thing end up
on one record.

It **refuses**, with a message that explains why: private or internal addresses (such as
`192.168.1.10`), made-up endings such as `.local`, `.internal` and `.lan`, single words, email
addresses, web links that contain a user name and password, MD5, SHA-1 and SHA-512 hashes, and
anything longer than 2,048 characters.

#### A low-risk result

![A result for 8.8.8.8: a score of 0, Informational](docs/screenshots/tour-result-fine.png)

1. **The gauge.** A ring that fills up to the score and changes colour with the risk band.
2. **The score**, from 0 to 100, with its band name.
3. **The confidence bar.** How much fresh evidence stands behind the score. It is *not* the chance
   that the indicator is bad.
4. **The facts.** The status (**Active** means at least one provider answer is still fresh,
   **Stale** means none is), when it was last checked, the activity window (when the providers saw
   it active) and how many sources had evidence.
5. **Open the saved record.** Every result is saved. The strip above the picture says, "This result
   is saved. You can return to it from the Indicators page."

#### A high-risk result

![A result for an invented risky address: a score of 100, Critical, with provider tags](docs/screenshots/tour-result-risky.png)

Markers 1 to 4 are the same as above. The new ones are:

5. **Provider tags.** Labels that the providers attached, here `botnet`, `loader` and `c2`. ("C2"
   means command and control: the servers that attackers use to give orders to infected machines.)
6. **The saved-record link**, as before.

#### Each provider's answer

![The Provider answers section: one card for each provider](docs/screenshots/tour-result-providers.png)

Scroll down to **Provider answers**. There is one card for each provider, so if the providers
disagree you see it here.

1. **The card header.** The provider's name and a status label such as **Answered**. The labels are
   explained in [What the provider labels mean](#what-the-provider-labels-mean).
2. **Evidence strength.** How strong this provider's evidence is, from 0 to 1. It is not a
   probability.
3. **Source.** "Queried live for this lookup" or "Stored answer from an earlier lookup".
4. **The other provider's card.**

A card also lists how fresh the answer is, the first and latest activity, when it was checked and
how long the answer stays valid, followed by the provider's own facts. AbuseIPDB gives an abuse
confidence (out of 100), the number of reports and of different reporters, the type of use, the
internet provider and an approximate location. OTX gives the number of *pulses* (reports written by
its community) that mention the indicator, and lists the top ones.

#### How the score was built

![The "How the score was built" panel](docs/screenshots/tour-result-score.png)

This panel comes right after the provider cards. It starts with a one-line summary, such as "2
providers answered; 2 reported malicious activity; 2 had evidence strong and recent enough to count
as independent support."

1. **The points table.** Each line is one reason with its points. A minus number takes points away
   (for example the cap at 100).
2. **The total**, "Score (out of 100)".
3. **What is not known.** The gaps in the evidence, stated plainly (for example "No internal
   telemetry was available").
4. **Recommended next steps.** Advice that depends on the risk band. CipherForge only recommends.
   It never blocks, isolates or changes anything on its own.
5. **How scores are calculated (intel-risk-v1).** A folded section; click it to open it. It explains
   the rules in the same terms as [How the score is made](#how-the-score-is-made).

#### When nothing can be said

![A Not assessed result: no number on the gauge, and neither provider could answer](docs/screenshots/tour-not-assessed.png)

1. **The gauge** says **Not assessed** and shows no number.
2. **The explanation**: "No provider answered, so CipherForge has no evidence about this indicator.
   This is not a clean result: it only means nothing was checked."
3. **The first card.** Here AbuseIPDB says **Not supported**, because it only handles IP addresses
   and this indicator is a domain.
4. **The second card.** Here OTX says **Rate limited**: it refused the request because its allowance
   was used up.

The demo does this on purpose for any value that contains `rate-limit`. On Path B with no keys you
see the same screen, with **Not configured** on both cards.

#### When an indicator is refused

![A refused lookup: a private address is not accepted, and a red alert explains why](docs/screenshots/tour-refused.png)

1. **The input** holds `192.168.1.10`, a private address that only exists inside a home or office
   network.
2. **Investigate**, as usual.
3. **The red alert**: "That request was not accepted", followed by the reason: private, loopback,
   link-local, multicast, reserved and other non-public addresses are not looked up.

There are two reasons. Your internal addressing is not leaked to a third party, and nobody can use
CipherForge to make the server probe machines inside your network. A refused lookup is still
recorded in the audit log, without the text you typed.

### The Indicators screen

![The Indicators list, filtered to High or critical and sorted by highest risk, with five numbered markers](docs/screenshots/tour-indicators.png)

This is the list you get when you click the **High-risk indicators** tile on the Overview.

1. **The search box.** Type part of an address, domain, URL or hash, then press **Search**.
2. **The filters.** **Type** (IPv4, IPv6, Domain, URL or SHA-256), **Classification** (High or
   critical, Critical, High, Medium, Low, Informational or Not assessed) and **Sort by** (Most
   recently checked, or Highest risk first). **Reset filters** appears when a filter is on.
3. **The count**, such as "12 indicators found."
4. **An indicator.** Click it to open its saved record.
5. **Score and Confidence.** The two numbers for each indicator. The other columns are Type,
   Classification, Sources (how many had evidence), Status and Last checked.

The list shows 25 indicators at a time. Use **Previous** and **Next** under the table.

### A saved record

![An indicator's saved record, with three numbered markers](docs/screenshots/tour-indicator-details.png)

1. **← All indicators.** Goes back to the list.
2. **Re-check with providers.** Asks the providers again and updates the record. This uses some of
   the providers' daily allowance, so use it when you need fresh evidence.
3. **The result.** The same gauge, provider cards and score breakdown that you saw on the Investigate
   screen. The page says, "This is the stored record. Re-checking asks the configured providers again
   and updates it."

### The System status screen

![The System status screen, with four numbered markers](docs/screenshots/tour-status.png)

1. **Overall status.** One word and one sentence. **Operational**: the API is up and its database is
   reachable. **Degraded**: the API is up, but something it needs is not healthy. **Down**: the API
   cannot be reached. **Checking**: it is still finding out.
2. **Refresh**, and the time of the last check. The page also refreshes itself every 30 seconds.
3. **The API card.** **Up** with the service name and version, or **Unreachable**.
4. **The Database card.** **Reachable** when the API can run queries, or **Unavailable** when it
   cannot reach its database.

If something looks wrong anywhere else, look here first.

### Shortcuts and the command palette

![The command palette after typing 8.8.8.8, with three numbered markers](docs/screenshots/tour-palette.png)

Press `Ctrl K` (`Cmd K` on a Mac) or `/` to open the palette from any screen.

1. **The input row.** Type what you want.
2. **The options.** Anything you type can be investigated or searched for, so the first two options
   are always "Investigate “8.8.8.8”" and "Search indicators for “8.8.8.8”". Typing a screen name
   offers to go there. You can also turn the visual effects on or off.
3. **The hint line.** "↑ ↓ move · Enter run · Esc close".

Choosing **Investigate** starts the lookup at once, so the indicator is sent to the providers
straight away. Following a link never does that.

| Keys | What happens |
| --- | --- |
| `Ctrl K` or `Cmd K` | Open or close the palette |
| `/` | Open the palette |
| `G`, then `O` | Go to Overview |
| `G`, then `I` | Go to Investigate |
| `G`, then `L` | Go to Indicators (**L** for list) |
| `G`, then `S` | Go to System status |
| `Esc` | Close the palette or a drawer |

For the two-key shortcuts, press the second key within one second. Plain keys do nothing while you
are typing in a box or while the palette or a drawer is open, so they cannot get in your way.

### What the provider labels mean

Each provider card has one of these labels.

| Label | What it means | What to do |
| --- | --- | --- |
| **Answered** | The provider returned evidence about this indicator. | Read its card. |
| **No data** | The provider answered but holds no reports about this indicator. **That is not proof it is safe.** | Treat it as "no information from this source". |
| **Not configured** | No API key is set on the server for this provider, so it was not asked. | Add the key: [Add your API keys](#add-your-api-keys-optional). |
| **Not supported** | This provider does not handle this type of indicator. | Nothing. AbuseIPDB, for example, only handles IP addresses. |
| **Rate limited** | The provider refused the request because its allowance was used up. | Try again later. |
| **Error** | The provider could not be asked, or returned something unusable. | Try again. See [When something goes wrong](#when-something-goes-wrong). |
| **Not queried** | No stored answer exists for this provider. | Investigate or re-check the indicator to ask it. |

An indicator's **Status** is **Active** when at least one provider answer is still fresh and
**Stale** when none is. A stale indicator is not wrong. It just has not been checked for a while.

### Things to try in the demo

| Type this | What happens |
| --- | --- |
| `8.8.8.8` | Score 0, **Informational**, confidence 70. The providers were asked and nothing bad was reported. |
| `2100:3946:b9d8::e0f4` | **Critical**, score 100, confidence 90. Both providers report it. |
| `rate-limit-sample.example.net` | **Not assessed**. AbuseIPDB cannot handle domains, and OTX says **Rate limited**. |
| `provider-error.example.com` | **Not assessed**. AbuseIPDB cannot handle domains, and OTX shows **Error**. Any value containing `provider-error` fails on purpose. |
| `hxxp://example[.]com` | Accepted and tidied into the URL `http://example.com/`. |
| `192.168.1.10` | Refused: a private address. |
| `d41d8cd98f00b204e9800998ecf8427e` | Refused: this is an MD5 hash, and only SHA-256 is accepted. |

**Anything else you type also gets an answer, but the answer is invented.** The simulated providers
make up a profile from the text you typed, so the same value always gets the same answer. It says
nothing about the real indicator, so never use the demo to judge one.

### Visual effects and small screens

The dashboard has a futuristic look: an animated background (aurora glows, a grid floor, drifting
dots and a light that follows your pointer), numbers that count up, charts that draw themselves and
headings that "decode". The motion is built with [anime.js](https://animejs.com/).

- **The Effects switch** in the top bar turns all of it off. Your choice is remembered in this
  browser only.
- **Reduced motion.** If your computer is set to reduce motion, the effects stay off and the switch is
  disabled, with a tooltip that says why.
- **Nothing depends on an effect.** Every screen works the same with them off.
- **Touch screens** skip the light that follows the pointer.
- **Slow computers.** The effects were not tuned for slow hardware. If a page feels sluggish, switch
  them off.
- **Phones.** The layout adapts and the menu moves to the bottom:

<img src="docs/screenshots/phone.png" alt="The Overview on a phone-sized screen, with the menu as a bar along the bottom" width="320">

## Using the API directly

The dashboard is only one way in. Everything it shows comes from the **API**, and you can call the API
yourself from PowerShell, `curl` or your own scripts. That is handy for automation, and for seeing
exactly what the dashboard sees. (In demo mode the answers are invented, as everywhere else.)

The API has eight endpoints today:

| Endpoint | What it does |
| --- | --- |
| `GET /health` | Is the API alive? Public. |
| `GET /ready` | Can the API reach its database? Public. It answers `503` when it cannot. |
| `GET /api/v1/me` | Who the API thinks you are, and which roles you have. |
| `POST /api/v1/intel/investigate` | Investigates one indicator, like the **Investigate** screen. The body is `{"indicator": "8.8.8.8"}`. Add `"refresh": true` to ask the providers again instead of reusing a saved answer. |
| `GET /api/v1/intel/indicators` | Searches what you have investigated. Optional filters: `q` (part of the value), `type`, `classification`, `assessed`, `sort`, `limit` and `offset`. |
| `GET /api/v1/intel/indicators/{id}` | One saved indicator, by its id. |
| `GET /api/v1/intel/stats` | Counts of indicators and lookups. |
| `GET /api/v1/intel/overview` | The figures behind the Overview screen. |

**Who may call them.** Everything under `/api/v1/intel` needs the `SecurityAnalyst` or `Admin` role.
With the default `AUTH_MODE=dev` you are a local developer who has the `SecurityAnalyst` role, so you
send no token. With `AUTH_MODE=entra` you send an `Authorization: Bearer <token>` header.

**Try it.** With the API running, open <http://127.0.0.1:8000/docs>. This interactive page lists every
endpoint and lets you try each one from the browser. It is switched off when
`ENVIRONMENT=production`. Or type commands in a terminal.

Windows (PowerShell):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/api/v1/me
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/intel/investigate -ContentType 'application/json' -Body '{"indicator": "8.8.8.8"}' | ConvertTo-Json -Depth 8
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/intel/indicators?sort=risk&limit=5" | ConvertTo-Json -Depth 5
```

macOS or Linux:

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/v1/me
curl -s -X POST -H "Content-Type: application/json" -d '{"indicator": "8.8.8.8"}' http://127.0.0.1:8000/api/v1/intel/investigate
curl -s "http://127.0.0.1:8000/api/v1/intel/indicators?sort=risk&limit=5"
```

`/health` answers `{"status":"ok","service":"cipherforge-api","version":"0.5.0"}` (PowerShell draws it
as a small table). `/api/v1/me` answers
`{"subject":"dev-user","name":"Local Developer","roles":["SecurityAnalyst"],"auth_mode":"dev"}`. (On
Windows, `curl.exe` also works, but its quoting rules differ between PowerShell versions, so this
guide uses `Invoke-RestMethod`.)

**What an investigation answer looks like.** This is the real answer of a new installation with no API
keys, shortened (the full one has more fields, listed in [docs/api.md](docs/api.md)):

```json
{
  "indicator": {
    "indicator_type": "ipv4",
    "indicator_value": "8.8.8.8",
    "risk_score": 0,
    "classification": "informational",
    "confidence": 0,
    "source_count": 0,
    "status": "stale"
  },
  "providers": [
    {
      "provider": "abuseipdb",
      "status": "not_configured",
      "message": "AbuseIPDB is not configured (no API key set)."
    },
    {
      "provider": "otx",
      "status": "not_configured",
      "message": "AlienVault OTX is not configured (no API key set)."
    }
  ],
  "score": {
    "methodology": "intel-risk-v1",
    "answered_sources": 0,
    "uncertainty": ["No provider returned evidence for this indicator.", "..."],
    "recommended_actions": [
      "No provider answered, so CipherForge has no evidence about this indicator and cannot say whether it is safe.",
      "..."
    ]
  }
}
```

| Part of the answer | What it holds |
| --- | --- |
| `indicator` | The saved record: type, value, `risk_score`, `classification` (always lower case), `confidence`, `status` and dates. |
| `providers` | One entry per provider, with a `status` (`ok`, `no_data`, `not_configured`, `unsupported`, `rate_limited`, `error` or `not_queried`), its evidence and a `message`. These are the [labels on the provider cards](#what-the-provider-labels-mean). |
| `score` | How the score was built: the lines (`factors`), `answered_sources`, what is not known (`uncertainty`) and the suggested next steps (`recommended_actions`). |
| `internal_evidence` | Always "not available" today, because no internal telemetry is connected. |

> **Always read `answered_sources`.** With no keys the API answers `risk_score: 0` and
> `classification: "informational"`, because it has no evidence at all. That is **not** "clean". Look at
> `score.answered_sources`: **0 means no provider answered, so the result is unknown.** The dashboard
> makes this check for you and shows **Not assessed**. A script of your own must do the same.

**Errors** all have the same shape, whatever went wrong. This is what you get for
`{"indicator": "192.168.1.10"}`, a private address, with HTTP status `422`:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Private, loopback, link-local, multicast, reserved and other non-public addresses are not looked up.",
    "correlation_id": "21a543a94ddc4365bee4366d0b7dc83f"
  }
}
```

The statuses you will meet are `401` (no valid sign-in), `403` (the wrong role), `422` (input not
accepted), `429` (too many lookups; the `Retry-After` header says how many seconds to wait) and `503`
(something the API needs, such as the database, is down). Every answer carries an `X-Correlation-ID`
header. Quote it when you report a problem, because the same ID appears in the API's log for that
request. The full contract is in [docs/api.md](docs/api.md).

## Settings

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
| `AUTH_MODE` | `dev`: no sign-in, and everyone is a local developer. `entra`: the API checks Microsoft Entra ID sign-in tokens. `dev` is refused when `ENVIRONMENT=production`. The dashboard cannot sign in yet, so it needs `dev` (see [Limitations](#limitations)). | `entra` (the template sets `dev`) |
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

**Docker only** (see [Path C](#run-everything-in-docker))

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

The full list, with the reasons for each rule, is in [docs/deployment.md](docs/deployment.md).

## When something goes wrong

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
| A long `Traceback` that ends with `ConfigurationError: Invalid configuration - NAME: ...` | A setting in `.env` is wrong. `NAME` is the setting. Fix it using the [Settings](#settings) tables and start again. |
| The API starts, but your data is gone, or the tables are missing | You ran `alembic` and `uvicorn` from different folders, so each used its own SQLite file. Run both from the `backend` folder. |
| Docker says it cannot connect to the daemon, or that `docker` is not found | Docker Desktop is not installed or not running. Start it and wait until it says it is running. |
| Docker says a port is already allocated | Another program uses port 3000, 8000 or 5432. Change `FRONTEND_PORT`, `BACKEND_PORT` or `POSTGRES_PORT` in `.env`. |

**While using the dashboard**

| What you see | What it means and what to do |
| --- | --- |
| **API OFFLINE** in the top bar, or **Could not reach the API** | The dashboard cannot talk to the API. Is Terminal 1 still running? Does <http://127.0.0.1:8000/health> answer? If the API uses another port, see [below](#free-a-port-or-use-another-one). |
| **The request timed out** | The API or a provider was slow. Try again in a moment. |
| **Not signed in** | The API wants a sign-in, and the dashboard cannot sign in yet. Put `AUTH_MODE=dev` and `ENVIRONMENT=development` in `.env`, then restart the API. |
| **Access denied** | Your role is not allowed to look things up. Set `DEV_AUTH_ROLES=SecurityAnalyst` in `.env`, then restart the API. |
| **That request was not accepted** | CipherForge refused the indicator, for example a private address or an MD5 hash. The line under the title says why. See [What you can type](#what-you-can-type). |
| **Rate limit reached** | You started more than 30 investigations in a minute. Wait for the number of seconds the notice shows. |
| **The API reported an error** | The API had a problem. Try again shortly. If it keeps happening, read Terminal 1, and quote the reference code shown in the notice. It also appears in the API's log for that request. |
| **Unexpected response from the API** | The dashboard and the API are different versions. Update both to the same version. |
| The **System status** screen says the database is **Unavailable** (or `/ready` answers `503`) | The API cannot reach its database. For Path B, check that `DATABASE_URL` points at your SQLite file and that you ran `alembic upgrade head` from `backend`. For Docker, check that the `postgres` container is running. |
| Every result says **Not configured** or **Not assessed** | No API key is set. Follow [Add your API keys](#add-your-api-keys-optional) and restart the API. |
| A provider card says **Rate limited** | The provider's daily allowance is used up. Wait, or try tomorrow. |
| A provider card says **Error** | The provider could not be asked, or sent back something unusable. Try again, and check that the key is right. The provider code has never been run against the live services (see [Limitations](#limitations)), so please treat a persistent error as a bug to look into. |
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

## Tests and quality checks

You do not need any of this to *use* CipherForge. It is for people who change the code, and for anyone
who wants to know how far the results can be trusted.

The project has three layers of automated tests (counts are for version 0.5.0):

| Layer | Tests | Tool | What it checks |
| --- | --- | --- | --- |
| Backend | 867 | pytest | The API, the input checks, the provider code (run against recorded answers, never the live services), the score, the database and the audit log |
| Frontend units | 426 | Vitest | Screens, components, helpers and the motion layer |
| End to end | 596 | Playwright | The finished dashboard, in a real browser, talking to the real API |

To run the first two, from the project folder.

Windows (PowerShell):

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest      # ends with: 669 passed, 198 skipped

cd ..\frontend
npm.cmd run typecheck
npm.cmd run lint
npm.cmd test                              # ends with: Tests  426 passed (426)
```

macOS or Linux:

```bash
cd backend && .venv/bin/python -m pytest      # ends with: 669 passed, 198 skipped
cd ../frontend && npm run typecheck && npm run lint && npm test
```

**"198 skipped" is normal.** 197 of them are the PostgreSQL copies of the database tests. They are
skipped unless you point `TEST_DATABASE_URL` at a throwaway PostgreSQL database (see
[docs/testing.md](docs/testing.md#quality-checks)). The last one is skipped on purpose, because SQLite
has no `TRUNCATE` statement. With a PostgreSQL database supplied, 866 tests pass and 1 is skipped.
Each of the two runs takes about a minute.

The end-to-end tests are started with `npm.cmd run test:e2e` (from `frontend`). They take about 37
minutes. Before the first run, read [docs/testing.md](docs/testing.md#testing-the-dashboard): it lists
what to install and what each group of tests proves. The same page lists the security scanners and the
other [quality checks](docs/testing.md#quality-checks).

**What a green result shows.** At the time of writing, every backend test passes (on SQLite, and on a
real PostgreSQL 16.2 when one is supplied), and so do all 426 frontend tests and all 596 end-to-end
tests. That shows the code does what the tests expect. It does **not** show that the live providers
work (the tests use recorded and simulated answers), that Docker Desktop works on your computer (the
containers have only been started by the automatic checks on GitHub) or that the design looks good to
a person. [What a green run does not show](docs/testing.md#what-a-green-run-does-not-show)
lists the gaps.

The checks also run automatically on GitHub, in `.github/workflows/ci.yml` (four jobs: backend,
frontend, dashboard end-to-end in Chromium on Linux, and a Docker build with a smoke test). Its first
run failed two of the four jobs. [What the first run on GitHub found](docs/testing.md#what-the-first-run-on-github-found)
explains the three causes, all of which are fixed.

## Project layout

You do not need to read any code to use CipherForge. This map is for when you are curious or want to
change something. A folder marked **Planned** holds only a short note, because that part is not built.

```text
cipherforge/
|-- README.md                 This guide
|-- LICENSE                   The MIT licence
|-- .env.example              A template for your settings (copy it to .env)
|-- docker-compose.yml        Starts everything in Docker (run by the automatic checks only)
|-- .github/                  The automatic checks (ci.yml) and dependency updates
|
|-- backend/                  THE API: the part that does the work (Python, FastAPI)
|   |-- app/
|   |   |-- main.py           Where the API starts
|   |   |-- api/              The web addresses: /health, /ready and /api/v1/...
|   |   |-- collectors/       One file per provider: abuseipdb.py and otx.py
|   |   |-- correlation/      scoring.py: how the 0 to 100 score is worked out
|   |   |-- services/         The investigation steps, Overview figures, audit log
|   |   |-- security/         Sign-in checks, roles and the rate limiter
|   |   |-- models/           The database tables
|   |   |-- schemas/          The exact shape of every request and reply
|   |   |-- database/         The connection to the database
|   |   |-- core/             Settings, logging, error format, request helpers
|   |   |-- detection/        Planned: nothing in it yet
|   |   `-- workers/          Planned: nothing in it yet
|   |-- alembic/              Database set-up scripts, called "migrations"
|   |-- devtools/             Demo mode: demo server, made-up data, pretend providers
|   |-- tests/                The backend tests (pytest)
|   `-- Dockerfile, requirements.txt, pyproject.toml, ...
|
|-- frontend/                 THE DASHBOARD (React, TypeScript, Vite, Tailwind)
|   |-- src/
|   |   |-- pages/            The screens: Overview, Investigate, Indicators, ...
|   |   |-- components/       Building blocks: cards, charts, the side rail, ...
|   |   |-- features/         Helper logic behind the screens' figures
|   |   |-- services/         The code that talks to the API and checks replies
|   |   |-- hooks/            Small helpers that load data
|   |   |-- motion/           The animations (anime.js)
|   |   |-- effects/          The "Visual effects" on/off switch
|   |   |-- test/, types/     Test helpers and shared type definitions
|   |   `-- App.tsx, main.tsx, index.css
|   |-- e2e/                  The browser tests (Playwright)
|   |-- public/               The icon shown on the browser tab
|   |-- scripts/              build-world-data.mjs, which makes the map data
|   |-- nginx.conf            Web server settings used by the Docker image
|   `-- Dockerfile, package.json, vite.config.ts, ...
|
|-- docs/                     The detailed documents (see "More documentation")
|   |-- images/               The two diagrams in this guide
|   `-- screenshots/          The pictures in this guide
|
|-- infra/                    Planned: Azure set-up (a note only)
`-- sensor/                   Planned: the network sensor (a note only)
```

Some more folders appear after you run things. They are not part of the project, Git ignores them, and
you can leave them alone: `backend/.venv` (the Python packages), `frontend/node_modules` (the
JavaScript packages), `frontend/dist` (the built dashboard), `backend/.demo` (the demo database) and
`backend/cipherforge.db` (the database from [Path B](#run-the-real-application)).

**Where to look when you want to change something:**

| I want to... | Look here |
| --- | --- |
| Change how the score is worked out | `backend/app/correlation/scoring.py`. The dashboard's "How the score was built" panel keeps its own copy of the rules in `frontend/src/components/intel/ScorePanel.tsx`, so change that too, and the write-up in [docs/threat-intelligence.md](docs/threat-intelligence.md#scoring-intel-risk-v1). |
| Add a third provider | `backend/app/collectors/`. The steps are in [Adding a provider](docs/threat-intelligence.md#adding-a-provider). |
| Add or change a setting | `backend/app/core/config.py` and `.env.example`. |
| Add a database table | `backend/app/models/`, plus a new script in `backend/alembic/versions/`. |
| Change what a screen looks like | `frontend/src/pages/` (the screens) and `frontend/src/components/` (the pieces). |
| Change the colours | The `@theme` block near the top of `frontend/src/index.css`. |
| Change the animations | `frontend/src/motion/`. |
| Change the demo's invented data | `backend/devtools/demo_data.py`. The pretend provider answers are in `simulated_providers.py` next to it. |

## Security in plain words

CipherForge is a security tool, so it tries to be careful with what it handles. This is what it does,
in everyday words. The technical list is in [docs/security.md](docs/security.md), and the thinking
behind it is in [docs/threat-model.md](docs/threat-model.md).

> **This is not a security audit.** CipherForge is a learning and portfolio project. Its protections
> are checked by automated tests and scanners. No independent security review or penetration test
> has been done, and the project does not claim to be ready for production use.

| Worry | What CipherForge does about it |
| --- | --- |
| **Will my API keys leak?** | The keys stay on the server, in the `.env` file (which Git ignores) or in environment variables. The dashboard never receives them. The API never sends them back; it only says whether a key is set. The logs hide them. |
| **What if I type something harmful?** | Every indicator is checked before it is used: a length limit, no hidden or invisible characters, only SHA-256 hashes, and only `http` and `https` links with no password inside. Error messages never repeat what you typed. |
| **Could CipherForge be tricked into probing my own network?** | No. Private and internal addresses (such as `192.168.1.10`) and made-up endings (such as `.local`) are refused before any request is made. The server contacts only two fixed provider websites and does not follow redirects. Security people call the trick this stops "server-side request forgery". |
| **Could a provider's answer attack me?** | Answers are treated as untrusted. Only known fields are kept, sizes are capped and control characters are removed. The dashboard shows every provider word as plain text, never as page code. The only links to other websites go to OTX and MITRE ATT&CK pages, built from strict patterns, so a provider cannot send you somewhere else. The project's code checks, and in the Docker image a strict browser security policy (CSP), add two more layers. |
| **What if a provider is slow or sends too much?** | Each call has a time limit (10 seconds by default) and a size limit (2 MiB). If one provider fails, the other one's answer still appears and the failure is labelled. |
| **Who can see what I look up?** | The providers: the indicator you investigate is sent to them, outside your organisation, so do not type anything you are not allowed to share. The Investigate screen says this next to the button. CipherForge also writes each lookup, with who asked and when, to the audit log in your own database. Your browser talks only to CipherForge's own web server. No fonts, maps or analytics come from other sites, and there are no cookies. The one thing the dashboard remembers is your visual-effects switch. One thing to know: the search text on the Indicators screen is part of the web address, so it can appear in your browser history. |
| **Who is allowed to use it?** | The API has three roles: `Admin`, `SecurityAnalyst` and `User`. The investigation and indicator routes need `SecurityAnalyst` or `Admin`, and unknown roles are ignored. In Microsoft Entra ID mode the API checks sign-in tokens and rejects forged or unsigned ones. In `dev` mode (used in this guide) there is no sign-in, so use it only on your own computer. |
| **What if someone floods it with requests?** | Each user may start 30 investigations a minute (you can change this). That also protects your providers' free allowances. |
| **Can the history be altered?** | Every check is written to the audit log, even refused ones (without the text that was refused). The database refuses to change or delete these rows. A database administrator could still remove that protection, so for serious use copy the log somewhere the application cannot write. |
| **What if the settings are unsafe?** | In `production` mode the API refuses to start with dev sign-in, SQLite, the example password `CHANGE_ME` or `*` for CORS (the setting that decides which websites may call the API). The message names the setting and never its value. The `/docs` page is switched off too. |
| **Could CipherForge break something on its own?** | No. It reads from two providers and advises. It never blocks, isolates or changes anything. |
| **Could the demo touch real data?** | No. Demo mode uses its own database file inside `backend/.demo/` (it refuses any other place), its providers are pretend and make no outside requests, and a banner on every screen says so. |
| **Will the screen mislead me?** | It is designed not to. "Not assessed" never looks like "safe". Each provider is shown separately. A country on the map is labelled "Provider-reported country", never as where the attacker is. Every chart has its exact numbers as text. |
| **Is the Docker set-up locked down?** | It is written to be: the containers run without administrator rights, drop extra Linux powers and publish ports only on `127.0.0.1`. The automatic checks on GitHub start it and confirm that it answers, but they do not test each of these protections, and it has not been run on a personal computer (see [Limitations](#limitations)). |

**Use it responsibly.** A score describes an *address*, not a *person*. Never treat it as proof of who
did something or where they are. When the planned network tools arrive (packet capture, honeypots),
use them only on systems and networks you own or have clear permission to test. See
[Responsible use](docs/security.md#responsible-use).

**Before you put CipherForge anywhere other people can reach**, read
[Before exposing it beyond your machine](docs/deployment.md#before-exposing-it-beyond-your-machine) and
the [Entra ID setup](docs/deployment.md#entra-id-setup-for-auth_modeentra). In short: put HTTPS (TLS)
in front of it, use `production` with Entra ID sign-in, set a strong database password, keep the API
keys in a secret store and add rate limiting at the proxy. Remember that the dashboard cannot sign in
yet, so it cannot be used against such an API.

## Limitations

CipherForge is open about what it cannot do. Please read this list before you rely on it for anything
that matters. More detail is in [docs/threat-intelligence.md](docs/threat-intelligence.md#limitations),
[docs/security.md](docs/security.md) and [docs/deployment.md](docs/deployment.md#verification-status).

### Not built yet

| Missing piece | What it would do |
| --- | --- |
| **Network sensor** | A defensive program that would watch the *numbers* of network traffic (how many packets and connections, not what is inside them) on a network you own, and report them. Only a note exists, in `sensor/`. |
| **Detection rules and correlation** | Spot attacks in that traffic and link them to what the providers know. Today only the scoring of looked-up indicators exists. |
| **Alerts and cases** | Raise an alert and follow an incident from start to finish. |
| **Encrypted file sharing ("Vault")** | Share files safely. **No encryption code exists**, and CipherForge does not claim to encrypt anything. [docs/encryption-design.md](docs/encryption-design.md) lists what must be decided first. |
| **Background workers** | Refresh old answers and tidy old data by themselves. A shared store such as Redis would join here. |
| **Azure deployment** | Run CipherForge in the cloud, described as code in `infra/`. |
| **Sign-in in the dashboard** | The dashboard cannot sign in to Microsoft Entra ID. It works only with `AUTH_MODE=dev`, which the API refuses in production. Against an API that needs Entra ID sign-in, every screen says "Not signed in". |

### Never tried for real

- **The two providers have never been called for real.** The tests use recorded and invented answers,
  because no keys were available when the code was written. The requests were checked against the
  services' public documentation and AlienVault's own code library, but a few OTX details (the pulse
  counts and dates, malware families and MITRE codes) come from sample answers and are **not
  confirmed**. If one is missing or renamed, CipherForge treats it as unknown and gives a weaker
  result instead of failing. **Do one real lookup with your own keys before you rely on the output.**
  Details: [Verification status](docs/threat-intelligence.md#verification-status).
- **Docker has not been run by a person.** The computer used to write the project had no Docker. The
  automatic checks on GitHub do build both images and start `docker-compose.yml` on a Linux machine,
  then check that the page and the API answer, but nobody has run `docker compose up` on a personal
  computer, and Docker Desktop on Windows or macOS was not tried. The nginx settings were also tested
  with a real nginx program outside Docker. If Path C fails, use Path A or B, and please report it.
  Details: [Verification status](docs/deployment.md#verification-status).
- **The automatic checks are new.** They ran for the first time only after the project was put
  online, and that first run failed two of its four jobs for three reasons, all since fixed (see
  [What the first run on GitHub found](docs/testing.md#what-the-first-run-on-github-found)).
- **Microsoft sign-in has never been tried with a real organisation.** The token checks are tested
  with generated keys only.
- **The browser tests ran in Chromium-based browsers only:** Microsoft Edge on Windows, and Chromium
  on Linux in the automatic checks. Firefox and Safari were not tested.
- **Only the Windows commands were run.** The macOS and Linux versions in this guide follow the same
  steps, but nobody has run them.

### What a score can and cannot tell you

- **A score is advice from two sources.** CipherForge has no data of your own to compare with, and
  every result says so. See [How the score is made](#how-the-score-is-made).
- **A score does not age by itself.** It is worked out again only when you investigate the indicator
  again. There are no background refreshes.
- **Provider text is written by other people.** Some of it (OTX pulse names and tags, for example) is
  written by volunteers, and it can be wrong or out of date.
- **A country is what the provider says,** and it says little about who is behind an address.
- **Demo mode invents its answers**, even for things you type yourself. Never treat a demo result as
  real threat intelligence.

### Limits of the dashboard

- **The Overview is worked out again on every request.** It reads only the 2,000 newest provider
  answers and the last 14 days (up to 20,000 lookups and 20,000 new indicators). The page says when it
  had to stop early. That is fine for a personal database. A busy installation would need caching.
- **The look was checked by measurement.** Automatic checks measured the layout at many window sizes,
  the text contrast and that each effect really runs. No formal design review has been done.
- **The effects were not tuned for slow computers.** If the dashboard feels heavy, switch the effects
  off (see [Visual effects and small screens](#visual-effects-and-small-screens)).
- **No screen reader has been used.** The accessibility checks are automatic ones: contrast, layout
  and keyboard use.
- **The screenshots in this guide show demo data,** so their numbers are invented.

### Smaller limits

- **There is no HTTPS built in.** CipherForge speaks plain HTTP on your own computer (`127.0.0.1`).
  Anything other people can reach needs a proxy with HTTPS in front of it.
- **The rate limit lives in memory.** It is per process, it resets when the API restarts, and several
  copies of the API would not share it.
- **Only investigations are audited.** Opening a stored record is not.
- **The audit log is protected from the application, not from a database administrator.**
- **Old data is kept.** Nothing is deleted or tidied away yet.
- **Two lookups of the same new indicator at the same moment** may both ask the providers and keep two
  answers.
- **A plain `pytest` run covers SQLite only,** so it reports 198 skipped tests. See
  [Tests and quality checks](#tests-and-quality-checks).

## More documentation

This guide is the starting point. Each document below goes deeper on one subject.

| Document | What is in it |
| --- | --- |
| [docs/project-status.md](docs/project-status.md) | The history of the project, phase by phase: what each phase added and what is still missing. |
| [docs/architecture.md](docs/architecture.md) | How the pieces are built and how the planned ones would plug in, including the [threat-intelligence flow](docs/architecture.md#threat-intelligence-flow-phase-2) and the [motion layer](docs/architecture.md#aurora-forge-and-the-motion-layer). |
| [docs/api.md](docs/api.md) | Every API endpoint, with the fields it accepts and returns. |
| [docs/threat-intelligence.md](docs/threat-intelligence.md) | The two providers, caching, the [scoring rules in full](docs/threat-intelligence.md#scoring-intel-risk-v1), the [limits](docs/threat-intelligence.md#limitations) and how to add a provider. |
| [docs/security.md](docs/security.md) | Every security control, in technical detail. |
| [docs/threat-model.md](docs/threat-model.md) | A STRIDE analysis: what could go wrong and what stops it. |
| [docs/deployment.md](docs/deployment.md) | Docker Compose, what to do before exposing CipherForge to a network, Entra ID setup and what has been verified. |
| [docs/testing.md](docs/testing.md) | Every automated check and how to run it. |
| [docs/detection-engine.md](docs/detection-engine.md) | The **planned** design for detection rules. Nothing is built. |
| [docs/encryption-design.md](docs/encryption-design.md) | The **planned** design for encrypted file sharing. No encryption code exists. |
| [sensor/README.md](sensor/README.md) and [infra/README.md](infra/README.md) | Notes on the planned network sensor and Azure set-up. |

## Map data

The world map on the Overview screen is drawn from [Natural Earth](https://www.naturalearthdata.com/)
data (public domain, release v5.1.2): a grid of 2-degree squares marked land or sea, made from the
1:110m land outline, and one label point per country from the 1:50m country data. The two generated
files are saved in the project (`frontend/src/features/overview/worldMask.ts` and
`countryCentroids.ts`), so building the app and loading the page never need the internet. To make them
again, run `node scripts/build-world-data.mjs` from the `frontend` folder.

## Credits

- **[AbuseIPDB](https://www.abuseipdb.com) and [AlienVault OTX](https://otx.alienvault.com)** supply the
  threat information CipherForge shows, under their own terms of use.
- **[anime.js](https://animejs.com)** by Julian Garnier (MIT) animates the interface (version 4.5.0,
  pinned; only the parts the app uses end up in the build).
- **[21st.dev](https://21st.dev) and [GetLayers](https://getlayers.ai)** were design references for the
  "Aurora Forge" look: a spotlight card, a "tubelight" navigation bar and layered, pointer-reactive
  backgrounds are general ideas both show. No component, prompt or source from either is in this
  repository. Everything was rebuilt from scratch.
- **Fonts** (Oxanium and JetBrains Mono, SIL Open Font License) come from the `@fontsource` packages
  and are bundled, never fetched from a font host.
- **Map data:** [Natural Earth](https://www.naturalearthdata.com/). See [Map data](#map-data).

## Licence

MIT. See [LICENSE](LICENSE).

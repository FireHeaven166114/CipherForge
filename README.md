# CipherForge - Ai Enabled Advanced SOC Enigma

**Intelligence. Detection. Encryption.**

CipherForge is a small **security operations centre (SOC)** that runs on your own computer. It does
three jobs, each on its own screen of the dashboard:

- **Threat intelligence.** You give it something suspicious (an IP address, a website name, a web
  link or a file fingerprint) and it tells you **how risky that thing looks, and why**.
- **Network monitoring.** It watches the *numbers* of network traffic (who talked to whom, on which
  port, how much), live from one of your computer's network interfaces or from a capture file you
  upload, and raises an alert when the traffic looks like a port scan, a flood or a conversation with
  a known bad address.
- **Encrypted file sharing.** You upload a file, CipherForge stores it encrypted, and you hand out
  download links that expire, can be limited to a number of downloads, can need a password and can be
  revoked.

For the first job it asks four well-known security services what they know, shows their answers side
by side, turns them into **one risk score from 0 to 100** with the working shown, and keeps a
permanent record of every check. You use it in your web browser, and every time on screen is shown in
Indian Standard Time (IST).

![The CipherForge Overview screen on a desktop: a navigation rail on the left, five headline tiles, and the Threat pulse and Risk posture panels over a dark animated background](docs/screenshots/overview.png)

*The Overview screen in demo mode, so the numbers are invented. The background moves; this is one
frame. The screenshots in this guide were taken before the Network and Files screens, VirusTotal and
ThreatFox existed, so the navigation rail in them is shorter than the one you will see, the results
show two provider cards where you will see four, and any times in them are in UTC rather than IST.*

> **Use it responsibly.** Threat intelligence sends the text you type to outside services. Network
> monitoring can capture the traffic of a real network interface: use it only on systems and networks
> you own or are explicitly allowed to monitor. Encrypted file sharing is encryption on the server and
> has not had an independent security review. See [Security in plain words](#security-in-plain-words).

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
   [what happens when you delete an indicator](#what-happens-when-you-delete-an-indicator),
   [what is built and what is planned](#what-is-built-and-what-is-planned)
4. [What you need before you start](#what-you-need-before-you-start)
5. [Get it running](#get-it-running): [try it without API keys](#try-it-without-api-keys),
   [run the real application](#run-the-real-application),
   [run everything in Docker](#run-everything-in-docker)
6. [Using the dashboard](#using-the-dashboard)
7. [Using the API directly](#using-the-api-directly)
8. [Settings](#settings)
9. [Tests and quality checks](#tests-and-quality-checks)
10. [Project layout](#project-layout)
11. [Security in plain words](#security-in-plain-words)
12. [Limitations](#limitations)
13. [More documentation](#more-documentation)
14. [Map data](#map-data), [Credits](#credits) and [Licence](#licence)

Full setup instructions, environment variables and troubleshooting live in
**[docs/setup.md](docs/setup.md)**; the full dashboard walkthrough lives in
**[docs/user-guide.md](docs/user-guide.md)**.

## What is CipherForge?

### The problem

Security teams ask "is this bad?" all day long. It might be an address in a log file, a link in an
email or a file someone downloaded. Checking each one by hand on several websites is slow, and the
websites do not always agree. Reading network traffic by eye is no easier, and sending a sensitive
file by email leaves a copy of it in every mailbox on the way.

### What CipherForge does about it

**1. Threat intelligence** (the Investigate and Indicators screens)

1. You enter one **indicator**: an IP address, a domain name, a web link or a file hash (MD5, SHA-1
   or SHA-256).
2. CipherForge asks up to four outside **providers**, AbuseIPDB, AlienVault OTX, VirusTotal and
   ThreatFox, what they know. Each one is asked only about the kinds of indicator it supports.
3. It shows **each provider's answer on its own card**. If the providers disagree, you see that.
4. It combines the answers into **one score from 0 to 100** and shows the working, line by line.
5. It lists **what is not known** and suggests **next steps**.
6. It **saves** the result so you can search it later, and writes a permanent entry in an
   **audit log**.
7. When you no longer want an indicator, you can **delete** it, one at a time or a whole range at
   once. The audit log keeps a note that you did.

**2. Network monitoring** (the Network screen). You start a **live capture** on one of your
computer's network interfaces, or upload a **capture file** (PCAP or PCAPNG) that was recorded
somewhere else. CipherForge groups the packets into **flows** (one conversation between two
addresses and ports), applies seven detection rules (port scan, connection rate, SYN rate, high
volume, known malicious address, suspicious port and unexpected protocol) and lists the alerts with
the evidence behind each one. A public IP address named in an alert can be looked up with the same
four providers. It keeps only addresses, ports, protocol, sizes and times, never the content of a
packet. See [docs/network-monitoring.md](docs/network-monitoring.md).

**3. Encrypted file sharing** (the Files screen, and the public Share page that a link opens). You
upload a file and CipherForge encrypts it with AES-256-GCM, under a fresh key for every file, before
anything is written to disk. You can then create **share links** that expire, count downloads, ask
for a password and can be revoked, and the person who receives a link needs no account. Every file
and share event goes to the audit log. This is encryption on the server, not end-to-end encryption,
and the feature stays off until you set a master key. See
[docs/file-sharing.md](docs/file-sharing.md).

### The screens

| Screen | What it is for |
| --- | --- |
| **Overview** | The home screen. Live figures: how many indicators you have checked, how many look risky, a world map, trends and the latest lookups. A panel marks which modules are Live and which are Planned. |
| **Investigate** | Where you type in an indicator and read the result. |
| **Indicators** | A searchable list of everything you have checked, with a page for each one. This is also where you delete indicators you no longer want. |
| **Network** | Start and stop a live capture, upload a capture file, and read the flows and alerts of each session. |
| **Files** | Upload a file, create and revoke share links, and read what has happened to each file. |
| **Share page** | The public page that a share link opens. It needs no sign-in. It shows the file's size, when the link expires and how many downloads are left, and a download button. The file's name is shown too, except on a link that needs a password: that one says "A password-protected file" until the download succeeds. |
| **System status** | Shows whether the API is running and can reach its database. |

### What it is not

- **It is not antivirus.** It never scans your computer or your files for malware. A file hash is just
  a fingerprint that you type in, and a file you upload for sharing is only stored, encrypted. No
  file or link is ever sent to a provider to be scanned.
- **It never acts on its own.** It does not block, isolate or change anything. The network module
  watches and raises alerts; it never stops traffic. It only advises.
- **It does not give verdicts.** A score is advice based on up to four sources. You decide what to do.
- **It is not finished.** A separate network sensor, correlation across modules, cases, background
  workers and Azure deployment are planned but not built. See
  [What is built and what is planned](#what-is-built-and-what-is-planned).

### One promise: "Not assessed" never means "safe"

If no provider can answer (for example because no API key is set), CipherForge shows
**Not assessed**. It never shows "0, all clear". Nothing was checked, so nothing can be said. You
will see this wording all over the dashboard. The same rule holds in the network module: an address
that no provider knows is shown without a score, not as clean.

## Words you will see

| Word | What it means |
| --- | --- |
| **Indicator** (also **IOC**, "indicator of compromise") | One thing you want to check: an IP address, a domain, a URL or a file hash. |
| **IP address** | A number that identifies a computer on a network. **IPv4** looks like `8.8.8.8`. **IPv6** is the newer, longer kind and contains colons. |
| **Domain** | A website name such as `example.com`. |
| **URL** | A full web address such as `https://example.com/path`. |
| **File hash** (MD5, SHA-1 or SHA-256) | A fingerprint of a file, 32, 40 or 64 characters long. The same file always gives the same fingerprint, so you can ask about a file without sending the file. |
| **Defanged** | Written in a deliberately broken way, such as `hxxp://example[.]com`, so that nobody clicks it by accident. CipherForge accepts these and fixes them. |
| **Threat intelligence** | Information that other people have collected about known bad addresses, websites, files and attackers. |
| **Provider** | An outside service that CipherForge asks. There are four today: AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox. |
| **API key** | A password-like code that a provider gives you (free) so it knows who is asking. CipherForge keeps it on the server and never shows it on screen. |
| **Risk score** | CipherForge's number from 0 to 100. Higher means more evidence of danger. |
| **Classification** | The score put into a named band: Informational, Low, Medium, High or Critical. |
| **Confidence** | How much fresh evidence stands behind the score. It is **not** the chance that the indicator is bad. |
| **Not assessed** | No provider answered, so nothing can be said. It is not the same as safe. |
| **Cache** | Saved answers that CipherForge reuses for a few hours (the time differs by provider), so it does not ask the providers again and again and use up your daily allowance. |
| **Audit log** | A permanent diary of every check, deletion, capture, upload and share event: what, when and by whom. Nothing in CipherForge can edit or delete entries, and database triggers refuse it too. |
| **Demo mode** | A special way to start CipherForge with made-up data, pretend ("simulated") providers and a pretend network, so you can explore without any keys. |
| **API** | The part of CipherForge that does the work. The dashboard and other programs talk to it. |
| **Dashboard** | The web pages you see in your browser. They show what the API sends them. |
| **Database** | Where CipherForge saves everything. **PostgreSQL** is for serious use. **SQLite** keeps everything in one file and is handy for quick tries. |
| **Terminal** | A window where you type commands. On Windows this guide uses PowerShell. |
| **SOC** | Security operations centre: a team that watches for attacks and responds to them. CipherForge is a small, learning-sized version of the tools such teams use. |
| **MITRE ATT&CK** | A public catalogue of attacker techniques, each with a code such as `T1059`. The Overview lists the techniques that providers mention. |
| **Capture file (PCAP)** | A recording of network traffic saved in a file (`.pcap`, `.pcapng` or `.cap`). CipherForge can analyse one without capturing anything itself. |
| **Flow** | One conversation between two addresses and ports, as CipherForge groups packets: who talked to whom, over which protocol, how much, and when. |
| **Npcap and libpcap** | The system software that lets a program read packets from a network interface: Npcap on Windows, libpcap on Linux. They are needed only for *live* capture. |
| **Master key** | The one secret that protects the keys of every encrypted file. You set it once (`CIPHERFORGE_MASTER_KEY`). If it is lost, the files cannot be read again. |
| **Share link** | A web address that lets whoever holds it download one file, until it expires, runs out of downloads or is revoked. |
| **UTC and IST** | The database and the API keep time in UTC. Everything you read on screen, and in exported text, is shown in Indian Standard Time (IST). |

## How it works

### The big picture

![How CipherForge fits together: a browser shows the dashboard; a web server (nginx or Vite) serves it and forwards API calls to the CipherForge API; the API checks who you are, validates the indicator, reuses saved answers or asks AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox, scores the result, keeps an audit trail, reads live traffic or capture files in a network monitor and encrypts uploaded files into a folder on the server; records are stored in a database; Microsoft Entra ID sign-in tokens can be validated](docs/images/architecture.svg)

**How to read the picture.** Cyan boxes are CipherForge's own parts. The six small boxes inside the
API are its building blocks, including the network monitor and the encrypted-file vault. Green boxes
are storage: the database, and the folder that holds the encrypted files. Orange boxes are outside
services that you do not control (the dashed one is used only when real Microsoft sign-in is switched
on). The amber line at the bottom lists what is not built yet. Each arrow is a question or an answer.
The API is the only part that talks to outside services, to the database and to the file folder.

**The parts, in plain words**

| Part | What it does | Where it lives in the code |
| --- | --- | --- |
| **1. Your browser** | Shows the dashboard. It is just a web page, so a browser is all you need to use CipherForge. | none |
| **2. The web server** | Serves the dashboard pages and passes requests for data on to the API. While you are trying things it is **Vite** (port 5173). In Docker it is **nginx** (port 3000). | `frontend/` (`vite.config.ts`, `nginx.conf`) |
| **3a. Gatekeeper** | Checks who you are (a sign-in token and a role) and applies limits per user, for example at most 30 investigations a minute. | `backend/app/security/` |
| **3b. Input checks** | Cleans up what you typed, works out what kind of indicator it is, and refuses private or internal addresses before anything leaves your computer. | `backend/app/services/normalization.py` |
| **3c. Intel engine** | Reuses saved answers that are still fresh, asks the providers for the rest, and scores the evidence. It also removes the indicators you choose to delete. | `backend/app/services/intel_service.py`, `backend/app/collectors/`, `backend/app/correlation/scoring.py` |
| **3d. Audit trail** | Writes down every lookup, deletion, capture, upload and share event. Database triggers refuse to change or delete these rows (a database administrator could still drop the triggers: [security.md](docs/security.md)). | `backend/app/services/audit.py` |
| **3e. Network monitor** | Reads packet headers from a network interface or from an uploaded capture file, groups them into flows, applies the detection rules and asks the intel engine about public addresses in alerts. | `backend/app/network/`, `backend/app/detection/network_rules.py` |
| **3f. File vault** | Encrypts uploaded files, writes them to a storage folder and serves share links. Needs the master key. | `backend/app/files/` |
| **4. The database** | Saves indicators, each provider's answers, the audit log, network sessions with their flows and alerts, and the records of encrypted files and share links. The encrypted file contents are kept in a storage folder next to it, not inside it. | `backend/app/models/`, `backend/alembic/` |
| **5. The providers** | **AbuseIPDB** (IP addresses only), **AlienVault OTX** (IP addresses, domains, URLs and file hashes), **VirusTotal** (IP addresses, domains, URLs and MD5, SHA-1 and SHA-256 hashes) and **ThreatFox** (IP addresses, domains, URLs and MD5 and SHA-256 hashes). | `backend/app/collectors/` |
| **6. Microsoft Entra ID** (optional) | Microsoft's sign-in service. Only when `AUTH_MODE=entra`, the API downloads Microsoft's public keys to check sign-in tokens. In the default local mode (`AUTH_MODE=dev`) there is no sign-in and you are a local developer. | `backend/app/security/auth.py` |

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
   for AbuseIPDB, 12 hours for OTX, 24 hours for VirusTotal and 6 hours for ThreatFox (you can change
   each of them).
6. **The API asks the providers for what is missing,** all at the same time, waiting at most 10
   seconds for each. A provider with no key is skipped (it shows as *Not configured*). A provider
   that cannot handle this kind of indicator is skipped too (*Not supported*: for example, AbuseIPDB
   does not take domains and ThreatFox has no SHA-1 search).
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
  + 8 points when two providers independently back each other up (16 when three or more do)
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
  with the number of community reports ("pulses") that mention the indicator. For VirusTotal it
  grows with the number of security engines that flag the indicator (an engine that says
  "malicious" counts twice as much as one that says "suspicious", and one or two engines alone are
  weak evidence). For ThreatFox it is the reporter's own confidence (0 to 100) divided by 100.
  Every provider's measure is put on the same 0-to-1 scale and each can add at most 45 points, so no
  single provider decides the result.
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

The method, with worked examples for every band, is written out in full in
[docs/threat-intelligence.md](docs/threat-intelligence.md#scoring-intel-risk-v1).

### What happens when you delete an indicator

Deleting is permanent, so it has a few safeguards. The step-by-step instructions are in
[Deleting indicators](docs/user-guide.md#deleting-indicators). Behind the scenes:

1. **You choose** one indicator or several, and press a delete button.
2. **A box asks you to confirm.** It names what is about to go, and **Cancel** is already selected,
   so pressing Enter by accident does nothing.
3. **The gatekeeper checks you,** just as for a lookup: you must be a `SecurityAnalyst` or `Admin`.
4. **The database removes everything in one go:** each chosen indicator and every provider answer
   that was saved for it. Either all of it goes or none of it does.
5. **The audit trail gets a note** for each deleted indicator: who deleted it, when, and from which
   address. Nothing already in the audit log is changed or removed.
6. **Every screen forgets the indicator:** the Indicators list, the Overview's lists and counts of
   indicators, and the indicator's own page, which now says it cannot be found.

Two things to know. **There is no undo,** because nothing is kept aside; only a database backup can
bring an indicator back. And **the audit log is not touched,** so it still holds the text of the
indicator, such as `8.8.8.8`, in its old entries. That is its job: it is the permanent record of what
was looked up and deleted. CipherForge has no feature for deleting audit entries.

### What is built and what is planned

| Area | Status |
| --- | --- |
| Threat intelligence: lookups with AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox, the cache, the score and the audit log | **Built and tested.** AbuseIPDB and OTX have been called for real; VirusTotal and ThreatFox have only been tested against hand-written sample answers, because no key was available (see [Limitations](#limitations)) |
| Deleting indicators: one at a time, a ticked range or a whole page, with a confirmation and an audit record | **Built and tested** |
| Network monitoring: live capture, capture-file analysis, flows, seven detection rules and the lookup of public addresses in alerts | **Built and tested.** Live capture was tried on Windows (with Npcap) only; the Linux path is covered by unit tests alone |
| Encrypted file sharing: AES-256-GCM, share links that expire, count downloads, take a password and can be revoked, and an audit trail | **Built and tested.** Encryption happens on the server, and no independent security review has been done |
| Times in Indian Standard Time on screen, UTC in the database and the API | **Built and tested** |
| The dashboard: Overview, Investigate, Indicators, Network, Files, the public Share page, System status, command palette and the animated "Aurora Forge" look | **Built** |
| Demo mode with simulated providers and a simulated network (for development and learning) | **Built** |
| Microsoft Entra ID sign-in checks in the API | **Built on the API side.** The dashboard cannot sign in yet, so it works with `AUTH_MODE=dev` only |
| Docker Compose stack and the automated build pipeline | **Built and checked by GitHub's automatic checks**, but never run on the author's own computer (see [Limitations](#limitations)) |
| A separate network sensor, correlation across modules, cases, background workers, Azure deployment | **Planned, not started** |

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
- **Free API keys** from AbuseIPDB, AlienVault OTX, VirusTotal and abuse.ch (for ThreatFox), only if
  you want real answers. Each one is optional and you can use any mix. See
  [Add your API keys](docs/setup.md#add-your-api-keys-optional).
- **Npcap** (Windows) or **libpcap** (Linux), only for *live* packet capture. Analysing a capture
  file needs nothing extra. See
  [Live capture prerequisites](docs/setup.md#live-capture-prerequisites-optional).
- **A master key**, only for encrypted file sharing: a random value you generate yourself. See
  [Generate the master key](docs/setup.md#generate-the-master-key-for-file-sharing).
- **Git**, only if you get the project through a Git repository.

You also need **the project folder**: the folder that contains `backend`, `frontend` and `docs`. Put
it somewhere you can find it, for example `C:\Users\you\cipherforge`. Every command in this guide
starts from that folder.

Full prerequisites, including how to check your installed versions, are in
[docs/setup.md](docs/setup.md#prerequisites).

## Get it running

There are three ways to run CipherForge. **Start with Path A.** Full step-by-step instructions for
all three paths are in [docs/setup.md](docs/setup.md); this section gives the two-minute version of
each.

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

### Try it without API keys

**Path A** runs the real application in **demo mode**: the four providers are **simulated** (nothing
is sent to AbuseIPDB, OTX, VirusTotal or ThreatFox) and the database starts pre-filled with about two
weeks of invented lookups, so every screen has something to show. The Network screen offers two
**simulated interfaces** (nothing is captured from your computer), and you can upload the invented
capture file `frontend/e2e/data/synthetic-network.pcap` to see flows and alerts. Encrypted file
sharing really works in the demo, with a throwaway master key that the demo makes for itself. No
`.env` file and no keys needed.

Terminal 1:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn devtools.demo_server:create_demo_app --factory
```

Terminal 2:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

(macOS or Linux: `python3`/`.venv/bin/python` and `npm` instead of `npm.cmd`.) Open
<http://127.0.0.1:5173>. You should see the Overview with a "simulated providers" banner, numbers on
the tiles, and **API ONLINE** in the top bar — a labelled picture of this screen is in
[docs/user-guide.md](docs/user-guide.md).

Everything in the demo is invented, including answers for anything you type yourself, so never use it
to judge a real indicator. The full explanation, exact terminal setup for both operating systems, what
the startup log should look like, and what each demo setting does are in
[docs/setup.md](docs/setup.md#path-a-try-it-without-api-keys).

### Run the real application

**Path B** is CipherForge without the pretend parts: it starts empty and every lookup is real. It
works with no API keys at all (every result then says **Not assessed**).

```powershell
Copy-Item .env.example .env
```

Open `.env`, set `DATABASE_URL=sqlite+pysqlite:///./cipherforge.db`, then in `backend`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory
```

Start the dashboard the same way as Path A, in `frontend`. Open <http://127.0.0.1:5173>: this is a
brand-new installation, so the Overview is empty and every investigation says **Not assessed** until
you add a provider key.

To get real answers, create a free account with any of the providers
([AbuseIPDB](https://www.abuseipdb.com/register), [AlienVault OTX](https://otx.alienvault.com),
[VirusTotal](https://www.virustotal.com) and [abuse.ch](https://auth.abuse.ch/), which issues the
ThreatFox key), put the key(s) in `.env` (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`,
`THREATFOX_API_KEY`) and restart the API. You can use any mix. Keep keys private: never paste them
into a chat, screenshot or commit; CipherForge keeps them server-side only and never sends them to
the browser.

Two more parts stay off until you switch them on:

- **Encrypted file sharing** needs a master key. Generate one and put it in `.env` as
  `CIPHERFORGE_MASTER_KEY`, then restart the API:

  ```powershell
  python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
  ```

  Keep a copy somewhere safe. A file that was encrypted under this key cannot be read without it,
  and there is no recovery.
- **Live packet capture** needs Npcap (Windows) or libpcap (Linux) and, on some systems, extra
  privileges. Analysing a capture file needs neither. The requirements are in
  [docs/network-monitoring.md](docs/network-monitoring.md#requirements) and the install steps are in
  [docs/setup.md](docs/setup.md#live-capture-prerequisites-optional).

Full steps (the database migration, what a brand-new installation looks like, and getting each
provider key) are in [docs/setup.md](docs/setup.md#path-b-run-the-real-application).

### Run everything in Docker

**Path C** runs the database (PostgreSQL), the API and the dashboard in containers, so you need only
Docker Desktop installed.

> **Checked by the automatic tests, not by hand.** Docker was not available where this project was
> written, so these steps have never been followed on a personal computer. GitHub's automatic checks
> do build both images and start the whole stack on Linux, and confirm the page and API answer. If
> Path C fails for you, use Path A or B and please report it. See
> [Limitations](#limitations).

```bash
docker compose up --build
```

(After copying `.env.example` to `.env` and setting a letters-and-digits-only `POSTGRES_PASSWORD`
first — PostgreSQL stores it on first start.) Open <http://localhost:3000>. Everything binds to
`127.0.0.1` only. In Docker, live packet capture is not available (the containers drop every extra
Linux privilege); uploading a capture file works, and encrypted file sharing works once
`CIPHERFORGE_MASTER_KEY` is set in `.env`. The full steps, the port table and adding API keys are in
[docs/setup.md](docs/setup.md#path-c-run-everything-in-docker); the full service breakdown, backups
and production hardening are in [docs/deployment.md](docs/deployment.md).

**Stopping and restarting.** Press `Ctrl+C` in each terminal (or run `docker compose down`). To start
again later you only need the start commands above, not the install steps. Full detail, including how
to reset the demo or start from an empty database, is in
[docs/setup.md](docs/setup.md#stop-it-and-start-it-again).

## Using the dashboard

Open <http://127.0.0.1:5173> for Paths A and B, or <http://localhost:3000> for Path C. The complete
screen-by-screen walkthrough, with a labelled picture for every screen and result type, is in
**[docs/user-guide.md](docs/user-guide.md)**.

| Screen | What it is for |
| --- | --- |
| **Overview** (`/`) | Figures, charts and a map for everything you have checked, and a panel that shows which modules are Live. |
| **Investigate** (`/investigate`) | Type in an indicator and read the result: a score, a risk band, and each provider's answer. |
| **Indicators** (`/indicators`) | A searchable list of everything you have checked. Delete one, a ticked range, or a whole page. |
| *(click any indicator)* | The saved record of one indicator. Re-check it or delete it there. |
| **Network** (`/network`) | Choose an interface and start or stop a live capture, or upload a capture file. Each session lists its flows and alerts. |
| **Files** (`/files`) | Upload a file, create and revoke share links, and read each file's activity. |
| **Share page** (`/share/<token>`) | What a link holder sees. It needs no sign-in and has no navigation menu. |
| **System status** (`/status`) | Is the API running, and can it reach its database? |

Use the menu on the left to move around (it becomes a bar along the bottom on a phone), or press
`Ctrl K` (`Cmd K` on a Mac) to open a command palette from any screen. `G` followed by `O`, `I`, `L`,
`N`, `F` or `S` jumps straight to Overview, Investigate, Indicators, Network, Files or System status.
Every screen has its own address, so you can bookmark it.

![The Indicators list, filtered to High or critical and sorted by highest risk, with eight numbered markers](docs/screenshots/tour-indicators.png)

### Deleting indicators

Delete one indicator at a time (the bin button on its row, or **Delete indicator** on its saved
record), a ticked range (hold `Shift` to select several rows), or every row on the page at once.
Deleting is permanent: a confirmation box names what will go before anything is removed, and the
audit log keeps a record of the deletion rather than losing it — CipherForge has no feature for
deleting audit entries. The full walkthrough, with every screen pictured, is in
[docs/user-guide.md](docs/user-guide.md#deleting-indicators).

### Watching a network

On **Network**, pick an interface and press start, or upload a `.pcap`, `.pcapng` or `.cap` file. A session
shows its packets, flows and alerts. Open an alert to see the rule, the numbers behind it and, for a
public address, what the providers say about it. Only one live capture can run at a time, and only
you can see, stop or delete your own sessions. Live capture needs Npcap or libpcap; see
[docs/network-monitoring.md](docs/network-monitoring.md).

### Sharing a file

On **Files**, upload a file, then create a share link for it. Choose when the link expires, how many
times it can be downloaded and whether it needs a password, and copy the link: it is shown **once**,
and CipherForge keeps only a fingerprint of it. Revoke a link at any time. Only the owner of a file
can see it or its links. See [docs/file-sharing.md](docs/file-sharing.md).

Everything else — reading a result and its score breakdown, what the provider labels mean,
shortcuts, the demo's sample values, and the visual effects — is covered screen by screen in
**[docs/user-guide.md](docs/user-guide.md)**.

## Using the API directly

The dashboard is only one way in. Everything it shows comes from the **API**, and you can call it
yourself from PowerShell, `curl` or your own scripts — handy for automation, and for seeing exactly
what the dashboard sees. (In demo mode the answers are invented, as everywhere else.)

The API has 33 endpoints today: health and readiness (2), who you are (1), threat intelligence (7),
network monitoring (12) and encrypted file sharing (8 for the owner of a file, plus 3 public ones
that a share link uses). `GET /api/v1/me` accepts any signed-in user. Everything under
`/api/v1/intel` and `/api/v1/network` needs the `SecurityAnalyst` or `Admin` role, and the file
endpoints under `/api/v1/files` accept `User`, `SecurityAnalyst` or `Admin`. The three public
endpoints under `/api/v1/shares` need no sign-in, because the share link itself is the credential.
With the default `AUTH_MODE=dev` you already have every role you need and send no token.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/intel/investigate -ContentType 'application/json' -Body '{"indicator": "8.8.8.8"}' | ConvertTo-Json -Depth 8
```

> **Always read `score.answered_sources`.** With no provider keys, the API answers `risk_score: 0`
> and `classification: "informational"` because it has no evidence at all — that is **not** "clean".
> `answered_sources: 0` means no provider answered. The dashboard makes this check for you and shows
> **Not assessed**; a script of your own must do the same.

The full endpoint list, every field, error codes, and terminal examples for deleting indicators
through the API are in **[docs/api.md](docs/api.md)**. With the API running, you can also browse it
interactively at <http://127.0.0.1:8000/docs> (disabled when `ENVIRONMENT=production`).

## Settings

CipherForge reads its settings from the `.env` file in the project folder, the one you made by copying
`.env.example`. **After you change a setting, stop the API (`Ctrl+C`) and start it again.** The
defaults lean towards safety: leaving out `ENVIRONMENT` and `AUTH_MODE` gets you `production` and
`entra`, so `.env.example` sets the relaxed values needed for local use. A wrong value stops the API
from starting, and the error names the setting but never its value.

The full reference for every setting — authentication, the database, provider API keys and rate
limits, network monitoring, encrypted file sharing, Docker-only settings, and demo/development-only
settings — is in
**[docs/setup.md](docs/setup.md#environment-variables)**; the reasoning behind each rule is in
[docs/deployment.md](docs/deployment.md). If something does not start or behave as expected, the
symptom-by-symptom table in
[docs/setup.md, Common setup problems](docs/setup.md#common-setup-problems) covers installation,
startup and dashboard issues, including freeing or changing a port.

## Tests and quality checks

You do not need any of this to *use* CipherForge. It is for people who change the code, and for anyone
who wants to know how far the results can be trusted.

The project has three layers of automated tests. The numbers change with every change to the code, so
they are not repeated here; the latest counts, and what each result does and does not prove, are in
[docs/testing.md](docs/testing.md#evidence-by-capability).

| Layer | Tool | What it checks |
| --- | --- | --- |
| Backend | pytest | The API, the input checks, the four provider adapters (run against recorded or hand-written answers, never the live services), the score, the database and its migrations, deleting indicators, the network analysis and its rules, the encrypted file sharing and the audit log |
| Frontend units | Vitest | Screens, components, helpers, the IST time display and the motion layer |
| End to end | Playwright | The finished dashboard, in a real browser, talking to the real API, including the Network, Files and Share screens |

To run the first two, from the project folder.

Windows (PowerShell):

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest

cd ..\frontend
npm.cmd run typecheck
npm.cmd run lint
npm.cmd test
```

macOS or Linux:

```bash
cd backend && .venv/bin/python -m pytest
cd ../frontend && npm run typecheck && npm run lint && npm test
```

**Some skipped tests are normal.** Most of them are the PostgreSQL copies of the database tests, which
are skipped unless you point `TEST_DATABASE_URL` at a throwaway PostgreSQL database (see
[docs/testing.md](docs/testing.md#quality-checks)). A few more are skipped when the operating system
cannot do what they need (for example, symbolic links or POSIX file permissions on Windows), and the
opt-in live tests below are skipped unless you switch them on. `python -m pytest -rs` prints the
reason for every skip.

**Two kinds of test are off by default because they touch the outside world.** One sends a single
request per provider, about `8.8.8.8`, using your own key (`CIPHERFORGE_LIVE_TESTS=1`). The other starts
a real packet capture on this computer and sends five harmless packets to a documentation-only address
(`CIPHERFORGE_LIVE_CAPTURE_TESTS=1`). Neither runs unless you ask. The commands, what each test needs
and what it prints are in [docs/testing.md](docs/testing.md#opt-in-live-tests).

The end-to-end tests are started with `npm.cmd run test:e2e` (from `frontend`). They are slow: tens of
minutes, depending on the computer. Before the first run, read
[docs/testing.md](docs/testing.md#testing-the-dashboard): it lists what to install and what each group
of tests proves. The same page lists the security scanners and the other
[quality checks](docs/testing.md#quality-checks).

**What a green result shows.** It shows that the code does what the tests expect: the backend tests
run on SQLite (and on a real PostgreSQL when one is supplied), and the end-to-end tests use the real
API with simulated providers and simulated network interfaces. It does **not** show that VirusTotal or
ThreatFox work (their adapters have only been run against hand-written sample answers; no key for
them has been tried yet), that a packet capture works on a computer other than the author's Windows
one, that Docker Desktop works on your computer (the containers have only been started by the
automatic checks on GitHub) or that the design looks good to a person.
[What a green run does not show](docs/testing.md#what-a-green-run-does-not-show) lists the gaps, and
[Evidence by capability](docs/testing.md#evidence-by-capability) says, for each feature, how far it
has been checked.

The checks also run automatically on GitHub, in `.github/workflows/ci.yml` (four jobs: backend,
frontend, dashboard end-to-end in Chromium on Linux, and a Docker build with a smoke test). Its first
run failed two of the four jobs. [What the first run on GitHub found](docs/testing.md#what-the-first-run-on-github-found)
explains the three causes, all of which are fixed. The same section records a later failure, one
browser test that assumed the page would be slower than it was on a fast runner; its fix is in the
repository and the next run on GitHub is what confirms it.

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
|   |   |-- collectors/       One file per provider: abuseipdb.py, otx.py, virustotal.py and threatfox.py
|   |   |-- correlation/      scoring.py: how the 0 to 100 score is worked out
|   |   |-- services/         The investigation steps, deleting indicators, Overview figures, audit log
|   |   |-- network/          Network monitoring: capture, reading capture files, flows, looking up addresses
|   |   |-- detection/        network_rules.py: the seven rules that raise network alerts
|   |   |-- files/            Encrypted file sharing: encryption, storage on disk, share links
|   |   |-- security/         Sign-in checks, roles and the rate limiter
|   |   |-- models/           The database tables
|   |   |-- schemas/          The exact shape of every request and reply
|   |   |-- database/         The connection to the database
|   |   |-- core/             Settings, logging, error format, request helpers, time (timeutil.py)
|   |   `-- workers/          Planned: nothing in it yet
|   |-- alembic/              Database set-up scripts, called "migrations"
|   |-- devtools/             Demo mode: demo server, made-up data, pretend providers, pretend network
|   |-- tests/                The backend tests (pytest)
|   `-- Dockerfile, requirements.txt, pyproject.toml, ...
|
|-- frontend/                 THE DASHBOARD (React, TypeScript, Vite, Tailwind)
|   |-- src/
|   |   |-- pages/            The screens: Overview, Investigate, Indicators, Network, Files, ...
|   |   |-- components/       Building blocks: cards, charts, the side rail, the Network and Files pieces, ...
|   |   |-- features/         Helper logic behind the screens' figures, and the IST time display
|   |   |-- services/         The code that talks to the API and checks replies
|   |   |-- hooks/            Small helpers that load data and keep track of ticked rows
|   |   |-- motion/           The animations (anime.js)
|   |   |-- effects/          The "Visual effects" on/off switch
|   |   |-- test/, types/     Test helpers and shared type definitions
|   |   `-- App.tsx, main.tsx, index.css
|   |-- e2e/                  The browser tests (Playwright), and a made-up capture file in e2e/data/
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
`-- sensor/                   Planned: a separate network sensor on another machine (a note only;
                              network monitoring itself already lives in backend/app/network/)
```

Some more folders appear after you run things. They are not part of the project, Git ignores them, and
you can leave them alone: `backend/.venv` (the Python packages), `frontend/node_modules` (the
JavaScript packages), `frontend/dist` (the built dashboard), `backend/.demo` (the demo database and its
demo files), `backend/data` (where the encrypted files are kept when you run the real application) and
`backend/cipherforge.db` (the database from [Path B](#run-the-real-application)).

**Where to look when you want to change something:**

| I want to... | Look here |
| --- | --- |
| Change how the score is worked out | `backend/app/correlation/scoring.py`. The dashboard's "How the score was built" panel keeps its own copy of the rules in `frontend/src/components/intel/ScorePanel.tsx`, so change that too, and the write-up in [docs/threat-intelligence.md](docs/threat-intelligence.md#scoring-intel-risk-v1). |
| Add a fifth provider | `backend/app/collectors/`. The steps are in [Adding a provider](docs/threat-intelligence.md#adding-a-provider). |
| Add or change a setting | `backend/app/core/config.py` and `.env.example`. |
| Add a database table | `backend/app/models/`, plus a new script in `backend/alembic/versions/`. |
| Change how deleting works | The rules and the database work are in `delete_indicators` in `backend/app/services/intel_service.py`, and the two routes are in `backend/app/api/v1/intel.py`. The confirmation box is `frontend/src/components/intel/DeleteIndicatorsDialog.tsx`, and the tick boxes are `frontend/src/hooks/useRowSelection.ts`. |
| Change a network detection rule, or the limit it uses | The rules are in `backend/app/detection/network_rules.py`, and their limits are settings in `backend/app/core/config.py` (for example `PORT_SCAN_THRESHOLD`). The reasoning is in [docs/detection-engine.md](docs/detection-engine.md). |
| Change how packets become flows, how a capture file is read, or how capturing starts and stops | `backend/app/network/` (`flows.py`, `pcap.py`, `capture.py` and `monitor.py`). See [docs/network-monitoring.md](docs/network-monitoring.md). |
| Change how files are encrypted or how share links work | `backend/app/files/` (`crypto.py` is the encryption; `service.py` handles uploads, share links and downloads). See [docs/encryption-design.md](docs/encryption-design.md) and [docs/file-sharing.md](docs/file-sharing.md). |
| Change how times are shown | `backend/app/core/timeutil.py` (the API's text and exports) and `frontend/src/features/time/` (the dashboard). See [Time handling](docs/architecture.md#time-handling-utc-storage-ist-display). |
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
| **Will my API keys leak?** | The keys stay on the server, in the `.env` file (which Git ignores) or in environment variables. The dashboard never receives them. The API never sends them back; it only says whether a key is set. The logs hide them. The master key that protects shared files is treated the same way. |
| **What if I type something harmful?** | Every indicator is checked before it is used: a length limit, no hidden or invisible characters, only MD5, SHA-1 and SHA-256 file hashes, and only `http` and `https` links with no password inside. Error messages never repeat what you typed. |
| **Could CipherForge be tricked into probing my own network?** | No. Private and internal addresses (such as `192.168.1.10`) and made-up endings (such as `.local`) are refused before any request is made. The server contacts only four fixed provider websites (AbuseIPDB, AlienVault OTX, VirusTotal and abuse.ch's ThreatFox) and does not follow redirects. Addresses found in network traffic follow the same rule: only public ones are ever looked up. Security people call the trick this stops "server-side request forgery". |
| **Could a provider's answer attack me?** | Answers are treated as untrusted. Only known fields are kept, sizes are capped and control characters are removed. The dashboard shows every provider word as plain text, never as page code. The only links to other websites go to pages on OTX, MITRE ATT&CK, VirusTotal, ThreatFox and Malpedia, built from strict patterns, so a provider cannot send you somewhere else; an address that a reporter supplies is shown with its `http` changed to `hxxp` and is never a link. The project's code checks, and in the Docker image a strict browser security policy (CSP), add two more layers. |
| **What if a provider is slow or sends too much?** | Each call has a time limit (10 seconds by default) and a size limit (2 MiB). If one provider fails, the other providers' answers still appear and the failure is labelled. |
| **Who can see what I look up?** | The providers: the indicator you investigate is sent to them, outside your organisation, so do not type anything you are not allowed to share. The Investigate screen says this next to the button. If you have set a key and leave `EXTERNAL_ENRICHMENT_ENABLED` on, the **public addresses found in your network traffic** are sent to them as well (the address only, never ports, volumes or packets); switch it off to stop that. CipherForge also writes each lookup, with who asked and when, to the audit log in your own database. Your browser talks only to CipherForge's own web server. No fonts, maps or analytics come from other sites, and there are no cookies. The one thing the dashboard remembers is your visual-effects switch. One thing to know: the search text on the Indicators screen is part of the web address, so it can appear in your browser history. |
| **Who is allowed to use it?** | The API has three roles: `Admin`, `SecurityAnalyst` and `User`. The investigation, indicator and network routes need `SecurityAnalyst` or `Admin`. The file routes accept all three roles, and each person sees only their own files and capture sessions: another person's get "not found", and there is no administrator override. Unknown roles are ignored. In Microsoft Entra ID mode the API checks sign-in tokens and rejects forged or unsigned ones. In `dev` mode (used in this guide) there is no sign-in, so use it only on your own computer. |
| **What if someone floods it with requests?** | Each user may start 30 investigations a minute, upload 10 files a minute and create 10 share links a minute. Looking up network addresses is limited to 4 a minute. One computer may make 30 requests a minute to share links and may guess a link's password 5 times in 15 minutes. You can change these numbers. They also protect your providers' free allowances. |
| **Can the history be altered?** | Every check, every deletion of an indicator, every capture or capture-file analysis and every file or share-link action (upload, share, download, refusal, revoke, delete) is written to the audit log, even refused checks (without the text that was refused). The database refuses to change or delete these rows, and CipherForge has no feature that does. A database administrator could still remove that protection, so for serious use copy the log somewhere the application cannot write. |
| **Could something be deleted by accident, or by someone who should not?** | Deleting always shows a box that names what will go, with **Cancel** already selected, so pressing Enter does nothing. No address or link can delete anything: only pressing the red button does. The API accepts a deletion only from a `SecurityAnalyst` or an `Admin`, only for the ids it names (there is no "delete everything that matches"), and for at most 100 at a time. Each deletion is recorded in the audit log with who did it. Any analyst may delete any indicator, and there is no undo. |
| **What if the settings are unsafe?** | In `production` mode the API refuses to start with dev sign-in, SQLite, the example password `CHANGE_ME` or `*` for CORS (the setting that decides which websites may call the API). The message names the setting and never its value. The `/docs` page is switched off too. A master key that is not a valid 32-byte value also stops the API from starting. |
| **Could CipherForge break something on its own?** | No. It reads from four providers and advises. The network monitor only listens: it never sends, blocks or changes traffic, and it never switches your network card into promiscuous mode. CipherForge never isolates or changes anything on your network or computers. The only things it removes are what you tell it to delete from its own database and its own file storage. |
| **Could the demo touch real data?** | No. Demo mode uses its own database file inside `backend/.demo/` (it refuses any other place), its providers are pretend and make no outside requests, its network interfaces are pretend (nothing is captured from your computer), its shared files are encrypted with a throwaway key, and a banner on every screen says so. |
| **What does the network monitor collect?** | Only the outline of each packet: addresses, ports, protocol, size, time and TCP flags. It never stores or shows what is *inside* a packet, such as web pages or passwords. A person starts each capture, on one chosen network card, and the data stays in your own database. An uploaded capture file is deleted as soon as it has been analysed. Finished sessions are purged after 72 hours by default (when the API starts or the session list is loaded), and you can delete one earlier. IP addresses can identify people, so use it only on networks you own or may monitor ([Responsible use](docs/security.md#responsible-use), [Data collected and privacy](docs/network-monitoring.md#data-collected-and-privacy)). |
| **Are my shared files safe?** | Each file is encrypted on the server (AES-256-GCM, with its own random key) before anything is written to disk, and that key is itself locked with a master key that you keep in `.env`. A share link is a long random secret that is stored only as a hash and shown once. A link can expire, allow a limited number of downloads, need a password and be revoked, and these rules are enforced on the server. Only the owner can see, share or delete a file; a person with the link can only download it. The honest limit: the **server** does the encrypting, so anyone who has both the master key and the storage folder can read the files, and a lost master key cannot be recovered. See [docs/encryption-design.md](docs/encryption-design.md). |
| **Will the screen mislead me?** | It is designed not to. "Not assessed" never looks like "safe". Each provider is shown separately. A country on the map is labelled "Provider-reported country", never as where the attacker is. Every chart has its exact numbers as text. |
| **Is the Docker set-up locked down?** | It is written to be: the containers run without administrator rights, drop extra Linux powers and publish ports only on `127.0.0.1`. For the same reason the container cannot capture live packets (uploading a capture file works). The automatic checks on GitHub start it and confirm that it answers, but they do not test each of these protections, and it has not been run on a personal computer (see [Limitations](#limitations)). |

**Use it responsibly.** A score describes an *address*, not a *person*. Never treat it as proof of who
did something or where they are. A network alert says that traffic *looks like* a scan or a flood; it
cannot tell a spoofed address from a real one. Capture packets, and share files, only on systems and
networks you own or have clear permission to use, and tell the people whose traffic you can see. See
[Responsible use](docs/security.md#responsible-use).

**Before you put CipherForge anywhere other people can reach**, read
[Before exposing it beyond your machine](docs/deployment.md#before-exposing-it-beyond-your-machine) and
the [Entra ID setup](docs/deployment.md#entra-id-setup-for-auth_modeentra). In short: put HTTPS (TLS)
in front of it (share links and passwords would otherwise travel in plain text), use `production` with
Entra ID sign-in, set a strong database password, keep the API keys and the master key in a secret
store and add rate limiting at the proxy. Remember that the dashboard cannot sign in yet, so it cannot
be used against such an API.

## Limitations

CipherForge is open about what it cannot do. Please read this list before you rely on it for anything
that matters. More detail is in [docs/threat-intelligence.md](docs/threat-intelligence.md#limitations),
[docs/security.md](docs/security.md) and [docs/deployment.md](docs/deployment.md#verification-status).

### Not built yet

| Missing piece | What it would do |
| --- | --- |
| **A separate network sensor** | A small program on another machine that would watch *that* machine's traffic and send the numbers to CipherForge. The network monitor that exists runs inside the API and sees only the computer that runs it (no promiscuous mode, no span ports or taps). Only a note exists, in `sensor/`. |
| **Correlation and baselines** | Learn what is normal on a network and combine several alerts, and your own logs, into one story. Today the seven network rules fire on fixed limits that you can change, and the Investigate result still says that no internal telemetry was available. |
| **Alert workflow and cases** | Give an alert a status and an owner, and follow an incident from start to finish. Today alerts are listed, explained and can be enriched, and that is all. Nothing responds to an alert automatically. |
| **End-to-end encrypted file sharing** | Encrypt in the browser, so that even the server could not read a file. The file sharing that exists encrypts on the server. The plan is in [docs/encryption-design.md](docs/encryption-design.md#planned-end-to-end-encryption). |
| **Background workers** | Refresh old answers and tidy old data by themselves, for example expired share links and leftover temporary files. A shared store such as Redis would join here. |
| **Azure deployment** | Run CipherForge in the cloud, described as code in `infra/`. |
| **Sign-in in the dashboard** | The dashboard cannot sign in to Microsoft Entra ID. It works only with `AUTH_MODE=dev`, which the API refuses in production. Against an API that needs Entra ID sign-in, every screen says "Not signed in". |

### Never tried for real

- **VirusTotal and ThreatFox have never been called for real.** No keys for them were available, so
  their code was written from the services' public API documentation and tested only against
  hand-written sample answers, and their opt-in live tests are skipped until you add a key.
  AbuseIPDB and AlienVault OTX have been called for real: the opt-in live test passed for both, and
  the author's own installation holds real answers from both. If a field is missing or renamed in an
  answer, CipherForge treats it as unknown and gives a weaker result instead of failing. **Do one real
  lookup with your own keys before you rely on the output.** Details:
  [Verification status](docs/threat-intelligence.md#verification-status).
- **Live packet capture has been run on one computer only:** the author's Windows machine with Npcap,
  without administrator rights. The Linux code path is covered by tests that use stand-ins, but no
  Linux machine was used, and macOS was not tried. Details:
  [Network monitoring: requirements](docs/network-monitoring.md#requirements).
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

- **A score is advice from up to four sources.** CipherForge has no data of your own to compare with,
  and every result says so. See [How the score is made](#how-the-score-is-made).
- **A score does not age by itself.** It is worked out again only when you investigate the indicator
  again. There are no background refreshes.
- **Provider text is written by other people.** Some of it (OTX pulse names and tags, ThreatFox
  reporter names and references, for example) is written by volunteers, and it can be wrong or out
  of date.
- **A country is what the provider says,** and it says little about who is behind an address.
- **Demo mode invents its answers and its network interfaces**, even for things you type yourself.
  Never treat a demo result as real threat intelligence, or as real network activity.

### Limits of network monitoring and file sharing

- **The network rules are simple.** They count packets, connections and ports in a time window and
  compare the count with a limit. A slow scan stays under the limit, busy but normal traffic can go
  over it, and an alert says "suspected": a faked source address cannot be told from a real one.
- **Only the outline of traffic is seen.** There is no look inside packets, so CipherForge cannot say
  what an attack contained. Only traffic that reaches the computer running the API is visible, on one
  network card at a time. Capture files are limited to 50 MB by default.
- **Looking up addresses uses your providers' free allowances.** Lookups are paced (4 a minute by
  default, 25 addresses per session), because VirusTotal's free key allows only 4 requests a minute and
  500 a day.
- **File sharing encrypts on the server, not in the browser.** It has had no independent security
  review. There is no way to change the master key without re-uploading the files, and a lost key
  cannot be recovered. A file is held in memory while it is encrypted (25 MB by default), the limits
  are counted per API process, and deleting a file is not a secure wipe.
- **Expired share links stay in the list** until the file is deleted, and a crash can leave a
  temporary file in the storage folder that only you can remove by hand. Nothing tidies either away,
  and there is no storage limit per person.
- **Part of this was tested on one kind of computer.** The network and file-sharing tests were run on
  SQLite on a Windows computer. A few of them (file permissions, symbolic links) need Linux and the
  PostgreSQL copies need a PostgreSQL database, so they are skipped there. They are meant to run in
  the automatic checks on GitHub, which have not seen this code yet.

### Limits of the dashboard

- **The Overview is worked out again on every request.** It reads only the 2,000 newest provider
  answers and the last 14 days (up to 20,000 lookups and 20,000 new indicators). The page says when it
  had to stop early. That is fine for a personal database. A busy installation would need caching.
- **The look was checked by measurement.** Automatic checks measured the layout at many window sizes,
  the text contrast and that each effect really runs. No formal design review has been done.
- **The effects were not tuned for slow computers.** If the dashboard feels heavy, switch the effects
  off (see [Visual effects and small screens](docs/user-guide.md#visual-effects-and-small-screens)).
- **No screen reader has been used.** The accessibility checks are automatic ones: contrast, layout
  and keyboard use.
- **The screenshots in this guide show demo data,** so their numbers are invented. They were taken
  before the Network and Files screens, VirusTotal and ThreatFox existed: they show two provider
  cards where the application now shows four, and their times are in UTC.

### Smaller limits

- **There is no HTTPS built in.** CipherForge speaks plain HTTP on your own computer (`127.0.0.1`).
  Anything other people can reach needs a proxy with HTTPS in front of it.
- **The rate limits live in memory.** They are per process, they reset when the API restarts, and
  several copies of the API would not share them.
- **Actions are audited, reading is not.** Investigations, indicator deletions, network captures and
  capture-file analyses, and file and share-link actions are written to the audit log. Opening a stored
  record, or listing files or sessions, is not.
- **The audit log is protected from the application, not from a database administrator.**
- **Old data is kept until you delete it,** with one exception: finished capture sessions are purged
  after 72 hours by default. You can delete indicators, capture sessions and files by hand. Nothing
  else is tidied away by itself, and the audit log cannot be deleted from at all.
- **A deleted indicator is still named in the audit log.** The audit entries keep the text of what was
  looked up and deleted, such as `8.8.8.8`, on purpose. Deleting also does not wipe copies that live
  outside the application, such as database backups.
- **Any analyst can delete any indicator.** There is no owner for an indicator, and there is no
  undo. (Capture sessions and files do have an owner, and only the owner can delete them.)
- **Two lookups of the same new indicator at the same moment** may both ask the providers and keep two
  answers.
- **A plain `pytest` run covers SQLite only,** so it reports the PostgreSQL copies as skipped. See
  [Tests and quality checks](#tests-and-quality-checks).

## More documentation

This guide is the starting point. Each document below goes deeper on one subject.

| Document | What is in it |
| --- | --- |
| [docs/setup.md](docs/setup.md) | The full step-by-step install for all three paths, every environment variable, the capture prerequisites, the master key for file sharing, and troubleshooting. |
| [docs/user-guide.md](docs/user-guide.md) | The screen-by-screen dashboard walkthrough, including the Network, Files and Share screens. |
| [docs/project-status.md](docs/project-status.md) | The history of the project, phase by phase: what each phase added and what is still missing. |
| [docs/architecture.md](docs/architecture.md) | How the pieces are built and how they fit together, including the [threat-intelligence flow](docs/architecture.md#threat-intelligence-flow-phase-2), [time handling (UTC storage, IST display)](docs/architecture.md#time-handling-utc-storage-ist-display) and the [motion layer](docs/architecture.md#aurora-forge-and-the-motion-layer). |
| [docs/api.md](docs/api.md) | Every API endpoint, with the fields it accepts and returns. |
| [docs/threat-intelligence.md](docs/threat-intelligence.md) | The four providers, caching, the [scoring rules in full](docs/threat-intelligence.md#scoring-intel-risk-v1), the [limits](docs/threat-intelligence.md#limitations) and how to add a provider. |
| [docs/network-monitoring.md](docs/network-monitoring.md) | Live capture and capture-file analysis: requirements, privileges, flows, alerts, address lookups, privacy and retention. |
| [docs/detection-engine.md](docs/detection-engine.md) | The seven network detection rules, their limits and how to change them, and what is still only planned. |
| [docs/file-sharing.md](docs/file-sharing.md) | Encrypted file sharing: uploads, share links, expiry, download limits, passwords, revocation, audit events and limits. |
| [docs/encryption-design.md](docs/encryption-design.md) | How files are encrypted and how the keys are protected, and the **planned** end-to-end design. |
| [docs/security.md](docs/security.md) | Every security control, in technical detail. |
| [docs/threat-model.md](docs/threat-model.md) | A STRIDE analysis: what could go wrong and what stops it. |
| [docs/deployment.md](docs/deployment.md) | Docker Compose, what to do before exposing CipherForge to a network, Entra ID setup and what has been verified. |
| [docs/testing.md](docs/testing.md) | Every automated check, how to run it, the opt-in live tests, and the [evidence for each capability](docs/testing.md#evidence-by-capability). |
| [sensor/README.md](sensor/README.md) and [infra/README.md](infra/README.md) | Notes on the planned separate network sensor and Azure set-up. |

## Map data

The world map on the Overview screen is drawn from [Natural Earth](https://www.naturalearthdata.com/)
data (public domain, release v5.1.2): a grid of 2-degree squares marked land or sea, made from the
1:110m land outline, and one label point per country from the 1:50m country data. The two generated
files are saved in the project (`frontend/src/features/overview/worldMask.ts` and
`countryCentroids.ts`), so building the app and loading the page never need the internet. To make them
again, run `node scripts/build-world-data.mjs` from the `frontend` folder.

## Credits

- **[AbuseIPDB](https://www.abuseipdb.com), [AlienVault OTX](https://otx.alienvault.com),
  [VirusTotal](https://www.virustotal.com) and [ThreatFox](https://threatfox.abuse.ch) (from
  abuse.ch)** supply the threat information CipherForge shows, under their own terms of use.
- **[Scapy](https://scapy.net)** (GPL-2.0-only) reads capture files and captures packets, and
  **[Npcap](https://npcap.com)** is the driver Windows needs for live capture; you install Npcap
  yourself, under its own licence. **[cryptography](https://cryptography.io)** (Apache-2.0 or
  BSD-3-Clause) supplies the AES-256-GCM and Argon2id used for file sharing.
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

MIT. See [LICENSE](LICENSE). That covers CipherForge's own code. The network module depends on Scapy,
which is GPL-2.0-only. Running the two together on your own computer is fine, but if you redistribute
CipherForge together with Scapy (a Docker image, for example), the GPL's terms apply to that
combination, so check them first. Npcap is not included. See
[Dependency management](docs/security.md#dependency-management).

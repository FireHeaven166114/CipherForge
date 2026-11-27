# Deployment

How to run CipherForge locally with Docker Compose, what to change before exposing it anywhere, and
what has and has not been verified. The stack is the dashboard behind nginx, the API (with its
network-monitoring and encrypted-file-sharing modules) and PostgreSQL. Two things need more care than
the rest: the encrypted-files volume and the master key that protects it (see
[The encrypted-files volume](#the-encrypted-files-volume), [The master key](#the-master-key) and
[Backups](#backups)), and live packet capture, which is not available in the containers (see
[Capture inside Docker](#capture-inside-docker)). The Azure deployment is **planned, not built**.

## Local stack with Docker Compose

```bash
cp .env.example .env
# Edit .env: set a random POSTGRES_PASSWORD (letters and digits only), for example
#   openssl rand -hex 24
docker compose up --build
```

Services, in start-up order:

| Service | Image | Role | Host port (loopback only) |
| --- | --- | --- | --- |
| `postgres` | `postgres:16-alpine` | Database. Data lives in the `postgres_data` volume. | `5432` (`POSTGRES_PORT`) |
| `migrate` | backend image | Runs `alembic upgrade head` once, then exits. It receives only the application, authentication, CORS and database settings: no provider keys, no master key and no volume. | none |
| `backend` | backend image | FastAPI on port 8000, as a single `uvicorn` process. Starts after the migration succeeds. The only service that holds the provider keys and the master key, and the only one that mounts the `encrypted_files` volume. | `8000` (`BACKEND_PORT`) |
| `frontend` | nginx (unprivileged) | Static app and reverse proxy to the API (see [The nginx front door](#the-nginx-front-door)). | `3000` (`FRONTEND_PORT`) |

Two named volumes hold all the state. Compose's project name is `cipherforge`, so on the host they
are called `cipherforge_postgres_data` and `cipherforge_encrypted_files`.

| Volume | Mounted by | Path in the container | What it holds |
| --- | --- | --- | --- |
| `postgres_data` | `postgres` | `/var/lib/postgresql/data` | The database: indicators and what the providers said about them, capture sessions with their flows and alerts, the file and share records, and the audit trail. |
| `encrypted_files` | `backend` | `/app/data/encrypted-files` | The encrypted file blobs. See [The encrypted-files volume](#the-encrypted-files-volume). |

Open <http://localhost:3000>. That is the dashboard: Overview, Investigate, Indicators, Network,
Files and System status, plus a public page for share links (`/share/<token>`) that needs no
sign-in. It needs the API's development authentication (the template's `AUTH_MODE=dev`), because
there is no browser sign-in yet; against an API that requires Entra tokens every screen shows
"Not signed in". `docker compose down` stops the stack and keeps the data;
`docker compose down --volumes` deletes **both** volumes: the database and every encrypted file.
File sharing stays off until you set a master key (see [The master key](#the-master-key)), and live
capture is not available in the containers (see [Capture inside Docker](#capture-inside-docker)).

### Configuration

Compose reads `.env` for substitution and passes the relevant values to the containers. The template
selects `ENVIRONMENT=development` and `AUTH_MODE=dev` so the stack works out of the box. If you omit
them entirely, the secure defaults apply and the API will refuse to start until Entra is configured.

`DATABASE_URL` is built by Compose from `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`.
Because the password sits inside a URL, keep it to letters and digits.

Compose gives the `backend` container every application setting, with the same defaults as
`backend/app/core/config.py` (a test fails if they drift apart), so the application settings in
`.env.example` take effect in the containers. Two values are fixed by Compose and ignored in `.env`:
`DATABASE_URL` (built from the `POSTGRES_*` values) and `ENCRYPTED_FILE_STORAGE_PATH` (the path of the
volume, see [The encrypted-files volume](#the-encrypted-files-volume)). `FORWARDED_ALLOW_IPS` is read
by `uvicorn`, not by the application (see
[Client address behind the proxy](#client-address-behind-the-proxy)). Every setting, with its range
and default, is listed in [`setup.md`](setup.md#environment-variables); the ones that matter for a
deployment are in [Network monitoring and file-sharing settings](#network-monitoring-and-file-sharing-settings).

### Threat-intelligence providers

Indicator investigation (Phase 2) and the enrichment of network traffic (Phase 4) query four outside
services. Each is optional and needs its own free account key, which you put in `.env`:

| Variable | Provider | Covers | Where to get a key |
| --- | --- | --- | --- |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IPv4 and IPv6 addresses | <https://www.abuseipdb.com/account/api> |
| `OTX_API_KEY` | AlienVault OTX | IP addresses, domains, URLs and MD5, SHA-1 and SHA-256 hashes | <https://otx.alienvault.com/settings> |
| `VIRUSTOTAL_API_KEY` | VirusTotal | IP addresses, domains, URLs and MD5, SHA-1 and SHA-256 hashes | <https://www.virustotal.com/gui/my-apikey> |
| `THREATFOX_API_KEY` | ThreatFox (abuse.ch) | IP addresses, domains, URLs and MD5 and SHA-256 hashes | <https://auth.abuse.ch/> |

- **No key is needed to start the stack.** A provider without a key is reported as
  `not_configured` in every investigation, never silently skipped and never counted as "clean".
- **Keys reach only the `backend` container.** The migration job and the web front end do not
  receive them, and neither does the master key (a test fails if one of the four keys or the master
  key reaches the migration job). The API never returns a key, and the log filter masks the exact
  value if it is ever written.
- **VirusTotal's free key is small, and VirusTotal remembers what you ask.** `.env.example` notes that
  the free key allows 4 requests per minute and 500 per day, and that VirusTotal keeps every
  indicator you look up with it, so do not use it for confidential indicators. Network enrichment is
  paced to stay inside that quota (`NETWORK_ENRICHMENT_MAX_PER_MINUTE`, see
  [Network monitoring and file-sharing settings](#network-monitoring-and-file-sharing-settings)).
- The remaining settings have working defaults: the cache times (`ABUSEIPDB_CACHE_TTL_SECONDS` 21600,
  `OTX_CACHE_TTL_SECONDS` 43200, `VIRUSTOTAL_CACHE_TTL_SECONDS` 86400 and
  `THREATFOX_CACHE_TTL_SECONDS` 21600 seconds); `PROVIDER_TIMEOUT_SECONDS` (10, for AbuseIPDB and
  OTX); for VirusTotal and ThreatFox their own `*_TIMEOUT_SECONDS` (15) and `*_MAX_RETRIES` (2), and
  `*_BASE_URL` values that must use `https` (plain `http` is accepted only for a loopback test
  server); and `INVESTIGATE_RATE_LIMIT_PER_MINUTE` (30 per analyst, counted in memory by each API
  process, so running several replicas multiplies it; the same budget also covers uploading a
  capture file, enriching an alert and refreshing the interface list).
- A longer cache time spends less of the free quota but shows older answers; every answer is shown
  with its age either way.

### Client address behind the proxy

The source address recorded in the audit trail comes from the `X-Forwarded-For` header set by nginx,
and the backend honours that header only from the networks in `FORWARDED_ALLOW_IPS`. Compose defaults
this to the private ranges (`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`) so the nginx container is
trusted. `uvicorn` reads this setting from the environment, not the application, and in
`.env.example` it is a commented-out, Compose-only value. The same address decides which client a
visitor to a public share link counts as: the link rate limit is kept per client network and the
wrong-password budget per link and client network (an IPv6 client counts as its /64). Three things
follow:

- If you put a TLS-terminating proxy in front of nginx, nginx sees the proxy as the client and the
  audit trail records the proxy's address. For share links the effect is larger: every visitor then
  counts as one client, so they share a single rate limit and a single wrong-password budget.
  Configure nginx's `real_ip` module for that proxy, or accept it. This stack does not do either for
  you.
- Do not publish the backend port (8000) beyond loopback. A caller inside the trusted ranges that
  reaches the backend directly can choose the address that gets recorded, and the client network it
  is counted under. The recorded value is still checked to be a valid IP address, and the audited
  user always comes from the token.
- Keep `FORWARDED_ALLOW_IPS` to the addresses of your own proxy. Do not set it to `*`, which would
  let any client choose the address it appears to come from.

### Network monitoring and file-sharing settings

Compose passes these to the `backend` container with the defaults shown. Only the settings that
matter when you deploy are listed; the full list, with ranges, is in
[`setup.md`](setup.md#environment-variables). What the network settings do is explained in
[`network-monitoring.md`](network-monitoring.md) and the file-sharing settings in
[`file-sharing.md`](file-sharing.md).

| Setting | Default | Why it matters for a deployment |
| --- | --- | --- |
| `CIPHERFORGE_MASTER_KEY` | blank (file sharing off) | See [The master key](#the-master-key). |
| `MAX_ENCRYPTED_FILE_SIZE_MB` | 25 (1 to 100) | The largest upload. A file is encrypted in memory, so keep it modest. The proxy body limit must be at least this. |
| `NETWORK_MAX_PCAP_SIZE_MB` | 50 (1 to 500) | The largest capture file accepted for analysis. The proxy body limit must be at least this. |
| `NETWORK_RETENTION_HOURS` | 72 (1 to 2160) | How long capture sessions are kept; their flows and alerts go with them. See [Retention and deletion](network-monitoring.md#retention-and-deletion). |
| `EXTERNAL_ENRICHMENT_ENABLED` | `true` | Allows the public addresses seen in traffic to be looked up with the configured providers. Private, loopback and other non-public addresses are never sent. Set it to `false` to keep captured addresses away from third parties. See [External IP enrichment](network-monitoring.md#external-ip-enrichment). |
| `NETWORK_ENRICHMENT_MAX_IPS`, `NETWORK_ENRICHMENT_MAX_PER_MINUTE` | 25, 4 | Cap the lookups per session and per minute. The default pace stays inside VirusTotal's free quota; raise it only if your keys allow more. |
| `MAX_ACTIVE_FLOWS`, `MONITORING_BUFFER_SIZE`, `NETWORK_MAX_STORED_FLOWS` | 10000, 10000, 20000 | Bounds on the flows tracked at once, the packets waiting to be processed (when the buffer is full, new packets are dropped and counted) and the flow rows kept per session. |
| `DEFAULT_SHARE_EXPIRY_HOURS`, `MAX_SHARE_EXPIRY_HOURS`, `MAX_SHARE_DOWNLOADS` | 24, 720, 100 | The default lifetime of a share link and the ceilings a user may choose. The default must not exceed `MAX_SHARE_EXPIRY_HOURS`, or the API does not start. |
| `FILE_UPLOAD_RATE_LIMIT_PER_MINUTE`, `SHARE_CREATE_RATE_LIMIT_PER_MINUTE`, `SHARE_DOWNLOAD_RATE_LIMIT_PER_MINUTE`, `SHARE_PASSWORD_ATTEMPT_LIMIT` | 10, 10, 30, 5 (wrong passwords per link in 15 minutes) | Counted in memory by each API process, so they hold only with one API process (see [Before exposing it beyond your machine](#before-exposing-it-beyond-your-machine)). |
| `APP_TIMEZONE` | `Asia/Kolkata` | The only accepted value. Times are stored in UTC and shown in IST (see [Time handling](architecture.md#time-handling-utc-storage-ist-display)). The image gets `tzdata` from `backend/requirements.txt`, so the slim base image needs nothing extra. |

The detection thresholds (`PORT_SCAN_*`, `CONNECTION_RATE_*`, `SYN_RATE_*`, `SUSPICIOUS_PORT*`,
`HIGH_VOLUME_*`, `EXPECTED_PROTOCOLS` and `KNOWN_MALICIOUS_MIN_SCORE`) are development starting
points: tune them to the network you monitor, as described in
[`detection-engine.md`](detection-engine.md#thresholds-and-settings).

### The encrypted-files volume

The `backend` container writes encrypted file blobs to `/app/data/encrypted-files`, which Compose
mounts from the named volume `encrypted_files`. Compose sets `ENCRYPTED_FILE_STORAGE_PATH` to that
path itself and ignores any value in `.env`; the template's `data/encrypted-files` (relative to the
`backend` folder) is the path for an API run directly on the host.

- **The only writable places.** The backend's root filesystem is read-only (a test keeps it so), so
  this volume and the `/tmp` tmpfs are the only places the API can write.
- **Ownership.** The API runs as the non-root user `cipherforge` (uid and gid 10001). The image creates
  the directory owned by that user with mode `0700`, and Docker initialises a new, empty named volume
  from the image's directory, owner and mode included. An existing volume, or a bind mount to a host
  folder, keeps its own owner: it must be writable by uid 10001 and should have mode `0700`, or
  uploads fail with `503 storage_unavailable`. If the directory is more permissive than `0700` the
  API tries to tighten it and logs a `storage_directory_permissive` warning when it cannot.
- **Nothing is created until it is needed.** Without a master key the directory is never touched.
- **What is in it.** Ciphertext blobs with random names (the design is in
  [`encryption-design.md`](encryption-design.md)). The owner, size, wrapped key and encrypted file
  name of each file are in the database, so the volume and the database must be backed up together
  (see [Backups](#backups)). A blob cannot be read without the master key, but it is still your
  users' data: treat the volume and its backups as sensitive.
- **No quota.** The only limit is the size of one upload (`MAX_ENCRYPTED_FILE_SIZE_MB`). Nothing
  deletes expired links or old files automatically
  ([Storage and cleanup](file-sharing.md#storage-and-cleanup)), so watch the free space on the volume.

### The master key

`CIPHERFORGE_MASTER_KEY` protects every stored file: it wraps each file's own key and is part of the
key of every password-protected link, and the fingerprint stored with each file is computed with it.
One key does all of these jobs; it is not split into separate keys (see
[`encryption-design.md`](encryption-design.md#the-master-key)). It is 32 random bytes,
base64url-encoded.

- **File sharing needs it; nothing else does.** While it is blank the feature is off: the Files page
  shows a notice instead of the upload form and the file endpoints answer `503 feature_not_configured`.
  A value that is set but malformed stops the API from starting.
- **Where it comes from.** In production, from a secret store or a protected environment (Key Vault,
  or your orchestrator's secrets), not from a file in the repository. Compose reads it from the shell
  environment or from `.env`, which is git-ignored.
- **It must never be baked into an image or committed.** Do not put it in a Dockerfile, a build
  argument, an image layer, `docker-compose.yml`, a CI log or Git. The backend image's build context
  excludes `.env` (`backend/.dockerignore`), the key reaches a container only when it runs, and only
  the `backend` container gets it: a test fails if it reaches the `migrate` job.
- **Generate it** with the command in
  [`setup.md`](setup.md#generate-the-master-key-for-file-sharing).
- **Back it up, apart from the data.** Without the exact key the files cannot be decrypted, and there
  is no escrow or recovery: losing the key loses the files. Keep a copy in your secret store,
  separate from the database and volume backups, so that a stolen backup of the volume is only
  ciphertext.
- **There is no key rotation yet.** There is no tool to re-wrap existing files under a new key.
  Replacing the key makes every existing file answer `503 encryption_key_mismatch` until the original
  key is put back.

### The nginx front door

The `frontend` container serves the dashboard and proxies `/api/`, `/health` and `/ready` to the
backend. Its configuration is `frontend/nginx.conf`. These parts matter for a deployment:

| Request | Body limit | Request buffering | Why |
| --- | --- | --- | --- |
| `/api/v1/files` and `/api/v1/network/pcap` (exact paths: the two upload endpoints) | `500m` | Off | At least the largest value the backend settings accept (`NETWORK_MAX_PCAP_SIZE_MB` up to 500, `MAX_ENCRYPTED_FILE_SIZE_MB` up to 100); the backend enforces the limit actually configured. With buffering off, nginx passes the body on as it arrives, so the API can refuse an upload (not signed in, too large) before the rest is sent, and nginx does not write the upload to disk. |
| Everything else | `64k` | On, in memory | The rest of the API takes small JSON documents, so a small limit keeps oversized bodies away from the API. The body buffer is as large as the limit, so a request body such as a share password is held in memory and never written to a temporary file. |

- **The proxy limit must be at least the largest permitted upload.** If you raise
  `MAX_ENCRYPTED_FILE_SIZE_MB` or `NETWORK_MAX_PCAP_SIZE_MB`, every proxy in front of the API must
  allow bodies that large on those two paths (the bundled nginx already allows up to the largest
  value those settings accept). A proxy with a smaller limit refuses the upload with its own `413`
  before the API sees it.
- **Downloads are not spooled.** Both API locations set `proxy_max_temp_file_size 0`, so a decrypted
  download is never written to nginx's temporary directory. Do not let a proxy in front of nginx
  buffer responses to disk for the same reason.
- **Headers.** nginx sets the Content-Security-Policy and the other security headers once (see
  [HTTP hardening](security.md#http-hardening)). It does not set `Strict-Transport-Security`, which
  belongs on the TLS layer in front of it.

**Share tokens and the logs.** A share link carries its secret in the path (`/share/<token>` in the
browser, `/api/v1/shares/<token>` at the API), and anyone who sees the URL can use the link.

- nginx's **access** log replaces everything after `/share/` and `/api/v1/shares/` with
  `[redacted]`, so the token never appears there. The API also masks share tokens in its own request
  logs (`cipherforge.http` and `uvicorn.access`).
- The nginx **error** log is not redacted. A failed request can put the whole request line, token
  included, in it: when this was tried, a share URL requested while the backend was down produced a
  `502` and appeared in the error log in full (see [Verification status](#verification-status)).
  Restrict who can read that log and how long it is kept.
- Anything else in front of nginx or beside it may log the full URL as well: a TLS terminator, load
  balancer, API gateway, CDN, web application firewall, or a monitoring or log-shipping agent that
  records requests. This stack does not control any of them. Configure each one not to log, or to
  mask, the path of `/share/` and `/api/v1/shares/` requests before you rely on links staying secret.

### Capture inside Docker

**Live packet capture is not available in the containers. Analysing an uploaded capture file is.**

- **Why live capture is out.** The `backend` container drops every Linux capability
  (`cap_drop: ALL`) and has a read-only root filesystem, and capturing from an interface needs
  raw-socket privileges that this removes. The Compose file has no capture-enabled variant, and this
  guide does not describe one.
- **What works.** Uploading a `.pcap`, `.pcapng` or `.cap` file needs no capture driver and no extra
  privileges (see [Analysing a capture file](network-monitoring.md#analysing-a-capture-file)). The
  upload is spooled to a private folder under `/tmp`, which Compose mounts as a `tmpfs` with no size
  set. A tmpfs is held in memory, so a file being analysed takes memory up to
  `NETWORK_MAX_PCAP_SIZE_MB`. The spool is deleted after the analysis, and one left behind by a crash
  is removed at the next start once it is 24 hours old.
- **Live capture** needs the API on a host that has the interface, with the capture driver and the
  privileges described in [Network monitoring: requirements](network-monitoring.md#requirements) and
  [privileges](network-monitoring.md#privileges); the install steps are in
  [`setup.md`](setup.md#live-capture-prerequisites-optional) and are not repeated here. Run only one
  API against a database at a time: each API process has its own file directory, rate limits and
  capture slot.

### Migrations

Schema changes are applied by the one-shot `migrate` service, never by the API at start-up. The
current head is `0005_encrypted_files`: five migrations take an empty database to the current schema
(what each one does is in [`setup.md`](setup.md#the-five-migrations)). `backend` starts only after
`migrate` has exited successfully, so a failed migration stops the stack at that point; read the
reason with `docker compose logs migrate`. To run them by hand: `docker compose run --rm migrate`.
To see which version a database is at: `docker compose run --rm migrate alembic current`. Create a
new migration from the backend directory with `alembic revision -m "describe the change"` and review
it before committing.

Back up the database **before** you start new code against an existing database:
`docker compose up --build` runs any new migration as soon as the images are built (see
[Back up before you update](setup.md#back-up-before-you-update)). Two downgrades destroy data:
going back from `0005` drops the file and share records, so the encrypted blobs stay on the volume
but can never be opened again, and going back from `0004` drops the three network tables. Read
[Go back to an earlier version](setup.md#go-back-to-an-earlier-version) before you downgrade.

### Backups

A backup you can restore from has three parts, and they have to belong together:

| Part | Where it is | Without it |
| --- | --- | --- |
| The database | The `postgres_data` volume. | Everything the application stores is gone: indicators, capture sessions, the records of who owns which file and link, and the audit trail. |
| The encrypted files | The `encrypted_files` volume (`/app/data/encrypted-files` in the `backend` container). | The file records survive but their content does not. A download that finds its blob missing answers `409 file_unavailable` and the file is quarantined for good (see [Integrity failures](file-sharing.md#integrity-failures)). |
| The master key | Your secret store (see [The master key](#the-master-key)). | The files cannot be decrypted, by anyone. Losing the key is unrecoverable: there is no escrow and no key rotation yet. A different key makes every file answer `503 encryption_key_mismatch`. |

If you do not use file sharing, only the database matters. If you do, take the database and the files
from the same moment: stop the API first, because a file added or deleted between the database dump
and the volume copy leaves a record without its blob, or the reverse. These commands have **not been
run** (see [Verification status](#verification-status)); the `pg_dump` line is the one
[`setup.md`](setup.md#back-up-before-you-update) uses.

```bash
docker compose stop backend

# The database
docker compose exec postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > backup.sql

# The encrypted files: a throwaway container mounts the volume read-only and writes a tar archive
docker run --rm -v cipherforge_encrypted_files:/data:ro -v "$(pwd)":/backup alpine tar czf /backup/encrypted-files.tgz -C /data .

docker compose start backend
```

Run them in a Linux or macOS shell, or in WSL on Windows: Windows PowerShell 5.1 saves the dump in a
format that `psql` cannot read. The volume name starts with the Compose project name
(`cipherforge_`; `docker volume ls` shows it). The master key is in neither file: keep a copy in the
secret store, apart from both.

Treat both files as sensitive and keep them out of the project folder. The dump holds the audit
trail, the network metadata that was captured, and the file and share records. The archive holds the
encrypted blobs: ciphertext, but still your users' data. Keeping the master key away from both means
a stolen backup is only ciphertext.

**Restoring.** No restore commands are given here, because none has been tried. Put back the dump and
the files from the same backup and use the master key that was in use then. Do that before the
`backend` starts: a download that finds a blob missing quarantines the file, and restoring the blob
afterwards does not clear that. The restored directory must be writable by uid 10001 and have
mode `0700` (see [The encrypted-files volume](#the-encrypted-files-volume)).

There is no automated backup yet, and nothing manages how long backups are kept. Apart from capture
sessions (see `NETWORK_RETENTION_HOURS`), nothing the application stores is removed automatically.

## Before exposing it beyond your machine

This stack is a development and demonstration setup. Before it faces a network:

1. **Terminate TLS in front of it** (a reverse proxy, Azure Front Door or Application Gateway) and
   have that layer set `Strict-Transport-Security`. The stack itself speaks plain HTTP, so without
   TLS the bearer tokens, share links and share passwords cross the network in clear text.
2. **Set `ENVIRONMENT=production` and `AUTH_MODE=entra`**, with a real Entra app registration (below).
   The API refuses to start in production with dev auth, SQLite or the template password. Until
   browser sign-in is built, the dashboard cannot be used against such an API.
3. **Use a strong, unique database password** and keep `.env` out of version control. In Azure, use
   Key Vault and managed identities instead of a file.
4. **Do not publish the database port, and keep the backend port on loopback.** Remove the `postgres`
   `ports` entry if you do not need host access. Anything that can reach port 8000 directly can
   choose the client address that is recorded and rate-limited (see
   [Client address behind the proxy](#client-address-behind-the-proxy)).
5. **Add rate limiting at the proxy.** The API limits investigations per analyst (the same budget
   covers uploading a capture file, enriching an alert and refreshing the interface list), file
   uploads, share-link creation, requests to a public share link, and wrong share passwords. All of
   it is counted in memory by each API process (item 8), and every other request is unlimited. Use a
   shared limiter at the proxy: the per-process limits multiply with every extra API process.
6. **Keep the provider keys and the master key in a secret store** (Key Vault in Azure), give them to
   the backend only, and rotate a provider key if it leaks. The master key cannot be rotated yet (see
   [The master key](#the-master-key)). Review the provider terms for your use before sending real
   indicators, and decide whether captured traffic may be looked up with outside providers at all:
   `EXTERNAL_ENRICHMENT_ENABLED=false` switches that off.
7. **Monitor and back up.** Ship the logs somewhere durable (item 10) and back up the database, the
   encrypted-files volume and the master key together (see [Backups](#backups)). The `audit_logs`
   table is append-only through the application and database triggers, but a database superuser can
   still remove it or its triggers: restrict who has that role, and back it up.
8. **Run exactly one API process.** The rate limiters, the wrong-password budget, the one live capture
   and the one capture-file analysis live in the memory of a single process. Do not add `--workers` to
   the `uvicorn` command or run replicas of `backend`: each would keep its own counters, so every
   limit would be multiplied, and could start its own capture (see
   [Concurrency and limits](architecture.md#concurrency-and-limits)).
9. **Set `FORWARDED_ALLOW_IPS` to your own proxy**, and if a TLS proxy sits in front of nginx,
   configure nginx's `real_ip` module for it (see
   [Client address behind the proxy](#client-address-behind-the-proxy)).
10. **Decide where the logs go and who reads them.** Compose defaults `LOG_FORMAT` to `json` (the
    template sets `console`) and keeps at most three files of 10 MB per service for each container's
    output. The API masks the provider keys, the master key, the database password and share tokens
    in what it writes, and nginx's access log redacts share tokens. The nginx error log, and
    anything in front of nginx, can still contain a full share URL (see
    [The nginx front door](#the-nginx-front-door)): restrict who reads them, and configure the other
    layers not to log those paths.
11. **Migrate to the current head before the new code runs.** The head is `0005_encrypted_files`.
    Back up the database first: `docker compose up --build` runs the migration before the API starts
    (see [Migrations](#migrations)).
12. **Set `NETWORK_RETENTION_HOURS`** (default 72) to the longest you are willing to keep captured
    metadata. Finished sessions older than that are deleted with their flows and alerts when the API
    starts and when the session list is loaded (at most every ten minutes), and an owner can delete a
    session at any time. Indicators that enrichment created are not deleted with a session (see
    [Retention and deletion](network-monitoring.md#retention-and-deletion)).
13. **Plan for file clean-up and disk space.** Expired links and files that nobody deleted stay until
    their owner deletes them, a `.tmp-*` blob left by a crash must be removed by hand, and there is no
    quota (see [Limitations](file-sharing.md#limitations)). Watch the free space on the
    `encrypted_files` volume.
14. **Keep the proxy body limit at least as large as the biggest upload.** Compare every proxy in
    front of the API with `MAX_ENCRYPTED_FILE_SIZE_MB` and `NETWORK_MAX_PCAP_SIZE_MB` (see
    [The nginx front door](#the-nginx-front-door)).
15. **Wire up health checks.** `/health` answers 200 while the process runs, with no dependencies.
    `/ready` checks the database only and answers 503 while it is unreachable. Neither checks the
    encrypted-files volume or the master key, and both answer without a sign-in. The container
    healthchecks use `/health` (API) and `/nginx-health` (nginx).
16. **Know what the CI `docker` job proves.** It builds the images, starts the stack with the
    template values and checks a few paths. It does not exercise capture, uploads, share links, TLS,
    log redaction or production authentication (see [Verification status](#verification-status)).

## Entra ID setup (for `AUTH_MODE=entra`)

The API validates v2.0 access tokens issued by your tenant. In the Entra admin centre:

1. Register an application that represents the API.
2. Make it issue **v2.0 access tokens** (set the requested access token version to 2 in the app
   registration's manifest).
3. Define **app roles** with the values `Admin`, `SecurityAnalyst` and `User`, and assign them to
   users or groups. The API reads them from the token's `roles` claim and ignores unknown values.
4. Set `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` (and `ENTRA_AUDIENCE` if your tokens use a different
   audience) in the environment.

Browser sign-in (MSAL) is not part of the frontend yet, so tokens must currently be obtained by
other means when testing against a real tenant, and the dashboard shows "Not signed in" against such
an API. This path has not been exercised against a real
tenant; it is covered only by tests that use generated signing keys.

## Azure (planned, not built)

The intended shape, from the project specification: Azure Container Apps or App Service for the
containers, Azure Database for PostgreSQL, Blob Storage for encrypted files, Key Vault for
server-side secrets, Entra ID for identity, and Azure Monitor / Application Insights for telemetry,
described as infrastructure as code (Bicep or Terraform) in `infra/`. None of it exists yet: `infra/`
holds only a README.

What runs today instead: encrypted files are blobs in a local directory (the `encrypted_files`
volume under Compose, see [The encrypted-files volume](#the-encrypted-files-volume)), not in Blob
Storage, and the provider keys and `CIPHERFORGE_MASTER_KEY` come from the environment, not from Key
Vault. Master-key rotation is not built either. The full list of gaps is in
[Not implemented yet](security.md#not-implemented-yet).

## Verification status

What was actually run while building Phases 1 to 4, and what was not. The machine the project was
built on had no Docker, so the images and the Compose stack were not built or started there. The CI
`docker` job, on a GitHub-hosted Linux runner, is the only place they have been built and started,
and no run on a personal computer is recorded. Phase 4 changed `docker-compose.yml`,
`backend/Dockerfile` and `frontend/nginx.conf` (the `encrypted_files` volume, the two upload
locations, the new settings). The `docker` job covers those changes only for a commit that contains
them, and GitHub shows its result for each commit: this page does not.

Rows that describe a manual run or a one-off check (PostgreSQL, the live provider calls, live
capture, the nginx builds, `actionlint`) are the author's record of what was done at the time. The
repository keeps no log of them, so they cannot be re-checked from it. Counts of tests, run times and
coverage figures are left out on purpose, because they change with every phase: the runners print
them, and [testing.md](testing.md) says how to run each suite.

| Item | Result |
| --- | --- |
| Backend tests | They run on SQLite, and on a real PostgreSQL as well when `TEST_DATABASE_URL` is set (the PostgreSQL variants skip without it; CI sets it and uses PostgreSQL 16). A few tests skip on purpose and say why: SQLite has no `TRUNCATE`, for example. The whole suite, every PostgreSQL variant included, also ran on the author's machine against a local PostgreSQL 16.15, and none failed (see [Latest full run](testing.md#latest-full-run)); the encrypted-file tests, which release parallel downloads at the same instant, are among them. The first run of these variants in CI failed because of a fault in the test fixture, not in the application; that is fixed (see [What the first run on GitHub found](testing.md#what-the-first-run-on-github-found)), and the run after the fix passed the whole suite on Linux with PostgreSQL 16: 3702 passed, 7 skipped, 0 failed. |
| Backend static checks | `ruff check`, `ruff format --check`, `bandit` (on `app/` and on the dev-only `devtools/`) and `pip-audit` were all clean when last checked. CI runs the same four on every push, and a finding fails the job. |
| Frontend checks | Type check (the app, the build tooling and the browser tests), ESLint, the unit and component tests (which include the Network, Files and Share screens) and the production build all passed when last checked, and so did both audits: `npm audit --omit=dev` (the packages that ship) and the full `npm audit` reported no vulnerabilities on 26 November 2026. The full audit used to report an advisory in a development tool (`picomatch`, GHSA-fc5q-39xc-vjpf) that GitHub has since withdrawn, so CI still only reports that step; see [Dependency management](security.md#dependency-management). CI runs the same checks on every push. |
| Dashboard in a real browser | The Playwright suite in `frontend/e2e/` drives the production build in a real browser (Microsoft Edge on Windows, Chromium in the CI `e2e` job) against the live demo API: the real application with simulated providers and a seeded SQLite database (see [Try it without API keys](../README.md#try-it-without-api-keys)). The build is served by a small Node server standing in for nginx: it sends the headers and Content Security Policy read from `frontend/nginx.conf` and proxies `/api`, `/health` and `/ready`. Which screens and flows the specs drive, what each proves and what a green run does not show are in [Testing the dashboard](testing.md#testing-the-dashboard) and [What a green run does not show](testing.md#what-a-green-run-does-not-show). The suite does not run against PostgreSQL (the overview's queries are covered on PostgreSQL by the backend tests) or against nginx itself, and the providers are simulated, so no real provider answer was seen in the dashboard. Nobody has looked at the Phase 3c design on a screen; its checks are measurements. On GitHub the job ran all 732 tests of this version on Linux with no failure and no retry. Whether the latest commit passes the `e2e` job is shown on GitHub. Its earlier runs found problems the Windows run could not (see [What the first run on GitHub found](testing.md#what-the-first-run-on-github-found)); they are fixed. |
| Database and API on PostgreSQL | Run by hand, once, when only migrations `0001` and `0002` existed: Alembic upgrade, downgrade and upgrade again on PostgreSQL 16.2. A live server against it answered `/health`, `/ready` and `/api/v1/me`, and (without provider keys) the intel endpoints: investigate, refused private and hostile input (422, audited without the input), list, stats and an unknown id (404). The audit table refused a `DELETE`. Provider calls were not part of this check. **Not run by hand:** migrations `0003` to `0005` on PostgreSQL, and the network and file endpoints against a running server on it. Automated tests cover them: they ran against a local PostgreSQL 16.15 and run on PostgreSQL 16 in CI. `test_upgrade_downgrade_and_readiness_on_postgresql` in `backend/tests/test_migrations.py` upgrades to head, downgrades to base, upgrades again, checks that the recorded version is the head revision and that `/ready` answers 200 with the database check `ok`; the other backend tests run against PostgreSQL 16 there; and the `docker` job runs `alembic upgrade head` on an empty PostgreSQL 16. |
| Provider adapters: AbuseIPDB and AlienVault OTX | Tested through a stub HTTP transport against sample answers written by hand from each provider's documentation (they are not recordings), and also **called for real**. The opt-in live test (`backend/tests/test_live_providers.py`, switched on with `CIPHERFORGE_LIVE_TESTS=1`) passed for both, with one `8.8.8.8` lookup each, and the author's own installation database holds real stored answers from both. In the real OTX answers the pulse-level fields (`pulse_count`; each pulse's `id`, `name`, `created` and `modified`; `malware_families`; `attack_ids`) were present and populated. Endpoints, headers and the main fields were also checked against AbuseIPDB's public documentation and AlienVault's own client library. |
| Provider adapters: VirusTotal and ThreatFox | Tested through the same stub transport, only against hand-written sample answers that follow each provider's official API documentation. **Never called against the live services**: no keys were available, so their live tests were skipped. To continue, put `VIRUSTOTAL_API_KEY` and `THREATFOX_API_KEY` in the git-ignored `.env`, then run from `backend`, in PowerShell: `$env:CIPHERFORGE_LIVE_TESTS="1"; .\.venv\Scripts\python.exe -m pytest -m live -q -rs` (the bash form and what the test checks are in [Opt-in live tests](testing.md#opt-in-live-tests)). Until that has been done, treat these two adapters as unconfirmed against the real services. |
| Live packet capture | Run for real on the author's Windows machine with Npcap, **without elevation**, through the application: three interfaces, including loopback, and no capture thread left behind afterwards. Linux live capture is covered only by unit tests of its code paths (no Linux machine was used), and macOS has not been tried. It cannot run in the Docker container ([Capture inside Docker](#capture-inside-docker)). Uploading a capture file is the route there, but no upload has been run through the container stack (the CI `docker` job uploads nothing); the pieces were tested separately, the analysis by the backend tests and the nginx upload location with a stand-in backend (see the nginx row below). Drivers and privileges are in [Network monitoring: privileges](network-monitoring.md#privileges). |
| Compose and `.env.example` against the settings | A test parses both files and fails if Compose does not pass a setting to the backend, passes one the API would ignore, or uses a fallback that differs from the application's default; if `.env.example` leaves out a variable Compose passes, differs from a default, or contains a provider key or the master key; if the provider keys or the master key reach the migration job; if forwarded headers are trusted from public networks by default; or if `ENCRYPTED_FILE_STORAGE_PATH` stops being fixed to the `encrypted_files` mount or the backend's root filesystem stops being read-only. |
| nginx configuration | Exercised with two real nginx builds, each time on a copy of `frontend/nginx.conf`. **nginx 1.30.8** (Windows build), for the Phase 4 upload locations and log redaction, with a stand-in backend and a copy that differs only in the listen address, document root, access-log path, upstream and the removed Docker resolver line: `nginx -t` accepts the file and each security header appears once; 10 MB bodies to `/api/v1/files`, `/api/v1/network/pcap` and `/api/v1/files?x=1` reach the backend unchanged; 100 KB bodies to other API routes (a share route, `investigate`, a path with a trailing slash, `pcap/x`) get 413; a declared `Content-Length` of 600000000 on the two upload paths is refused with 413 at once, and a declared 70,000 on a share route too; nothing is written to nginx's temporary body folders; the access log shows `/share/[redacted]` and `/api/v1/shares/[redacted]` and never the token. **The error log is not redacted:** with the backend stopped, a share URL got 502 and the token appeared in `error.log` (see [The nginx front door](#the-nginx-front-door)). **nginx 1.30.6**, for the Phase 3 configuration, on a copy that differs only in the listen address, document root and upstream: security headers once, caching and gzip, SPA fallback, 404 for missing assets, proxying of the API with the error envelope intact, correlation-ID replacement and the 413 body limit; those checks were not repeated on 1.30.8. **Not run:** nginx inside the container image (the CI `docker` job only checks that `/ready`, `/health`, `/api/v1/me`, a page route and the CSP header come through), TLS, and any proxy in front of nginx. |
| `docker-compose.yml` | Validated against the Compose specification JSON schema. The CI `docker` job copies `.env.example` to `.env` and so starts the stack with the template values (development authentication, no master key, so file sharing is off): `docker compose up --build` started the whole stack (PostgreSQL, the migration job, the API and the dashboard behind nginx) on a GitHub runner and the smoke test passed, including for the commit that added the Phase 4 `encrypted_files` volume and settings. The job sets no master key, so file sharing is off there and the volume is mounted but never written to. **Not run on a personal computer.** |
| The encrypted-files volume | **Not run.** The volume's ownership and mode (see [The encrypted-files volume](#the-encrypted-files-volume)), a real write and read of an encrypted file inside the container, and the backup and restore commands in [Backups](#backups) have not been tried, because the CI `docker` job never sets a master key. File storage is tested by the backend tests on ordinary local directories: atomic writes, a private directory, no overwriting, missing and wrong-sized blobs, symbolic links never followed. |
| Dockerfiles | Both images are built by the CI `docker` job. Its first run failed because the frontend image type-checked files that `.dockerignore` keeps out of the image; that is fixed (see [What the first run on GitHub found](testing.md#what-the-first-run-on-github-found)). Phase 4 added the encrypted-files directory to the backend image, and the job built it on 26 November 2026. **Not built on a personal computer.** |
| GitHub Actions workflow | `actionlint` clean when last checked, including the browser end-to-end job; pinned action SHAs confirmed to match their release tags. It has run on GitHub. The first run failed two of its four jobs for three reasons (see [What the first run on GitHub found](testing.md#what-the-first-run-on-github-found)); after the fixes all four jobs passed. The first run of the network, file-sharing and four-provider work failed the backend and frontend jobs for three further reasons, which are fixed too (same section); the run after those fixes passed all four jobs. Whether the latest commit passes is shown on GitHub, not here. |
| `dependabot.yml` | Validated against its published schema. |
| Entra token validation against a real tenant | **Not tested.** |

What the CI `docker` job does, step by step (`.github/workflows/ci.yml`): it copies `.env.example` to
`.env`, validates the Compose file (`docker compose config --quiet`), builds and starts the stack
(`docker compose up --build --detach`) and waits for `/ready` through nginx on port 3000 (40
retries, 3 seconds apart). It then requests `/health` and `/api/v1/me`, a made-up page path
(`/some/spa/route`, whose answer must contain the dashboard's `<div id="root">`) and the headers of
`/`, which must include `Content-Security-Policy`. On a failure it prints the last 200 log lines of
each container, and it always ends with `docker compose down --volumes`. Because the migration job
has to finish before the API starts, a pass also means that `alembic upgrade head` ran on an empty
PostgreSQL 16. It does **not** exercise capture, uploads, share links, TLS, token redaction or
production authentication. The browser suite runs in Chromium on Linux in the separate `e2e` job.
Both jobs run on every push to `main`, on every pull request and when started by hand. What a hosted
runner cannot show is Docker Desktop on Windows or macOS, a restart with the data kept, and the
providers with real keys.
If you run Compose locally and something fails, that is more likely to be a defect in the container
files than in the application, and a report is welcome.

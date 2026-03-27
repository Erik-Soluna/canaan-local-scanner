# Canaan A15 Scanner (Air Cooling)

Web app that scans Canaan Avalon miners (A15 series) via the documented TCP API on port `4028`.

## Run (local)
1. Install deps:
   - `pip install -r requirements.txt`
2. Start server:
   - `uvicorn canaan_scanner.app.main:app --reload --host 0.0.0.0 --port 8000`
3. Open `http://localhost:8000`

## Run (Docker, Linux host)
1. Copy env template and edit secrets:
   - `cp .env.example .env`
2. Start:
   - `docker compose up -d --build`
3. Check:
   - `docker compose ps`
   - `docker compose logs -f`

By default the app listens on `http://<host>:8000`.

## Admin user (first run)
On startup, the app seeds an admin account if none exists:
- `ADMIN_USERNAME` (default: `admin`)
- `ADMIN_PASSWORD` (default: `admin`)

## Web authentication
Accounts are stored in SQLite with `pbkdf2_sha256` password hashes.

## Environment variables (optional)
- `SESSION_SECRET` (default: `dev-change-me`)
- `DB_PATH` (default: `canaan_scanner.sqlite` next to the project)
- `MINER_PORT` (default: `4028`)
- `SCAN_CONCURRENCY` (default: `20`)
- `CONNECT_TIMEOUT_S` (default: `2.0`)
- `READ_TIMEOUT_S` (default: `5.0`)
- `MAX_IPS_PER_SCAN` (default: `5000`)

## Scan results
- Hash-rate is reported as sum of `MHS av` from the miner `summary` response.
- “Online count per octet bucket” groups by the third IP octet (`C`) from your expanded `A.B.C.D` range syntax.
- “Issues” shows aggregated error counts by error type. Each device stores the first failing stage’s `error_type`; it is not a log of every TCP timeout.

### TCP read timeouts vs errors
The miner TCP API may keep the socket open until the read deadline. The scanner treats a **read timeout as success** if **any** response bytes were already received for that query; only a timeout **with zero bytes** is recorded as `read_timeout` (and similar query errors). See the Issues page in the app for the same note in context.

## GitHub deploy identity and update checks
The Docker image records a short deploy revision (build arg `GIT_SHA` / file `app/.deploy_sha`, or env `DEPLOY_SHA`). While logged in, the UI can compare that to the tip of GitHub `main` and show a banner when they differ.

- `GET /api/update-status` — JSON payload (cached GitHub SHA for `GITHUB_UPDATE_CACHE_TTL_S`, default **600** seconds).
- `GET /api/update-status?refresh=1` — same, but **forces** a fresh fetch of `main` from the GitHub API (bypasses that cache for this request). Optional `GITHUB_TOKEN` improves rate limits.

The app does **not** auto-pull or restart; redeploy using your normal process.

## HTTPS reverse proxy (optional)
For public access, terminate TLS with Caddy or nginx and proxy to `127.0.0.1:8000`.

## CI and Git workflow
- CI runs on GitHub Actions (`.github/workflows/ci.yml`) for push/PR to `main`.
- CI checks:
  - `pytest -q`
  - `docker build -f Dockerfile .`
- Contributor guidelines are in `CONTRIBUTING.md`.


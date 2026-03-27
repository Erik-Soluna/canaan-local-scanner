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
2. **Bake the git revision into the image** so Settings / update checks show a real `deployed_sha` (not `unknown`):
   - From the repo root on the server or in CI, set the build arg to the commit you are deploying:
   - `export GIT_SHA=$(git rev-parse HEAD)` then `docker compose build --build-arg GIT_SHA=$GIT_SHA`  
   - Or add `GIT_SHA=<full commit sha>` to `.env` before `docker compose build` (compose passes `build.args` from `.env`).
3. Start:
   - `docker compose up -d --build`
4. Optional: without rebuilding, set **`DEPLOY_SHA`** in `.env` to the same value as the running image’s commit; the app reads `DEPLOY_SHA` before `GIT_SHA`.
5. Check:
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
- `GIT_SHA` — used by **docker compose build** (see `docker-compose.yml` `build.args`); set to `git rev-parse HEAD` when building the image you deploy.
- `DEPLOY_SHA` — optional **runtime** override (same meaning as `GIT_SHA`); highest priority in `get_deploy_sha()`.

## Scan results
- Hash-rate is reported as sum of `MHS av` from the miner `summary` response.
- “Online count per octet bucket” groups by the third IP octet (`C`) from your expanded `A.B.C.D` range syntax.
- “Issues” shows aggregated error counts by error type. Each device stores the first failing stage’s `error_type`; it is not a log of every TCP timeout.

### TCP read timeouts vs errors
The miner TCP API may keep the socket open until the read deadline. The scanner treats a **read timeout as success** if **any** response bytes were already received for that query; only a timeout **with zero bytes** is recorded as `read_timeout` (and similar query errors). See the Issues page in the app for the same note in context.

## GitHub deploy identity and update checks
The Docker image records a short deploy revision (build arg `GIT_SHA` / file `app/.deploy_sha`, or env `DEPLOY_SHA`). While logged in, the UI can compare that to the tip of GitHub `main` and show a banner when they differ.

- `GET /settings` — web page (logged-in) showing deploy vs GitHub `main`, JSON details, and buttons to **Refresh status** (cached) or **Check again (fresh)** (`?refresh=1`).
- `GET /api/update-status` — JSON payload (cached GitHub SHA for `GITHUB_UPDATE_CACHE_TTL_S`, default **600** seconds).
- `GET /api/update-status?refresh=1` — same, but **forces** a fresh fetch of `main` from the GitHub API (bypasses that cache for this request). Optional `GITHUB_TOKEN` improves rate limits.

The app does **not** auto-pull or restart containers by itself. Redeploy using your normal process, or configure a **deploy webhook** so admins can use **Trigger deploy** on Settings: the server POSTs `{}` to that URL when GitHub `main` is ahead of this deployment (your CI or host should pull/rebuild/restart).

- **Settings (admin)** — save **Webhook URL** and optional **Secret** in the database (no `.env` required). **`DEPLOY_WEBHOOK_URL`** / **`DEPLOY_WEBHOOK_SECRET`** in the environment still work if the DB URL is empty or you want secrets only in env.
- `POST /api/trigger-deploy` — admin session only; returns **503** if no webhook URL is configured (DB or env), **409** if no update is available, **502** if the webhook HTTP call fails.
- `GET` / `POST /api/deploy-webhook-settings` — admin only; load or save the stored webhook (JSON body for POST: `webhook_url`, optional `webhook_secret`; omit `webhook_secret` to leave the current secret unchanged, send `""` with **Clear stored secret** to remove it).

## HTTPS reverse proxy (optional)
For public access, terminate TLS with Caddy or nginx and proxy to `127.0.0.1:8000`.

## CI and Git workflow
- CI runs on GitHub Actions (`.github/workflows/ci.yml`) for push/PR to `main`.
- CI checks:
  - `pytest -q`
  - `docker build -f Dockerfile .`
- Contributor guidelines are in `CONTRIBUTING.md`.


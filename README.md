# Canaan A15 Scanner (Air Cooling)

Web app that scans Canaan Avalon miners (A15 series) via the documented TCP API on port `4028`.

## Run (local)
1. Install deps:
   - `pip install -r requirements.txt`
2. Start server:
   - `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`
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
- “Issues” shows aggregated error counts by error type.

## HTTPS reverse proxy (optional)
For public access, terminate TLS with Caddy or nginx and proxy to `127.0.0.1:8000`.

## CI and Git workflow
- CI runs on GitHub Actions (`.github/workflows/ci.yml`) for push/PR to `main`.
- CI checks:
  - `pytest -q`
  - `docker build -f Dockerfile .`
- Contributor guidelines are in `CONTRIBUTING.md`.



## Per-device details
- On a scan job page, use **All devices** to list every IP (paginated), with filters. **Details** shows one machine; raw text may be truncated (Admin debug ZIP has full text).

## Updates from GitHub
- A banner may appear when GitHub main is ahead of the deployed build (SHA compare).
- **Docker:** build-arg GIT_SHA is written into the image; docker compose passes GIT_SHA from the environment when building.
- Override at runtime with DEPLOY_SHA if needed. Optional GITHUB_TOKEN helps GitHub API rate limits.
- **Server refresh:** cron or webhook: git pull and docker compose up -d --build in the repo.

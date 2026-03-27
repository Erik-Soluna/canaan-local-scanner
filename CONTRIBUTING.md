# Contributing

## Branch model
- Default branch: `main`
- Feature branches: `feature/<short-name>`
- Open pull requests into `main`

## Local development
1. Create environment and install deps:
   - `python -m venv .venv`
   - `source .venv/bin/activate` (Linux/macOS) or `.venv\\Scripts\\activate` (Windows)
   - `pip install -r requirements.txt`
2. Run app:
   - `uvicorn canaan_scanner.app.main:app --reload --host 0.0.0.0 --port 8000`
3. Run tests:
   - `pytest`

## Pull request checklist
- Keep changes focused and scoped.
- Verify app starts and key pages load (`/ranges`, `/jobs`, `/dashboard`).
- Run `pytest` locally.
- If changing deployment behavior, update `README.md`.

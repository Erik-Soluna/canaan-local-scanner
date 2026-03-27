"""Compare deployed revision to GitHub main (server-side; avoids browser CORS)."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

_GITHUB_CACHE: dict[str, object] = {"sha": None, "err": None, "ts": 0.0}
GITHUB_CACHE_TTL_S = float(os.getenv("GITHUB_UPDATE_CACHE_TTL_S", "600"))
DEFAULT_REPO = "Erik-Soluna/canaan-local-scanner"


def _env_deploy_sha(key: str) -> str | None:
    """Return a commit-ish value from env, or None if unset / placeholder."""
    v = os.getenv(key, "").strip()
    if not v or v.lower() == "unknown":
        return None
    return v[:64]


def get_deploy_sha(app_package_dir: Path) -> str:
    for key in ("DEPLOY_SHA", "GIT_SHA"):
        v = _env_deploy_sha(key)
        if v:
            return v
    p = app_package_dir / ".deploy_sha"
    if p.is_file():
        return p.read_text(encoding="utf-8").strip()[:64]
    return "unknown"


def _github_repo_path() -> str:
    return os.getenv("GITHUB_REPO", DEFAULT_REPO).strip() or DEFAULT_REPO


def fetch_github_main_sha(*, force: bool = False) -> tuple[str | None, str | None]:
    now = time.monotonic()
    if not force and (
        _GITHUB_CACHE["sha"] is not None
        and now - float(_GITHUB_CACHE["ts"]) < GITHUB_CACHE_TTL_S
    ):
        return str(_GITHUB_CACHE["sha"]), None  # type: ignore[arg-type]

    url = f"https://api.github.com/repos/{_github_repo_path()}/commits/main"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        sha = data.get("sha")
        if isinstance(sha, str) and len(sha) >= 7:
            _GITHUB_CACHE["sha"] = sha
            _GITHUB_CACHE["err"] = None
            _GITHUB_CACHE["ts"] = now
            return sha, None
        return None, "unexpected GitHub response"
    except urllib.error.HTTPError as e:
        err = f"GitHub HTTP {e.code}"
        _GITHUB_CACHE["err"] = err
        _GITHUB_CACHE["ts"] = now
        return None, err
    except OSError as e:
        err = str(e)
        _GITHUB_CACHE["err"] = err
        _GITHUB_CACHE["ts"] = now
        return None, err


def _short_sha(s: str) -> str:
    s = (s or "").strip()
    return s[:7] if len(s) >= 7 else s


def build_update_payload(deployed_sha: str, *, force_refresh: bool = False) -> dict:
    gh_sha, gh_err = fetch_github_main_sha(force=force_refresh)
    update_available = False
    if gh_sha and deployed_sha not in ("", "unknown"):
        update_available = _short_sha(gh_sha) != _short_sha(deployed_sha)

    repo = _github_repo_path()
    html_url = f"https://github.com/{repo}/commits/main"
    return {
        "deployed_sha": deployed_sha,
        "github_sha": gh_sha,
        "update_available": update_available,
        "github_error": gh_err,
        "html_url": html_url,
    }
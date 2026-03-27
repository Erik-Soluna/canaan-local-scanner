from pathlib import Path

from app.update_check import get_deploy_sha


def test_get_deploy_sha_ignores_unknown_git_sha_env_uses_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DEPLOY_SHA", raising=False)
    monkeypatch.setenv("GIT_SHA", "unknown")
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    sha = "deadbeef0000deadbeef0000deadbeef0000dead"
    (app_dir / ".deploy_sha").write_text(sha, encoding="utf-8")
    assert get_deploy_sha(app_dir) == sha[:64]


def test_get_deploy_sha_uses_real_git_sha_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DEPLOY_SHA", raising=False)
    monkeypatch.setenv("GIT_SHA", "aaaabbbbccccddddeeeeffff00001111aaaabbbb")
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / ".deploy_sha").write_text("file_sha_should_not_win", encoding="utf-8")
    assert get_deploy_sha(app_dir) == "aaaabbbbccccddddeeeeffff00001111aaaabbbb"

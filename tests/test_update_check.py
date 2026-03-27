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


def test_trigger_deploy_webhook_prefixes_http_when_scheme_missing(monkeypatch) -> None:
    captured: dict[str, str] = {}

    def fake_urlopen(req, timeout=120):
        captured["full_url"] = req.full_url  # type: ignore[attr-defined]
        return _FakeResp()

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def getcode(self) -> int:
            return 200

    monkeypatch.setenv("DEPLOY_WEBHOOK_URL", "127.0.0.1:9/webhook")
    monkeypatch.delenv("DEPLOY_WEBHOOK_SECRET", raising=False)
    monkeypatch.setattr("app.update_check.urllib.request.urlopen", fake_urlopen)

    from app.update_check import trigger_deploy_webhook

    ok, code, err = trigger_deploy_webhook("127.0.0.1:9/webhook", "")
    assert ok and code == 200 and err is None
    assert captured["full_url"] == "http://127.0.0.1:9/webhook"

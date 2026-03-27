from unittest.mock import patch


def test_devices_api_requires_auth():
    from starlette.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.get("/api/jobs/1/devices").status_code == 401


def test_update_status_requires_auth():
    from starlette.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.get("/api/update-status").status_code == 401


def test_update_status_refresh_requires_auth():
    from starlette.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.get("/api/update-status?refresh=1").status_code == 401


@patch(
    "app.update_check.fetch_github_main_sha",
    return_value=("abcdef1234567890abcdef1234567890abcd", None),
)
def test_update_status_refresh_returns_json_when_logged_in(mock_fetch):
    from starlette.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    r = c.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    assert r.status_code == 303

    r2 = c.get("/api/update-status?refresh=1")
    assert r2.status_code == 200
    body = r2.json()
    assert "deployed_sha" in body
    assert "github_sha" in body
    assert "update_available" in body
    mock_fetch.assert_called_once()
    assert mock_fetch.call_args.kwargs.get("force") is True


def test_trigger_deploy_requires_auth():
    from starlette.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    assert c.post("/api/trigger-deploy").status_code == 401


def test_deploy_webhook_settings_requires_auth():
    from starlette.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    assert c.get("/api/deploy-webhook-settings").status_code == 401
    assert c.post("/api/deploy-webhook-settings", json={"webhook_url": ""}).status_code == 401


@patch("app.main.resolve_deploy_webhook", return_value=("", ""))
@patch("app.main.get_deploy_sha", return_value="1111111111111111111111111111111111111111")
@patch(
    "app.update_check.fetch_github_main_sha",
    return_value=("2222222222222222222222222222222222222222", None),
)
def test_trigger_deploy_returns_503_when_webhook_not_configured(mock_gh, mock_deploy, mock_resolve):
    from starlette.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    r = c.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    assert r.status_code == 303

    r2 = c.post("/api/trigger-deploy")
    assert r2.status_code == 503
    body = r2.json()
    assert body.get("error") == "not_configured"


@patch("app.main.get_deploy_sha", return_value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
@patch(
    "app.update_check.fetch_github_main_sha",
    return_value=("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", None),
)
def test_trigger_deploy_returns_409_when_no_update(mock_gh, mock_deploy):
    from starlette.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    r = c.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    assert r.status_code == 303

    r2 = c.post("/api/trigger-deploy")
    assert r2.status_code == 409
    assert r2.json().get("error") == "no_update"


def test_deploy_webhook_settings_get_post_as_admin():
    from starlette.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    r = c.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    assert r.status_code == 303

    g = c.get("/api/deploy-webhook-settings")
    assert g.status_code == 200
    assert "webhook_url" in g.json()
    assert "secret_set" in g.json()

    p = c.post("/api/deploy-webhook-settings", json={"webhook_url": "http://example.test/hook"})
    assert p.status_code == 200
    assert p.json().get("ok") is True

    g2 = c.get("/api/deploy-webhook-settings")
    assert g2.json().get("webhook_url") == "http://example.test/hook"

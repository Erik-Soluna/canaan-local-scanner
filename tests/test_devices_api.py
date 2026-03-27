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

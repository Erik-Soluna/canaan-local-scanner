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

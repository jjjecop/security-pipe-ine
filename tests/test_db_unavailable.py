import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from main import app, get_session


class BrokenSession:
    # จำลองตอน Docker ปิด: คำสั่งไหนที่แตะฐานข้อมูลก็พังแบบเดียวกับของจริง
    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("connection to 127.0.0.1:5432 refused"))

        return fail


@pytest.fixture
def client():
    app.dependency_overrides[get_session] = BrokenSession
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_login_returns_503_when_database_is_down(client):
    response = client.post("/auth/login", json={"username": "admin", "password": "any-password-here"})
    assert response.status_code == 503


def test_database_error_details_are_not_sent_to_the_user(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "tmp")
    response = client.get("/projects", headers={"X-API-Key": "tmp"})
    assert response.status_code == 503
    assert "127.0.0.1" not in response.text

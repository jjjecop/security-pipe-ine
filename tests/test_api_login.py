from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_me_without_login_is_rejected():
    assert client.get("/auth/me").status_code == 401


def test_logout_without_login_is_harmless():
    assert client.post("/auth/logout").status_code == 200


def test_login_requires_username_and_password():
    assert client.post("/auth/login", json={"username": "admin"}).status_code == 422


def test_forged_session_cookie_is_rejected():
    # cookie ที่ไม่มีลายเซ็นถูกต้องจาก SESSION_SECRET ต้องใช้ไม่ได้
    client.cookies.set("vc_session", "eyJ1c2VyX2lkIjogMX0=.fake.signature")
    assert client.get("/auth/me").status_code == 401
    client.cookies.clear()
import redis
from fastapi.testclient import TestClient

import main
from auth import LoginRateLimiter
from main import app
from tests.fake_redis import FakeRedis

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


class RedisDown:
    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise redis.exceptions.ConnectionError("Redis is down")

        return fail


def test_login_is_refused_when_the_limiter_cannot_check(monkeypatch):
    # fail closed: ถ้านับครั้งที่ผิดไม่ได้ ต้องไม่ปล่อยให้เดารหัสได้ไม่จำกัด
    monkeypatch.setattr(main, "login_limiter", LoginRateLimiter(max_attempts=5, window_seconds=900, client=RedisDown()))
    response = client.post("/auth/login", json={"username": "admin", "password": "any-password-here"})
    assert response.status_code == 503


def test_login_is_blocked_after_too_many_failures(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(main, "login_limiter", LoginRateLimiter(max_attempts=5, window_seconds=900, client=fake))
    for _ in range(5):
        main.login_limiter.record_failure("testclient:admin")
    response = client.post("/auth/login", json={"username": "Admin", "password": "any-password-here"})
    assert response.status_code == 429

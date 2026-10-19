import base64
import json
from types import SimpleNamespace

import pytest
import redis
from fastapi import HTTPException
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import main
from auth import SessionStore
from tests.fake_redis import FakeRedis


class FakeDb:
    def __init__(self, users):
        self.users = {user.id: user for user in users}

    def get(self, model, user_id):
        return self.users.get(user_id)


ADMIN = SimpleNamespace(id=1, username="admin", is_active=True)


@pytest.fixture
def store(monkeypatch):
    fake = FakeRedis()
    session_store = SessionStore(ttl_seconds=60, client=fake)
    monkeypatch.setattr(main, "session_store", session_store)
    return session_store, fake


def browser(session_id):
    # จำลอง request ของเบราว์เซอร์ ที่ cookie มีรหัส session อยู่
    return SimpleNamespace(session={"sid": session_id})


def test_valid_session_returns_the_user(store):
    session_store, _ = store
    session_id = session_store.create(ADMIN.id)
    assert main.get_current_user(browser(session_id), FakeDb([ADMIN])) is ADMIN


def test_copied_cookie_stops_working_after_logout(store):
    session_store, _ = store
    session_id = session_store.create(ADMIN.id)
    stolen_copy = browser(session_id)

    main.logout(browser(session_id))

    with pytest.raises(HTTPException) as error:
        main.get_current_user(stolen_copy, FakeDb([ADMIN]))
    assert error.value.status_code == 401


def test_session_expires_on_the_server(store):
    session_store, fake = store
    session_id = session_store.create(ADMIN.id)
    fake.advance(61)
    with pytest.raises(HTTPException):
        main.get_current_user(browser(session_id), FakeDb([ADMIN]))


def test_old_cookie_with_user_id_is_not_accepted(store):
    # cookie แบบเดิมเก็บ user_id ไว้ตรงๆ ต้องใช้ไม่ได้แล้ว
    with pytest.raises(HTTPException) as error:
        main.get_current_user(SimpleNamespace(session={"user_id": ADMIN.id}), FakeDb([ADMIN]))
    assert error.value.status_code == 401


def test_redis_only_stores_a_hash_of_the_session_id(store):
    session_store, fake = store
    session_id = session_store.create(ADMIN.id)
    assert all(session_id not in key for key in fake.values)


def browser_cookie(session_id):
    # สร้าง cookie แบบเดียวกับที่ SessionMiddleware เซ็นให้เบราว์เซอร์
    data = base64.b64encode(json.dumps({"sid": session_id}).encode())
    return TimestampSigner(main.session_secret).sign(data).decode()


def test_me_works_with_a_cookie_and_fails_after_logout(store):
    session_store, _ = store
    main.app.dependency_overrides[main.get_session] = lambda: FakeDb([ADMIN])
    try:
        client = TestClient(main.app)
        client.cookies.set("vc_session", browser_cookie(session_store.create(ADMIN.id)))
        assert client.get("/auth/me").json() == {"username": "admin"}

        cookie_copy = client.cookies.get("vc_session")
        assert client.post("/auth/logout").status_code == 200
        attacker = TestClient(main.app)
        attacker.cookies.set("vc_session", cookie_copy)
        assert attacker.get("/auth/me").status_code == 401
    finally:
        main.app.dependency_overrides.clear()


def test_auth_returns_503_when_redis_is_down(monkeypatch):
    class RedisDown:
        def get(self, *args):
            raise redis.exceptions.ConnectionError("connection to 127.0.0.1:6379 refused")

    monkeypatch.setattr(main, "session_store", SessionStore(ttl_seconds=60, client=RedisDown()))
    main.app.dependency_overrides[main.get_session] = lambda: FakeDb([ADMIN])
    try:
        client = TestClient(main.app)
        client.cookies.set("vc_session", browser_cookie("any-session-id"))
        response = client.get("/auth/me")
    finally:
        main.app.dependency_overrides.clear()
    assert response.status_code == 503
    assert "127.0.0.1" not in response.text

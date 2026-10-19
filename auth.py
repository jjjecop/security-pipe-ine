import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from scan_queue import get_redis

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

def password_problem(password: str) -> str | None:
    # คืนข้อความบอกปัญหา หรือ None ถ้ารหัสผ่านใช้ได้
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"รหัสผ่านต้องยาวอย่างน้อย {MIN_PASSWORD_LENGTH} ตัวอักษร"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"รหัสผ่านต้องยาวไม่เกิน {MAX_PASSWORD_LENGTH} ตัวอักษร"
    return None

class LoginRateLimiter:
    # เก็บจำนวนครั้งที่ login ผิดไว้ใน Redis ไม่ใช่ในหน่วยความจำของ API
    # ถ้าเก็บในหน่วยความจำ แค่ restart API ตัวนับก็หาย ผู้โจมตีเดารหัสต่อได้ทันที และถ้ามี API หลายตัวก็นับแยกกัน
    def __init__(self, max_attempts: int, window_seconds: int, client=None):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.client = client

    def _redis(self):
        # สร้าง client ครั้งเดียวแล้วใช้ซ้ำ client ของ redis-py มี connection pool ในตัวและใช้พร้อมกันหลาย request ได้
        if self.client is None:
            self.client = get_redis()
        return self.client

    def _key(self, key: str) -> str:
        return f"login_failures:{key}"

    def is_blocked(self, key: str) -> bool:
        return int(self._redis().get(self._key(key)) or 0) >= self.max_attempts

    def record_failure(self, key: str):
        redis_key = self._key(key)
        client = self._redis()
        client.incr(redis_key)
        # nx = ตั้งเวลาหมดอายุเฉพาะตอนที่ key ยังไม่มี ตัวนับจึงหายเองเมื่อครบเวลานับจากครั้งแรกที่ผิด
        # ถ้าครั้งไหนตั้งไม่สำเร็จ (เช่น API ดับตรงกลาง) ครั้งถัดไปจะตั้งให้ ตัวนับจึงไม่ค้างจนล็อกตลอดไป
        client.expire(redis_key, self.window_seconds, nx=True)

    def reset(self, key: str):
        self._redis().delete(self._key(key))


class SessionStore:
    # cookie เก็บแค่รหัสสุ่ม ส่วนข้อมูลว่าเป็นใครอยู่ใน Redis
    # ถ้าเก็บ user_id ไว้ใน cookie ตรงๆ (แบบเดิม) กด logout แล้ว cookie ที่ถูกขโมยไปยังใช้ได้จนหมดอายุ
    # แบบนี้ logout หรือหมดอายุเมื่อไร ลบใน Redis แล้ว cookie นั้นใช้ไม่ได้ทันที
    def __init__(self, ttl_seconds: int, client=None):
        self.ttl_seconds = ttl_seconds
        self.client = client

    def _redis(self):
        if self.client is None:
            self.client = get_redis()
        return self.client

    @staticmethod
    def _key(session_id: str) -> str:
        # เก็บแค่ hash ของรหัส ถ้าข้อมูลใน Redis หลุด ก็เอาไปทำ cookie ที่ใช้ได้ไม่ได้
        return "session:" + hashlib.sha256(session_id.encode()).hexdigest()

    def create(self, user_id: int) -> str:
        session_id = secrets.token_urlsafe(32)
        self._redis().set(self._key(session_id), user_id, ex=self.ttl_seconds)
        return session_id

    def get_user_id(self, session_id: str) -> int | None:
        value = self._redis().get(self._key(session_id))
        return int(value) if value is not None else None

    def delete(self, session_id: str):
        self._redis().delete(self._key(session_id))

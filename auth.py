import time
from collections import defaultdict, deque
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

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
    # นับครั้งที่ login ผิดไว้ในหน่วยความจำ (หายเมื่อ restart API) พอสำหรับ API ที่รันเครื่องเดียว
    def __init__(self, max_attempts: int, window_seconds: int, clock=time.monotonic):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.clock = clock
        self.failures = defaultdict(deque)

    def _recent(self, key: str) -> deque:
        cutoff = self.clock() - self.window_seconds
        attempts = self.failures[key]
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        return attempts

    def is_blocked(self, key: str) -> bool:
        return len(self._recent(key)) >= self.max_attempts

    def record_failure(self, key: str):
        self._recent(key).append(self.clock())

    def reset(self, key: str):
        self.failures.pop(key, None)
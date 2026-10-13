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
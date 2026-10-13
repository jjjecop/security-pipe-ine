from auth import hash_password, verify_password, password_problem


def test_hash_does_not_contain_password():
    hashed = hash_password("MyPass123")
    assert "MyPass123" not in hashed
    assert hashed.startswith("$argon2id$")


def test_correct_password_is_accepted():
    assert verify_password(hash_password("MyPass123"), "MyPass123")


def test_wrong_password_is_rejected():
    hashed = hash_password("MyPass123")
    assert not verify_password(hashed, "mypass123")
    assert not verify_password(hashed, "")


def test_same_password_gives_different_hashes():
    assert hash_password("MyPass123") != hash_password("MyPass123")


def test_broken_hash_is_rejected_not_crash():
    assert not verify_password("not-a-real-hash", "MyPass123")

def test_short_password_is_rejected():
    assert password_problem("short") is not None


def test_long_passphrase_is_accepted():
    assert password_problem("ฉันชอบกินข้าวมันไก่ทุกวัน") is None


def test_password_without_symbols_is_accepted():
    assert password_problem("correcthorsebatterystaple") is None


def test_extremely_long_password_is_rejected():
    assert password_problem("a" * 129) is not None
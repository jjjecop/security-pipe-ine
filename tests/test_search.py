from fastapi.testclient import TestClient

from main import app, like_pattern

client = TestClient(app)


def test_like_pattern_wraps_text_with_wildcards():
    assert like_pattern("xss") == "%xss%"


def test_like_pattern_escapes_sql_wildcards():
    # ผู้ใช้พิมพ์ % หรือ _ มา ต้องค้นหาตามตัวอักษรนั้นจริง ๆ ไม่ใช่ wildcard
    assert like_pattern("100%") == "%100\\%%"
    assert like_pattern("CWE_79") == "%CWE\\_79%"
    assert like_pattern("a\\b") == "%a\\\\b%"


def test_search_text_too_long_is_rejected(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    response = client.get(
        "/projects/NodeGoat/findings",
        params={"q": "a" * 101},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 422
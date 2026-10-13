import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-key"}


@pytest.fixture(autouse=True)
def api_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setenv("SCAN_ALLOWED_REPO_ROOTS", str(tmp_path))
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "localhost")


def post_scan(body):
    return client.post("/scans", json=body, headers=HEADERS)


def test_scan_requires_api_key():
    response = client.post("/scans", json={"project": "Demo", "target_url": "http://localhost"})
    assert response.status_code == 401


def test_scan_without_any_target_is_refused():
    assert post_scan({"project": "Demo"}).status_code == 400


def test_repo_outside_allowed_root_is_refused():
    assert post_scan({"project": "Demo", "repo_path": "C:\\Users"}).status_code == 400


def test_missing_repo_folder_is_refused(tmp_path):
    assert post_scan({"project": "Demo", "repo_path": str(tmp_path / "missing")}).status_code == 400


def test_target_not_in_allowlist_is_refused():
    assert post_scan({"project": "Demo", "target_url": "http://192.168.1.1"}).status_code == 400


@pytest.mark.parametrize("body", [
    {"project": "Demo", "image": "--help"},
    {"project": "Demo", "image": "nginx; rm -rf /"},
    {"project": "Demo; DROP TABLE project", "target_url": "http://localhost"},
    {"project": "Demo", "scans": ["nmap"], "target_url": "http://localhost"},
])
def test_invalid_input_is_rejected_by_validation(body):
    assert post_scan(body).status_code == 422
import pytest

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)



def test_missing_api_key_is_rejected(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    response = client.get("/projects")
    assert response.status_code == 401


def test_wrong_api_key_is_rejected(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    response = client.get("/projects", headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_api_refuses_when_api_key_not_configured(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    response = client.get("/projects", headers={"X-API-Key": "anything"})
    assert response.status_code == 503

@pytest.mark.parametrize("url", ["/projects/NodeGoat/report", "/scan-jobs/1/report"])
def test_report_download_requires_api_key(monkeypatch, url):
    monkeypatch.setenv("API_KEY", "test-key")
    assert client.get(url).status_code == 401
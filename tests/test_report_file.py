from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import main


@pytest.fixture
def report(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "REPORTS_DIR", str(tmp_path))
    pdf = tmp_path / "security_report.pdf"
    pdf.write_bytes(b"%PDF-1.4")
    return SimpleNamespace(file_path=str(pdf), scan_job_id=7)


def test_report_is_downloaded_by_default(report):
    response = main.report_file_response(report, "NodeGoat")
    assert response.headers["content-disposition"].startswith("attachment;")
    assert "NodeGoat_scanjob7_security_report.pdf" in response.headers["content-disposition"]


def test_report_can_be_opened_inline_for_printing(report):
    response = main.report_file_response(report, "NodeGoat", inline=True)
    assert response.headers["content-disposition"].startswith("inline;")


def test_file_outside_reports_dir_is_refused(report, tmp_path):
    secret = tmp_path.parent / ".env"
    secret.write_text("API_KEY=x")
    report.file_path = str(secret)
    with pytest.raises(HTTPException) as error:
        main.report_file_response(report, "NodeGoat")
    assert error.value.status_code == 404


def test_report_saved_on_windows_opens_on_linux(monkeypatch, tmp_path):
    # รายงานที่สร้างตอนรันบน Windows เก็บ path เป็น reports\... แต่ Linux (Docker) ไม่ถือว่า \ เป็นตัวคั่นโฟลเดอร์
    monkeypatch.setattr(main, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(main, "REPORTS_DIR", str(tmp_path / "reports"))
    pdf = tmp_path / "reports" / "NodeGoat_20261019_103848" / "security_report.pdf"
    pdf.parent.mkdir(parents=True)
    pdf.write_bytes(b"%PDF-1.4")
    report = SimpleNamespace(file_path=r"reports\NodeGoat_20261019_103848\security_report.pdf", scan_job_id=7)
    response = main.report_file_response(report, "NodeGoat")
    assert response.status_code == 200


def test_windows_style_path_cannot_escape_reports_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(main, "REPORTS_DIR", str(tmp_path / "reports"))
    (tmp_path / "reports").mkdir()
    (tmp_path / ".env").write_text("API_KEY=x")
    report = SimpleNamespace(file_path=r"reports\..\.env", scan_job_id=7)
    with pytest.raises(HTTPException) as error:
        main.report_file_response(report, "NodeGoat")
    assert error.value.status_code == 404

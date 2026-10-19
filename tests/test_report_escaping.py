import pytest

from generate_report import env

# ชื่อช่องโหว่มาจากโค้ดที่ถูกสแกน ซึ่งคนนอกเป็นคนเขียน จึงต้องถือว่าเป็นข้อมูลอันตราย
MALICIOUS_TITLE = '<script>alert("xss")</script>'


@pytest.mark.parametrize("template_name", ["report_template.html", "dashboard_template.html"])
def test_finding_title_is_escaped_in_reports(template_name):
    finding = {
        "title": MALICIOUS_TITLE,
        "risk_score": 9.0,
        "epss_score": None,
        "tool": "semgrep",
        "severity": "high",
        "owasp_category": None,
        "cwe_id": None,
        "location_label": "code",
        "location_detail": "app.js",
        "remediation_workaround": None,
    }
    html = env.get_template(template_name).render(
        project_name="demo",
        report_date="2026-10-19 10:00",
        severity_data=[{"severity": "high", "count": 1}],
        top_findings=[finding],
    )
    assert MALICIOUS_TITLE not in html
    assert "&lt;script&gt;" in html
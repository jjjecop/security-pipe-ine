from normalizer import (
    normalize_semgrep_finding,
    normalize_trivy_finding,
    normalize_zap_finding,
)


# ---------- Semgrep ----------

def make_semgrep_raw(line, code, path="C:/repo/app/a.js"):
    return {
        "check_id": "javascript.eval-injection",
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "message": "Avoid eval",
            "severity": "ERROR",
            "lines": code,
            "metadata": {
                "cwe": ["CWE-95: Eval Injection"],
                "owasp": ["A03:2021 - Injection"],
            },
        },
    }


def test_semgrep_same_code_moved_line_keeps_fingerprint():
    # Code moved from line 10 to 15 -> still the same finding
    a = normalize_semgrep_finding(make_semgrep_raw(10, "eval(x)"))
    b = normalize_semgrep_finding(make_semgrep_raw(15, "eval(x)"))
    assert a["fingerprint"] == b["fingerprint"]


def test_semgrep_two_issues_in_same_file_are_different():
    # Old bug: these were merged into one finding
    a = normalize_semgrep_finding(make_semgrep_raw(10, "eval(x)"))
    b = normalize_semgrep_finding(make_semgrep_raw(20, "eval(userInput)"))
    assert a["fingerprint"] != b["fingerprint"]


def test_semgrep_requires_login_falls_back_to_line():
    a = normalize_semgrep_finding(make_semgrep_raw(10, "requires login"))
    b = normalize_semgrep_finding(make_semgrep_raw(20, "requires login"))
    assert a["fingerprint"] != b["fingerprint"]


def test_semgrep_path_is_relative_to_repo():
    result = normalize_semgrep_finding(make_semgrep_raw(10, "eval(x)"), base_path="C:/repo")
    assert result["location"]["code"]["file_path"] == "app/a.js"


def test_semgrep_cwe_is_extracted():
    result = normalize_semgrep_finding(make_semgrep_raw(10, "eval(x)"))
    assert result["cwe_id"] == "CWE-95"


# ---------- Trivy ----------

def make_trivy_raw(version):
    return {
        "PkgName": "minimist",
        "VulnerabilityID": "CVE-2021-44906",
        "InstalledVersion": version,
        "Severity": "CRITICAL",
        "CVSS": {"nvd": {"V3Score": 9.8}},
        "CweIDs": ["CWE-1321"],
    }


def test_trivy_different_versions_are_different_findings():
    a = normalize_trivy_finding(make_trivy_raw("0.0.8"))
    b = normalize_trivy_finding(make_trivy_raw("1.2.0"))
    assert a["fingerprint"] != b["fingerprint"]


def test_trivy_reads_cvss_score():
    assert normalize_trivy_finding(make_trivy_raw("0.0.8"))["cvss_score"] == 9.8


# ---------- ZAP ----------

ZAP_ALERT = {
    "pluginid": "10202",
    "name": "Absence of Anti-CSRF Tokens",
    "riskcode": "2",
    "confidence": "2",
    "desc": "<p>No CSRF token</p>",
    "cweid": "352",
}


def make_zap_instance(uri):
    return {"uri": uri, "method": "GET", "param": "", "evidence": "<form>"}


def test_zap_query_string_is_ignored():
    # Old bug: ?id=1 and ?id=2 became two separate findings
    a = normalize_zap_finding(ZAP_ALERT, make_zap_instance("http://host/login?id=1"))
    b = normalize_zap_finding(ZAP_ALERT, make_zap_instance("http://host/login?id=2"))
    assert a["fingerprint"] == b["fingerprint"]


def test_zap_different_paths_are_different():
    a = normalize_zap_finding(ZAP_ALERT, make_zap_instance("http://host/login"))
    b = normalize_zap_finding(ZAP_ALERT, make_zap_instance("http://host/signup"))
    assert a["fingerprint"] != b["fingerprint"]


def test_zap_html_is_removed_from_description():
    result = normalize_zap_finding(ZAP_ALERT, make_zap_instance("http://host/login"))
    assert result["description"] == "No CSRF token"
    assert result["severity_native"] == "medium"

from risk_scoring import normalize_severity, calculate_risk_score


def test_semgrep_error_is_high():
    assert normalize_severity("ERROR") == "high"


def test_semgrep_warning_is_medium():
    assert normalize_severity("WARNING") == "medium"


def test_lowercase_input_works():
    assert normalize_severity("critical") == "critical"


def test_missing_severity_is_info():
    assert normalize_severity(None) == "info"
    assert normalize_severity("") == "info"


def test_unknown_severity_is_info():
    assert normalize_severity("SOMETHING_NEW") == "info"


def test_risk_score_averages_base_and_cvss():
    # critical base = 9.0, cvss 9.5 -> (9.0 + 9.5) / 2 = 9.25
    assert calculate_risk_score("critical", 9.5) == 9.25


def test_risk_score_without_cvss_uses_base():
    assert calculate_risk_score("high", None) == 7.0
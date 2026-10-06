SEVERITY_NORMALIZE_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
}


def normalize_severity(severity_native: str) -> str:
    if not severity_native:
        return "info"

    return SEVERITY_NORMALIZE_MAP.get(severity_native.upper(), "info")


SEVERITY_BASE_SCORE = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def calculate_risk_score(severity_normalized: str, cvss_score: float | None) -> float:
    base_score = SEVERITY_BASE_SCORE.get(severity_normalized, 1.0)

    if cvss_score is not None:
        return round((base_score + cvss_score) / 2, 2)

    return base_score


if __name__ == "__main__":
    test_cases = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "WARNING", "INFO", "info", "low", "medium", "high"]
    for case in test_cases:
        print(f"{case} -> {normalize_severity(case)}")

    print(calculate_risk_score("critical", 9.5))
    print(calculate_risk_score("high", None))
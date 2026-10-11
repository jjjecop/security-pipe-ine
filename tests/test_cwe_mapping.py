import pytest

from apply_cwe_mapping import normalize_cwe_id


@pytest.mark.parametrize("raw, expected", [
    ("CWE-79", "CWE-79"),
    ("79", "CWE-79"),
    (" CWE-79 ", "CWE-79"),
    ("cwe-79", "CWE-79"),
])
def test_valid_cwe_is_normalized(raw, expected):
    assert normalize_cwe_id(raw) == expected


@pytest.mark.parametrize("raw", ["-1", "0", "", None, "C"])
def test_missing_or_invalid_cwe_returns_none(raw):
    assert normalize_cwe_id(raw) is None

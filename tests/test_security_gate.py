import sys

import pytest

import run_pipeline
from security_gate import gate_message, severities_at_or_above


def test_critical_counts_only_critical():
    assert severities_at_or_above("critical") == ["critical"]


def test_high_also_counts_critical():
    assert severities_at_or_above("high") == ["critical", "high"]


def test_info_counts_everything():
    assert severities_at_or_above("info") == ["critical", "high", "medium", "low", "info"]


def test_gate_passes_when_nothing_is_blocking():
    assert gate_message("high", {}).startswith("security gate ผ่าน")


def test_gate_message_lists_counts_from_most_severe():
    message = gate_message("high", {"high": 5, "critical": 2})
    assert message.startswith("security gate ไม่ผ่าน")
    assert message.endswith("(critical 2, high 5)")


def run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", *args])
    return run_pipeline.parse_args()


def test_fail_on_is_optional(monkeypatch, tmp_path):
    args = run_cli(monkeypatch, "--project", "demo", "--repo", str(tmp_path))
    assert args.fail_on is None


def test_unknown_severity_is_rejected(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "--project", "demo", "--repo", str(tmp_path), "--fail-on", "severe")


def test_fail_on_cannot_be_used_with_queue(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "--project", "demo", "--repo", str(tmp_path), "--fail-on", "high", "--queue")
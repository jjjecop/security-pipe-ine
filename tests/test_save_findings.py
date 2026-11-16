# ตรวจการบันทึกผลและตัดรายการซ้ำ โดยใช้ session จำลอง จึงรันได้โดยไม่ต้องเปิดฐานข้อมูล
from types import SimpleNamespace

import save_findings
from models import Finding, ScanJob, ScanRun
from save_findings import (
    create_scan_job,
    execute_scan_job,
    mark_missing_as_fixed,
    run_single_scan,
    save_finding_with_dedup,
)


class FakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, expr):
        # รองรับเงื่อนไขแบบ column == value ที่ save_findings ใช้
        name, value = expr.left.key, expr.right.value
        return FakeQuery([item for item in self.items if getattr(item, name) == value])

    def first(self):
        return self.items[0] if self.items else None

    def all(self):
        return list(self.items)


class FakeSession:
    def __init__(self):
        self.rows = []
        self.rollbacks = 0
        self.next_id = 1

    def query(self, model):
        return FakeQuery([row for row in self.rows if isinstance(row, model)])

    def add(self, row):
        if getattr(row, "status", None) is None and isinstance(row, Finding):
            row.status = "open"  # ค่าเริ่มต้นที่ฐานข้อมูลจริงใส่ให้
        self.rows.append(row)

    def refresh(self, row):
        if getattr(row, "id", None) is None:
            row.id = self.next_id
            self.next_id += 1

    def commit(self):
        pass

    def flush(self):
        pass

    def rollback(self):
        self.rollbacks += 1

    def findings(self):
        return [row for row in self.rows if isinstance(row, Finding)]


def make_normalized(fingerprint="fp-1", tool="semgrep", severity="ERROR", cvss=None):
    return {
        "fingerprint": fingerprint,
        "tool": tool,
        "tool_rule_id": "rule-1",
        "title": "Avoid eval",
        "description": "desc",
        "severity_native": severity,
        "cvss_score": cvss,
        "cwe_id": "CWE-95",
        "owasp_category": "A03:2021 - Injection",
        "confidence": "high",
        "location_type": "file",
        "location": {"file": "a.js", "line": 10},
    }


def test_new_finding_is_inserted_with_risk_score():
    session = FakeSession()
    result = save_finding_with_dedup(session, scan_run_id=1, project_id=1, normalized=make_normalized(severity="CRITICAL", cvss=9.8))
    assert result == "inserted"
    finding = session.findings()[0]
    assert finding.severity_normalized == "critical"
    assert finding.risk_score == 9.4  # (9 + 9.8) / 2


def test_same_fingerprint_again_updates_instead_of_adding():
    session = FakeSession()
    save_finding_with_dedup(session, 1, 1, make_normalized())
    result = save_finding_with_dedup(session, 2, 1, make_normalized())
    assert result == "update"
    assert len(session.findings()) == 1


def test_update_refreshes_location_and_severity():
    session = FakeSession()
    save_finding_with_dedup(session, 1, 1, make_normalized(severity="WARNING"))
    moved = make_normalized(severity="ERROR")
    moved["location"] = {"file": "a.js", "line": 25}
    save_finding_with_dedup(session, 2, 1, moved)
    finding = session.findings()[0]
    assert finding.location["line"] == 25
    assert finding.severity_normalized == "high"


def test_fixed_finding_found_again_is_reopened():
    session = FakeSession()
    save_finding_with_dedup(session, 1, 1, make_normalized())
    session.findings()[0].status = "fixed"
    save_finding_with_dedup(session, 2, 1, make_normalized())
    assert session.findings()[0].status == "open"


def test_update_keeps_epss_in_risk_score():
    # สแกนซ้ำต้องไม่ทำให้คะแนนตกเพราะลืมบวก EPSS ที่ดึงไว้แล้ว
    session = FakeSession()
    save_finding_with_dedup(session, 1, 1, make_normalized(severity="HIGH", cvss=7.0))
    finding = session.findings()[0]
    finding.epss_score = 0.5
    save_finding_with_dedup(session, 2, 1, make_normalized(severity="HIGH", cvss=7.0))
    assert finding.risk_score == 8.5  # (7 + 7) / 2 + 3 * 0.5


def test_same_fingerprint_in_another_project_is_a_separate_finding():
    session = FakeSession()
    save_finding_with_dedup(session, 1, 1, make_normalized())
    result = save_finding_with_dedup(session, 2, 2, make_normalized())
    assert result == "inserted"
    assert len(session.findings()) == 2


def test_mark_missing_as_fixed_only_touches_the_same_tool():
    session = FakeSession()
    save_finding_with_dedup(session, 1, 1, make_normalized("fp-seen", tool="semgrep"))
    save_finding_with_dedup(session, 1, 1, make_normalized("fp-gone", tool="semgrep"))
    save_finding_with_dedup(session, 1, 1, make_normalized("fp-zap", tool="zap"))
    fixed = mark_missing_as_fixed(session, project_id=1, tool="semgrep", seen_fingerprints={"fp-seen"})
    status = {f.fingerprint: f.status for f in session.findings()}
    assert fixed == 1
    assert status == {"fp-seen": "open", "fp-gone": "fixed", "fp-zap": "open"}


def make_job(scans=("sast",)):
    return SimpleNamespace(id=7, requested_scans=list(scans), status="queued")


def test_run_single_scan_counts_duplicate_fingerprint_once():
    session = FakeSession()
    project = SimpleNamespace(id=1)
    ok = run_single_scan(session, make_job(), project, "zap", lambda: [make_normalized("same", tool="zap"), make_normalized("same", tool="zap")])
    runs = [row for row in session.rows if isinstance(row, ScanRun)]
    assert ok is True
    assert len(session.findings()) == 1
    assert runs[0].status == "completed" and runs[0].finished_at is not None


def test_run_single_scan_marks_missing_finding_as_fixed():
    session = FakeSession()
    project = SimpleNamespace(id=1)
    run_single_scan(session, make_job(), project, "semgrep", lambda: [make_normalized("a"), make_normalized("b")])
    run_single_scan(session, make_job(), project, "semgrep", lambda: [make_normalized("a")])
    status = {f.fingerprint: f.status for f in session.findings()}
    assert status == {"a": "open", "b": "fixed"}


def test_run_single_scan_records_failure_and_rolls_back():
    session = FakeSession()

    def broken():
        raise RuntimeError("semgrep not found")

    ok = run_single_scan(session, make_job(), SimpleNamespace(id=1), "semgrep", broken)
    run = [row for row in session.rows if isinstance(row, ScanRun)][0]
    assert ok is False
    assert session.rollbacks == 1
    assert run.status == "failed" and "semgrep not found" in run.error_message


def test_failed_scan_does_not_mark_existing_findings_as_fixed():
    # เครื่องมือล้มเหลวไม่ได้แปลว่าช่องโหว่หายไป
    session = FakeSession()
    project = SimpleNamespace(id=1)
    run_single_scan(session, make_job(), project, "semgrep", lambda: [make_normalized("a")])

    def broken():
        raise RuntimeError("boom")

    run_single_scan(session, make_job(), project, "semgrep", broken)
    assert session.findings()[0].status == "open"


def test_create_scan_job_starts_queued():
    session = FakeSession()
    job = create_scan_job(session, SimpleNamespace(id=3), ["sast", "dependency"], triggered_by="cli")
    assert isinstance(job, ScanJob)
    assert (job.status, job.triggered_by, job.requested_scans) == ("queued", "cli", ["sast", "dependency"])


def run_job_with(monkeypatch, sast_ok, dep_ok):
    def collector(ok, fingerprint, tool):
        def run(_):
            if not ok:
                raise RuntimeError("tool failed")
            return [make_normalized(fingerprint, tool=tool)]
        return run

    monkeypatch.setattr(save_findings, "collect_semgrep", collector(sast_ok, "s", "semgrep"))
    monkeypatch.setattr(save_findings, "collect_trivy_dependency", collector(dep_ok, "d", "trivy-dep"))
    session = FakeSession()
    return execute_scan_job(session, make_job(("sast", "dependency")), SimpleNamespace(id=1), repo_path="/repo")


def test_job_is_completed_when_every_tool_succeeds(monkeypatch):
    assert run_job_with(monkeypatch, True, True) == "completed"


def test_job_is_partial_when_one_tool_fails(monkeypatch):
    assert run_job_with(monkeypatch, False, True) == "partial"


def test_job_is_failed_when_every_tool_fails(monkeypatch):
    assert run_job_with(monkeypatch, False, False) == "failed"

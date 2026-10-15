from types import SimpleNamespace

import pipeline


class FakeSession:
    def commit(self):
        pass

    def rollback(self):
        pass


def fake_steps(monkeypatch, fake_report):
    # แทนขั้นที่ช้าหรือต้องใช้ฐานข้อมูลด้วยของปลอม เพื่อทดสอบแค่ลำดับการทำงาน
    monkeypatch.setattr(pipeline, "execute_scan_job", lambda *args, **kwargs: "completed")
    monkeypatch.setattr(pipeline, "apply_cwe_mapping", lambda *args, **kwargs: None)
    monkeypatch.setattr(pipeline, "generate_report", fake_report)


def test_job_is_finished_only_after_report_is_created(monkeypatch):
    job = SimpleNamespace(id=1, status="running")
    seen = {}

    def fake_report(*args, **kwargs):
        seen["status_while_reporting"] = job.status
        return "reports/x"

    fake_steps(monkeypatch, fake_report)
    report_dir = pipeline.run_full_pipeline(FakeSession(), SimpleNamespace(id=1), job, use_epss=False)

    assert seen["status_while_reporting"] == "running"
    assert job.status == "completed"
    assert report_dir == "reports/x"


def test_report_failure_keeps_scan_result(monkeypatch):
    job = SimpleNamespace(id=1, status="running")

    def broken_report(*args, **kwargs):
        raise OSError("disk full")

    fake_steps(monkeypatch, broken_report)
    report_dir = pipeline.run_full_pipeline(FakeSession(), SimpleNamespace(id=1), job, use_epss=False)

    assert job.status == "completed"
    assert report_dir is None

from types import SimpleNamespace

from scan_queue import QUEUE_NAME, enqueue_scan, list_unfinished_scans, wait_for_scan
from tests.fake_redis import FakeRedis
from worker import recover_unfinished_scans


class FakeSession:
    def __init__(self, jobs):
        self.jobs = {job.id: job for job in jobs}
        self.executed = []

    def get(self, model, job_id):
        return self.jobs.get(job_id)

    def execute(self, statement):
        self.executed.append(statement)

    def commit(self):
        pass


def take_job(fake, job_id):
    # จำลองว่า worker ตัวก่อนหยิบงานไปแล้วหยุดกลางคัน (ไม่ได้เรียก finish_scan)
    enqueue_scan(job_id, repo_path="C:/repo", client=fake)
    wait_for_scan(client=fake)


def test_running_job_left_by_stopped_worker_becomes_failed():
    fake = FakeRedis()
    take_job(fake, 1)
    job = SimpleNamespace(id=1, status="running")
    session = FakeSession([job])

    recover_unfinished_scans(session, client=fake)

    assert job.status == "failed"
    assert len(session.executed) == 1  # ScanRun ที่ค้าง running ถูกเปลี่ยนเป็น failed ด้วย
    assert list_unfinished_scans(client=fake) == []


def test_job_taken_but_not_started_goes_back_to_queue():
    fake = FakeRedis()
    take_job(fake, 2)
    job = SimpleNamespace(id=2, status="queued")

    recover_unfinished_scans(FakeSession([job]), client=fake)

    assert job.status == "queued"
    assert wait_for_scan(client=fake)["scan_job_id"] == 2


def test_finished_job_is_only_removed_from_processing():
    fake = FakeRedis()
    take_job(fake, 3)
    job = SimpleNamespace(id=3, status="completed")
    session = FakeSession([job])

    recover_unfinished_scans(session, client=fake)

    assert job.status == "completed"
    assert session.executed == []
    assert list_unfinished_scans(client=fake) == []
    assert fake.lists[QUEUE_NAME] == []
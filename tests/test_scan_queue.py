from scan_queue import QUEUE_NAME, enqueue_scan, finish_scan, list_unfinished_scans, wait_for_scan
from tests.fake_redis import FakeRedis


def test_enqueued_scan_comes_back_unchanged():
    fake = FakeRedis()
    enqueue_scan(39, repo_path="C:/repo", target_url="http://host:4000", client=fake)
    assert wait_for_scan(client=fake) == {
        "scan_job_id": 39,
        "repo_path": "C:/repo",
        "image": None,
        "target_url": "http://host:4000",
        "with_remediation": False,
    }


def test_queue_is_first_in_first_out():
    fake = FakeRedis()
    enqueue_scan(1, client=fake)
    enqueue_scan(2, client=fake)
    assert wait_for_scan(client=fake)["scan_job_id"] == 1
    assert wait_for_scan(client=fake)["scan_job_id"] == 2


def test_empty_queue_returns_none():
    assert wait_for_scan(client=FakeRedis()) is None


def test_taken_scan_stays_in_processing_until_finished():
    fake = FakeRedis()
    enqueue_scan(7, repo_path="C:/repo", client=fake)
    task = wait_for_scan(client=fake)
    assert fake.lists[QUEUE_NAME] == []
    assert list_unfinished_scans(client=fake) == [task]

    finish_scan(task, client=fake)
    assert list_unfinished_scans(client=fake) == []
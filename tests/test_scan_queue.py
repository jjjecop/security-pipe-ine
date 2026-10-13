from scan_queue import enqueue_scan, wait_for_scan


class FakeRedis:
    def __init__(self):
        self.lists = {}

    def rpush(self, name, value):
        self.lists.setdefault(name, []).append(value)

    def blpop(self, name, timeout=0):
        items = self.lists.get(name)
        if not items:
            return None
        return name, items.pop(0)


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


import json
import os

import redis
from dotenv import load_dotenv

load_dotenv()

QUEUE_NAME = "scan_queue"


def get_redis():
    # socket_timeout ต้องนานกว่า timeout ของ BLPOP ไม่อย่างนั้น Python จะตัดการเชื่อมต่อ
    # ก่อนที่ Redis จะตอบว่าคิวว่าง (redis-py 8 ตั้งค่าเริ่มต้นไว้ 5 วินาที เท่ากับ BLPOP ของเรา)
    return redis.Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        decode_responses=True,
        socket_timeout=30,
    )


def enqueue_scan(scan_job_id: int, repo_path=None, image=None, target_url=None, with_remediation=False, client=None):
    task = {
        "scan_job_id": scan_job_id,
        "repo_path": repo_path,
        "image": image,
        "target_url": target_url,
        "with_remediation": with_remediation,
    }
    (client or get_redis()).rpush(QUEUE_NAME, json.dumps(task))


def wait_for_scan(timeout: int = 5, client=None) -> dict | None:
    # รอสูงสุด timeout วินาที ถ้าไม่มีงานให้คืน None เพื่อให้ worker กลับมาเช็กว่าถูกสั่งหยุดหรือยัง
    item = (client or get_redis()).blpop(QUEUE_NAME, timeout=timeout)
    if item is None:
        return None
    _, payload = item
    return json.loads(payload)
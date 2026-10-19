import json
import os

import redis
from dotenv import load_dotenv

load_dotenv()

QUEUE_NAME = "scan_queue"
# งานที่ worker หยิบไปแล้วแต่ยังทำไม่เสร็จ ถ้า worker ดับกลางคัน งานจะยังอยู่ที่นี่ให้ตามเก็บได้
PROCESSING_NAME = "scan_processing"


def get_redis():
    # socket_timeout ต้องนานกว่า timeout ของ BLPOP ไม่อย่างนั้น Python จะตัดการเชื่อมต่อ
    # ก่อนที่ Redis จะตอบว่าคิวว่าง (redis-py 8 ตั้งค่าเริ่มต้นไว้ 5 วินาที เท่ากับ BLPOP ของเรา)
    return redis.Redis.from_url(
        # ใช้ 127.0.0.1 ไม่ใช่ localhost: บน Windows localhost จะลอง IPv6 (::1) ก่อน
        # แต่ Docker เปิด port ไว้แค่ IPv4 จึงเสียเวลารอประมาณ 2 วินาทีทุกครั้งที่ต่อใหม่
        os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"),
        # แยกรหัสผ่านออกจาก URL จะได้ไม่ต้อง encode อักขระพิเศษ และ URL ไม่มีความลับติดอยู่ตอนพิมพ์ log
        password=os.getenv("REDIS_PASSWORD") or None,
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
    # BLMOVE ย้ายงานจากคิวไปไว้ใน PROCESSING_NAME ในคำสั่งเดียว งานจึงไม่หายไประหว่างทาง
    payload = (client or get_redis()).blmove(QUEUE_NAME, PROCESSING_NAME, timeout)
    if payload is None:
        return None
    return json.loads(payload)


def finish_scan(task: dict, client=None):
    # json.dumps ของ dict เดิมได้ข้อความเดียวกับตอน enqueue_scan จึงลบรายการที่ตรงกันได้
    (client or get_redis()).lrem(PROCESSING_NAME, 1, json.dumps(task))


def list_unfinished_scans(client=None) -> list[dict]:
    return [json.loads(payload) for payload in (client or get_redis()).lrange(PROCESSING_NAME, 0, -1)]
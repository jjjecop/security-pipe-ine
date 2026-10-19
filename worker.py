import sys
import time
import traceback

from datetime import datetime

import redis
from sqlalchemy import update
from sqlalchemy.orm import Session

from db import engine
from models import Project, ScanJob, ScanRun
from pipeline import run_full_pipeline
from scan_queue import wait_for_scan, enqueue_scan, finish_scan, list_unfinished_scans


def process_task(task: dict):
    with Session(engine) as session:
        scan_job = session.get(ScanJob, task["scan_job_id"])
        if scan_job is None:
            print(f"ไม่พบ ScanJob {task['scan_job_id']} ข้ามงานนี้")
            return
        if scan_job.status != "queued":
            # กันไม่ให้สแกนซ้ำ ถ้างานเดียวกันถูกใส่คิว 2 ครั้ง
            print(f"ScanJob {scan_job.id} สถานะเป็น {scan_job.status} ไม่ใช่ queued ข้ามงานนี้")
            return

        project = session.get(Project, scan_job.project_id)
        try:
            run_full_pipeline(
                session,
                project,
                scan_job,
                repo_path=task.get("repo_path"),
                image=task.get("image"),
                target_url=task.get("target_url"),
                with_remediation=task.get("with_remediation", False),
            )
        except Exception:
            # งานเดียวพังต้องไม่ทำให้ worker หยุด ให้บันทึกเป็น failed แล้วรองานถัดไป
            session.rollback()
            scan_job.status = "failed"
            session.commit()
            traceback.print_exc()


def fail_interrupted_job(session, scan_job):
    scan_job.status = "failed"
    session.execute(
        update(ScanRun)
        .where(ScanRun.scan_job_id == scan_job.id, ScanRun.status == "running")
        .values(status="failed", finished_at=datetime.utcnow(), error_message="worker หยุดทำงานระหว่างสแกน")
    )
    session.commit()


def recover_unfinished_scans(session, client=None):
    # งานที่ยังค้างใน PROCESSING_NAME ตอน worker เริ่ม คืองานที่ worker ตัวก่อนทำไม่จบ (Ctrl+C, ปิดหน้าต่าง, เครื่องดับ)
    # ออกแบบไว้สำหรับ worker ตัวเดียว ถ้ามีหลายตัวต้องแยกรายการตามชื่อ worker ไม่อย่างนั้นจะไปเก็บงานที่ตัวอื่นกำลังทำอยู่
    for task in list_unfinished_scans(client):
        scan_job = session.get(ScanJob, task["scan_job_id"])
        if scan_job is not None and scan_job.status == "running":
            # สแกนไปได้ครึ่งทาง ผลไม่ครบ จึงบันทึกเป็น failed ให้ผู้ใช้สั่งสแกนใหม่เอง
            print(f"ScanJob {scan_job.id} ค้างเป็น running จาก worker ตัวก่อน เปลี่ยนเป็น failed")
            fail_interrupted_job(session, scan_job)
        elif scan_job is not None and scan_job.status == "queued":
            # หยิบไปแล้วแต่ยังไม่ทันเริ่มสแกน ใส่กลับเข้าคิวได้เลย
            print(f"ScanJob {scan_job.id} ยังไม่ได้เริ่ม ใส่กลับเข้าคิว")
            enqueue_scan(**task, client=client)
        finish_scan(task, client)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("worker เริ่มทำงาน รองานจากคิว (กด Ctrl+C เพื่อหยุด)")
    recovered = False
    try:
        while True:
            try:
                if not recovered:
                    with Session(engine) as session:
                        recover_unfinished_scans(session)
                    recovered = True
                task = wait_for_scan()

            except redis.exceptions.ConnectionError:
                print("ต่อ Redis ไม่ได้ ลองใหม่ใน 5 วินาที")
                time.sleep(5)
                continue
            if task is None:
                continue
            print(f"\n>>> ได้งาน ScanJob {task['scan_job_id']}")
            process_task(task)
            # ลบออกจากรายการ "กำลังทำ" หลังทำเสร็จเท่านั้น ถ้า worker หยุดกลางคัน งานจะยังอยู่ให้รอบหน้าเก็บ
            finish_scan(task)

            print(f"<<< จบงาน ScanJob {task['scan_job_id']} รองานถัดไป")
    except KeyboardInterrupt:
        print("\nหยุด worker แล้ว")


if __name__ == "__main__":
    main()
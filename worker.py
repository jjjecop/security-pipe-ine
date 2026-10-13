import sys
import time
import traceback

import redis
from sqlalchemy.orm import Session

from db import engine
from models import Project, ScanJob
from pipeline import run_full_pipeline
from scan_queue import wait_for_scan


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


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("worker เริ่มทำงาน รองานจากคิว (กด Ctrl+C เพื่อหยุด)")
    try:
        while True:
            try:
                task = wait_for_scan()
            except redis.exceptions.ConnectionError:
                print("ต่อ Redis ไม่ได้ ลองใหม่ใน 5 วินาที")
                time.sleep(5)
                continue
            if task is None:
                continue
            print(f"\n>>> ได้งาน ScanJob {task['scan_job_id']}")
            process_task(task)
            print(f"<<< จบงาน ScanJob {task['scan_job_id']} รองานถัดไป")
    except KeyboardInterrupt:
        print("\nหยุด worker แล้ว")


if __name__ == "__main__":
    main()
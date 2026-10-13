import argparse
import os
import sys

# ให้พิมพ์ภาษาไทยได้แม้ terminal/ไฟล์ log บน Windows จะไม่ใช่ UTF-8
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from sqlalchemy.orm import Session

from db import engine
from save_findings import SCAN_TYPES, get_or_create_project, create_scan_job
from pipeline import run_full_pipeline


def parse_args():
    parser = argparse.ArgumentParser(
        description="สแกนช่องโหว่ บันทึกลงฐานข้อมูล แล้วสร้างรายงาน",
        epilog=(
            "ตัวอย่าง: python run_pipeline.py --project NodeGoat "
            "--repo C:\\Allprojects\\Targets\\NodeGoat --image nodegoat:latest "
            "--url http://host.docker.internal:4000"
        ),
    )
    parser.add_argument("--project", required=True, help="ชื่อโปรเจกต์ (ใช้แยกข้อมูลในฐานข้อมูล)")
    parser.add_argument("--repo", help="path ของ source code (ใช้กับ sast และ dependency)")
    parser.add_argument("--image", help="ชื่อ Docker image (ใช้กับ container)")
    parser.add_argument("--url", help="URL ของเว็บที่รันอยู่ (ใช้กับ dast) ถ้าเว็บรันบนเครื่องตัวเองให้ใช้ host.docker.internal แทน localhost")
    parser.add_argument(
        "--scans",
        help=f"เลือกสแกนที่จะรัน คั่นด้วย comma จาก {','.join(SCAN_TYPES)} (ค่าเริ่มต้น: เลือกจาก argument ที่ให้มา)",
    )
    parser.add_argument("--output-dir", default="reports", help="โฟลเดอร์เก็บรายงาน (ค่าเริ่มต้น: reports)")
    parser.add_argument("--no-report", action="store_true", help="สแกนอย่างเดียว ไม่สร้างรายงาน")
    parser.add_argument("--with-remediation", action="store_true", help="ให้ Gemini เขียนคำแนะนำการแก้ไขให้ CWE ที่ยังไม่มี (ประมาณ 13-40 วินาทีต่อ CWE)")
    parser.add_argument("--no-epss", action="store_true", help="ไม่ดึงคะแนน EPSS จาก FIRST.org (ใช้ตอนไม่มี internet)")

    args = parser.parse_args()

    if args.scans:
        scans = [s.strip() for s in args.scans.split(",") if s.strip()]
        unknown = [s for s in scans if s not in SCAN_TYPES]
        if unknown:
            parser.error(f"ไม่รู้จักประเภทสแกน: {', '.join(unknown)}")
    else:
        scans = []
        if args.repo:
            scans += ["sast", "dependency"]
        if args.image:
            scans.append("container")
        if args.url:
            scans.append("dast")

    if not scans:
        parser.error("ต้องระบุอย่างน้อยหนึ่งใน --repo, --image, --url")

    if {"sast", "dependency"} & set(scans) and not args.repo:
        parser.error("sast/dependency ต้องระบุ --repo")
    if "container" in scans and not args.image:
        parser.error("container ต้องระบุ --image")
    if "dast" in scans and not args.url:
        parser.error("dast ต้องระบุ --url")
    if args.repo:
        if not os.path.isdir(args.repo):
            parser.error(f"ไม่พบโฟลเดอร์ {args.repo}")
        args.repo = os.path.abspath(args.repo)

    args.scans = scans
    return args


def main():
    args = parse_args()

    with Session(engine) as session:
        project = get_or_create_project(session, args.project, repo_path=args.repo, target_url=args.url)
        scan_job = create_scan_job(session, project, args.scans, triggered_by="cli")

        run_full_pipeline(
            session,
            project,
            scan_job,
            repo_path=args.repo,
            image=args.image,
            target_url=args.url,
            with_remediation=args.with_remediation,
            use_epss=not args.no_epss,
            make_report=not args.no_report,
            output_dir=args.output_dir,
        )

        failed = scan_job.status == "failed"

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

from save_findings import execute_scan_job
from apply_cwe_mapping import apply_cwe_mapping
from epss import apply_epss
from generate_remediation import generate_remediation, get_project_cwe_ids
from generate_report import generate_report


def run_full_pipeline(
    session,
    project,
    scan_job,
    repo_path=None,
    image=None,
    target_url=None,
    with_remediation=False,
    use_epss=True,
    make_report=True,
    output_dir="reports",
):
    # แกนกลางที่ CLI และ worker ใช้ร่วมกัน: สแกน -> CWE -> EPSS -> Gemini -> รายงาน
    final_status = execute_scan_job(session, scan_job, project, repo_path=repo_path, image=image, target_url=target_url)

    print("\n=== จับคู่ CWE -> OWASP Top 10 ===")
    apply_cwe_mapping(session, project_id=project.id)

    if use_epss:
        print("\n=== ดึงคะแนน EPSS จาก FIRST.org ===")
        try:
            apply_epss(session, project.id)
        except Exception as e:
            session.rollback()
            print(f"ดึง EPSS ไม่สำเร็จ: {e}")
            print("ยังสร้างรายงานต่อได้ แต่ risk score จะไม่รวม EPSS")

    if with_remediation:
        print("\n=== สร้างคำแนะนำการแก้ไขด้วย Gemini ===")
        try:
            generate_remediation(session, cwe_ids=get_project_cwe_ids(session, project.id))
        except Exception as e:
            session.rollback()
            print(f"สร้างคำแนะนำไม่สำเร็จ: {e}")
            print("ยังสร้างรายงานต่อได้ แต่บาง CWE จะไม่มีคำแนะนำ")

    report_dir = None
    if make_report:
        print("\n=== สร้างรายงาน ===")
        try:
            report_dir = generate_report(session, project, scan_job_id=scan_job.id, output_dir=output_dir)
        except Exception as e:
            session.rollback()
            print(f"สร้างรายงานไม่สำเร็จ: {e}")
            print("ผลสแกนยังอยู่ในฐานข้อมูล แต่งานนี้จะไม่มีไฟล์รายงาน")

    # บันทึกสถานะสุดท้ายหลังสร้างรายงานแล้วเท่านั้น
    # ไม่อย่างนั้นหน้าเว็บจะเห็น "เสร็จ" แล้วโหลดตารางก่อนที่รายงานจะมี (race condition)
    scan_job.status = final_status
    session.commit()
    print(f"\nScanJob {scan_job.id} สถานะ: {final_status}")
    return report_dir
# คำนวณ severity/risk_score ใหม่ทั้งหมด (ปกติ save_findings คำนวณให้ตอนบันทึกแล้ว
# ใช้สคริปต์นี้เมื่อแก้สูตรใน risk_scoring.py แล้วต้องการคำนวณข้อมูลเก่าใหม่)
from db import engine
from sqlalchemy.orm import Session

from models import Finding 
from risk_scoring import normalize_severity, calculate_risk_score


def apply_risk_scoring(session):
    all_findings = session.query(Finding).all()

    print("จำนวน Finding ทั้งหมด:", len(all_findings))

    updated_count = 0
    for finding in all_findings:
        finding.severity_normalized = normalize_severity(finding.severity_native)
        finding.risk_score = calculate_risk_score(finding.severity_normalized, finding.cvss_score)
        updated_count += 1

    session.commit()
    print("อัปเดตสำเร็จ", updated_count, "รายการ")


if __name__ == "__main__":
    with Session(engine) as session:
        apply_risk_scoring(session)

from db import engine
from sqlalchemy.orm import Session

from models import Finding, CweOwaspMapping


def normalize_cwe_id(raw_cwe_id: str) -> str | None:
    if not raw_cwe_id:
        return None

    cleaned = raw_cwe_id.strip()

    if cleaned.startswith("CWE-"):
        return cleaned

    if cleaned.isdigit():
        return f"CWE-{cleaned}"

    return None


def apply_cwe_mapping(session, project_id: int | None = None):
    query = (
        session.query(Finding)
        .filter(Finding.owasp_category.is_(None))
        .filter(Finding.cwe_id.isnot(None))
    )
    if project_id is not None:
        query = query.filter(Finding.project_id == project_id)
    findings_to_update = query.all()

    print("จำนวน Finding ที่ owasp_category ว่างอยู่:", len(findings_to_update))

    updated_count = 0
    not_found_count = 0

    for finding in findings_to_update:
        normalize_cwe = normalize_cwe_id(finding.cwe_id)

        if normalize_cwe is None:
            not_found_count += 1
            continue

        mapping = session.get(CweOwaspMapping, normalize_cwe)

        if mapping is None:
            not_found_count += 1
            continue

        finding.owasp_category = mapping.owasp_top10_2021
        updated_count += 1

    session.commit()

    print("อัปเดตสำเร็จ:", updated_count, "รายการ")
    print("หา mapping ไม่เจอ:", not_found_count, "รายการ")


if __name__ == "__main__":
    with Session(engine) as session:
        apply_cwe_mapping(session)

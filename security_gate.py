from sqlalchemy import func

from models import Finding

# เรียงจากร้ายแรงมากไปน้อย ใช้ทั้งใน API และ security gate
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def severities_at_or_above(threshold: str) -> list[str]:
    # --fail-on high หมายถึงนับทั้ง critical และ high
    return list(SEVERITY_ORDER[: SEVERITY_ORDER.index(threshold) + 1])


def count_blocking_findings(session, project_id: int, threshold: str) -> dict[str, int]:
    rows = (
        session.query(Finding.severity_normalized, func.count(Finding.id))
        .filter(Finding.project_id == project_id)
        .filter(Finding.status == "open")
        .filter(Finding.severity_normalized.in_(severities_at_or_above(threshold)))
        .group_by(Finding.severity_normalized)
        .all()
    )
    return dict(rows)


def gate_message(threshold: str, counts: dict[str, int]) -> str:
    if not counts:
        return f"security gate ผ่าน: ไม่พบช่องโหว่ที่ยังเปิดอยู่ระดับ {threshold} ขึ้นไป"
    detail = ", ".join(f"{severity} {counts[severity]}" for severity in SEVERITY_ORDER if severity in counts)
    return f"security gate ไม่ผ่าน: พบช่องโหว่ที่ยังเปิดอยู่ระดับ {threshold} ขึ้นไป ({detail})"
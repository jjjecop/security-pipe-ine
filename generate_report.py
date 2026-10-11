import os
import re
import shutil
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
)

from models import Finding, Project, CweOwaspMapping, Report

from apply_cwe_mapping import normalize_cwe_id

from collections import defaultdict

from db import engine

LOCATION_TYPE_LABELS = {
    "code": "ช่องโหว่ในโค้ด (SAST)",
    "dependency": "ช่องโหว่ใน Library (Dependency)",
    "container_image": "ช่องโหว่ใน Container Image",
    "http_endpoint": "ช่องโหว่จากการทดสอบเว็บจริง (DAST)"
}


def extract_location_detail(location_type: str, location: dict) -> str:
    if location_type == "code":
        code = location.get("code", {})
        return f"ไฟล์: {code.get('file_path')} บรรทัด {code.get('line_start')}"
    if location_type == "dependency":
        dep = location.get("dependency", {})
        fixed = dep.get('fixed_version')
        fixed_text = f" (แก้ไขได้ที่เวอร์ชัน {fixed})" if fixed else " (ยังไม่มีเวอร์ชันที่แก้ไข)"
        return f"Package: {dep.get('package_name')} เวอร์ชัน {dep.get('installed_version')}{fixed_text}"
    if location_type == "container_image":
        img = location.get('container_image', {})
        fixed = img.get('fixed_version')
        fixed_text = f" (แก้ไขได้ที่เวอร์ชัน {fixed})" if fixed else ""
        return f"พบใน Docker image: {img.get('image_ref')} | Package: {img.get('os_package')} เวอร์ชั่น {img.get('installed_version')}{fixed_text}"
    if location_type == "http_endpoint":
        http = location.get("http_endpoint", {})
        evidence = http.get("attack_evidence")
        if evidence and len(evidence) > 200:
            evidence = evidence[:200] + "..."
        evidence_text = f" | หลักฐานที่พบ: {evidence}" if evidence else ""
        return f"URL: {http.get('url')} | Method: {http.get('method')}{evidence_text}"

    return "ไม่มีรายละเอียดเพิ่มเติม"

def get_remediation_workaround(session, cwe_id: str, package_name: str = None, version: str = None) -> str | None:
    if not cwe_id:
        return None 

    normalized = normalize_cwe_id(cwe_id)
    if normalized is None:
        return  None

    mapping = session.get(CweOwaspMapping, normalized)
    if mapping is None or mapping.remediation_workaround is None:
        return None

    template = mapping.remediation_workaround
    return (template
            .replace("{package}", package_name or "library นี้")
            .replace("{version}", version or "ที่ใช้อยู่"))


def build_report_data(session, project_id: int):
    open_findings = Finding.status == "open"

    severity_counts = (
        session.query(Finding.severity_normalized, func.count(Finding.id))
        .filter(Finding.project_id == project_id)
        .filter(open_findings)
        .group_by(Finding.severity_normalized)
        .all()
    )

    print("จำนวนแยกตาม severity:", severity_counts)

    severity_data = [
        {"severity": row[0], "count": row[1]}
        for row in severity_counts
    ]

    all_findings_sorted = (
        session.query(Finding)
        .filter(Finding.project_id == project_id)
        .filter(open_findings)
        .order_by(Finding.risk_score.desc().nulls_last())
        .all()
    )

    grouped = defaultdict(list)
    for f in all_findings_sorted:
        grouped[f.tool_rule_id].append(f)

    top_findings_data = []
    for tool_rule_id, finding_groups in grouped.items():
        primary = max(finding_groups, key=lambda x: x.risk_score or 0)
        sources = sorted(set(f.tool for f in finding_groups))

        location_detail = []
        for f in finding_groups:
            detail = extract_location_detail(f.location_type, f.location)
            location_detail.append(f"[{f.tool}] {detail}")


        package_name = None
        package_version = None 

        if primary.location_type == "dependency":
            dep = primary.location.get("dependency", {})
            package_name = dep.get("package_name")
            package_version = dep.get("installed_version")
        elif primary.location_type == "container_image":
            img = primary.location.get("container_image", {})
            package_name = img.get("os_package")
            package_version = img.get("installed_version")

        top_findings_data.append({
            "title": primary.title,
            "risk_score": primary.risk_score,
            "epss_score": primary.epss_score,
            "tool": ", ".join(sources),
            "severity": primary.severity_normalized,
            "owasp_category": primary.owasp_category,
            "cwe_id": primary.cwe_id, 
            "location_label": LOCATION_TYPE_LABELS.get(primary.location_type, primary.location_type),
            "location_detail": " | ".join(location_detail),
            "remediation_workaround": get_remediation_workaround(session, primary.cwe_id, package_name, package_version),

        })

    top_findings_data.sort(key=lambda x: x["risk_score"] or 0, reverse=True)

    print("\n--- Top 5 Finding ที่อันตรายที่สุด ---")
    for item in top_findings_data[:5]:
        print(item["title"][:100], "| risk_score:", item["risk_score"], " | tool:", item["tool"])

    return severity_data, top_findings_data


def generate_report(session, project: Project, scan_job_id: int | None = None, output_dir: str = "reports") -> str:
    from weasyprint import HTML

    severity_data, top_findings_data = build_report_data(session, project.id)

    now = datetime.now()
    report_date = now.strftime("%Y-%m-%d %H:%M")
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", project.name)
    report_dir = os.path.join(output_dir, f"{safe_name}_{now.strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(report_dir, exist_ok=True)

    context = dict(
        project_name=project.name,
        report_date=report_date,
        severity_data=severity_data,
        top_findings=top_findings_data,
    )
    report_html = env.get_template("report_template.html").render(**context)
    dashboard_html = env.get_template("dashboard_template.html").render(**context)

    # คัดลอก CSS ไปไว้ข้างไฟล์ HTML เพื่อให้เปิดจากโฟลเดอร์รายงานได้ตรงๆ
    for css in ("report_style.css", "dashboard_style.css"):
        shutil.copy(os.path.join(TEMPLATES_DIR, css), report_dir)

    with open(os.path.join(report_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write(report_html)
    dashboard_path = os.path.join(report_dir, "dashboard.html")
    with open(dashboard_path, "w", encoding="utf-8") as f:
        f.write(dashboard_html)

    pdf_path = os.path.join(report_dir, "security_report.pdf")
    HTML(string=report_html, base_url=TEMPLATES_DIR).write_pdf(pdf_path)

    if scan_job_id is not None:
        session.add(Report(
            scan_job_id=scan_job_id,
            file_path=pdf_path,
            summary={
                "severity": {row["severity"]: row["count"] for row in severity_data},
                "total_open": sum(row["count"] for row in severity_data),
            },
        ))
        session.commit()

    print(f"\nสร้างรายงานสำเร็จที่ {report_dir}")
    print("  - dashboard.html (เปิดในเบราว์เซอร์)")
    print("  - report.html")
    print("  - security_report.pdf")
    return report_dir


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="สร้างรายงานจาก finding ที่อยู่ในฐานข้อมูล")
    parser.add_argument("--project", required=True, help="ชื่อโปรเจกต์")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()

    with Session(engine) as session:
        project = session.query(Project).filter(Project.name == args.project).first()
        if project is None:
            raise SystemExit(f"ไม่พบโปรเจกต์ '{args.project}'")
        generate_report(session, project, output_dir=args.output_dir)

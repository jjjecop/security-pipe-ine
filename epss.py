import argparse
import json
import sys
import urllib.parse
import urllib.request

from dotenv import load_dotenv
from sqlalchemy.orm import Session

from db import engine
from models import Finding, Project
from risk_scoring import calculate_risk_score

# โหลด .env ก่อนต่อ internet เพื่อให้ใช้ ca-bundle ของ Norton ได้
load_dotenv()

EPSS_API_URL = "https://api.first.org/data/v1/epss"
# ส่ง CVE ทีละ 100 ตัวต่อครั้ง เพื่อไม่ให้ URL ยาวเกินไป
BATCH_SIZE = 100
CVE_TOOLS = ("trivy-dep", "trivy-container")


def parse_epss_response(data: dict) -> dict[str, float]:
    return {row["cve"]: float(row["epss"]) for row in data.get("data") or []}


def fetch_epss_scores(cve_ids, timeout: int = 30) -> dict[str, float]:
    # EPSS มีเฉพาะ CVE ส่วน GHSA / NSWG ไม่มี
    cve_ids = sorted({c for c in cve_ids if c and c.startswith("CVE-")})
    scores = {}
    for i in range(0, len(cve_ids), BATCH_SIZE):
        batch = cve_ids[i:i + BATCH_SIZE]
        query = urllib.parse.urlencode({"cve": ",".join(batch), "limit": len(batch)})
        with urllib.request.urlopen(f"{EPSS_API_URL}?{query}", timeout=timeout) as response:
            scores.update(parse_epss_response(json.load(response)))
    return scores


def apply_epss(session, project_id: int):
    findings = (
        session.query(Finding)
        .filter(Finding.project_id == project_id)
        .filter(Finding.status == "open")
        .filter(Finding.tool.in_(CVE_TOOLS))
        .all()
    )
    scores = fetch_epss_scores(f.tool_rule_id for f in findings)

    updated_count = 0
    for finding in findings:
        epss_score = scores.get(finding.tool_rule_id)
        if epss_score is None:
            continue
        finding.epss_score = epss_score
        finding.risk_score = calculate_risk_score(finding.severity_normalized, finding.cvss_score, epss_score)
        updated_count += 1

    session.commit()
    print(f"ดึง EPSS ได้ {len(scores)} CVE | อัปเดต risk score {updated_count} จาก {len(findings)} finding")


def main():
    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="ดึงคะแนน EPSS จาก FIRST.org แล้วคำนวณ risk score ใหม่")
    parser.add_argument("--project", required=True, help="ชื่อโปรเจกต์")
    args = parser.parse_args()

    with Session(engine) as session:
        project = session.query(Project).filter(Project.name == args.project).first()
        if project is None:
            raise SystemExit(f"ไม่พบโปรเจกต์ '{args.project}'")
        apply_epss(session, project.id)


if __name__ == "__main__":
    main()

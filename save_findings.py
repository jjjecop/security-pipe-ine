from datetime import datetime

from sqlalchemy.orm import Session

from models import Project, ScanJob, ScanRun, Finding
from normalizer import (
    normalize_semgrep_finding,
    normalize_trivy_finding,
    normalize_trivy_container_finding,
    normalize_zap_finding,
)
from risk_scoring import normalize_severity, calculate_risk_score
from scanners.sast import run_semgrep_scan
from scanners.dependency import run_trivy_dependency_scan
from scanners.container import run_trivy_container_scan
from scanners.dast import run_zap_baseline_scan


SCAN_TYPES = ("sast", "dependency", "container", "dast")


def save_finding_with_dedup(session, scan_run_id, project_id, normalized):
    severity_normalized = normalize_severity(normalized["severity_native"])
    risk_score = calculate_risk_score(severity_normalized, normalized.get("cvss_score"))

    existing = (
        session.query(Finding)
        .filter(Finding.project_id == project_id)
        .filter(Finding.fingerprint == normalized["fingerprint"])
        .first()
    )

    if existing:
        existing.last_seen = datetime.utcnow()
        existing.status = "open"
        existing.location = normalized["location"]
        existing.severity_native = normalized["severity_native"]
        existing.severity_normalized = severity_normalized
        existing.cvss_score = normalized.get("cvss_score")
        existing.risk_score = risk_score
        return "update"

    finding = Finding(
        scan_run_id=scan_run_id,
        project_id=project_id,
        fingerprint=normalized["fingerprint"],
        tool=normalized["tool"],
        tool_rule_id=normalized["tool_rule_id"],
        title=normalized["title"],
        description=normalized["description"],
        severity_normalized=severity_normalized,
        severity_native=normalized["severity_native"],
        cvss_score=normalized.get("cvss_score"),
        risk_score=risk_score,
        cwe_id=normalized["cwe_id"],
        owasp_category=normalized["owasp_category"],
        confidence=normalized["confidence"],
        location_type=normalized["location_type"],
        location=normalized["location"],
    )
    session.add(finding)
    return "inserted"


def mark_missing_as_fixed(session, project_id, tool, seen_fingerprints) -> int:
    # finding ที่เคย open แต่สแกนรอบนี้ไม่เจอแล้ว ถือว่าแก้ไขแล้ว
    open_findings = (
        session.query(Finding)
        .filter(Finding.project_id == project_id)
        .filter(Finding.tool == tool)
        .filter(Finding.status == "open")
        .all()
    )
    fixed_count = 0
    for finding in open_findings:
        if finding.fingerprint not in seen_fingerprints:
            finding.status = "fixed"
            fixed_count += 1
    return fixed_count


def get_or_create_project(session, name, repo_path=None, target_url=None) -> Project:
    project = session.query(Project).filter(Project.name == name).first()

    if project is None:
        project = Project(name=name, repo_url=repo_path, target_url=target_url)
        session.add(project)
        print("สร้าง Project ใหม่:", name)
    else:
        if repo_path:
            project.repo_url = repo_path
        if target_url:
            project.target_url = target_url
        print("ใช้ Project เดิม id:", project.id)

    session.commit()
    session.refresh(project)
    return project


def collect_semgrep(repo_path):
    result = run_semgrep_scan(repo_path)
    return [normalize_semgrep_finding(raw, base_path=repo_path) for raw in result.get("results", [])]


def collect_trivy_dependency(repo_path):
    result = run_trivy_dependency_scan(repo_path)
    normalized = []
    for res in result.get("Results") or []:
        for raw in res.get("Vulnerabilities") or []:
            normalized.append(normalize_trivy_finding(raw))
    return normalized


def collect_trivy_container(image):
    result = run_trivy_container_scan(image)
    normalized = []
    for res in result.get("Results") or []:
        for raw in res.get("Vulnerabilities") or []:
            normalized.append(normalize_trivy_container_finding(raw, image))
    return normalized


def collect_zap(target_url):
    result = run_zap_baseline_scan(target_url)
    normalized = []
    for site in result.get("site") or []:
        for alert in site.get("alerts") or []:
            for instance in alert.get("instances") or []:
                normalized.append(normalize_zap_finding(alert, instance))
    return normalized


def run_single_scan(session, scan_job, project, tool, collector) -> bool:
    scan_run = ScanRun(
        scan_job_id=scan_job.id,
        tool=tool,
        status="running",
        started_at=datetime.utcnow(),
    )
    session.add(scan_run)
    session.commit()
    session.refresh(scan_run)

    print(f"\n[{tool}] เริ่มสแกน (ScanRun id: {scan_run.id})")

    try:
        normalized_findings = collector()

        inserted_count = 0
        updated_count = 0
        seen_fingerprints = set()
        for normalized in normalized_findings:
            # fingerprint ซ้ำในรอบเดียวกัน (เช่น ZAP เจอ URL เดียวกันหลายรอบ) ให้นับครั้งเดียว
            if normalized["fingerprint"] in seen_fingerprints:
                continue
            seen_fingerprints.add(normalized["fingerprint"])

            result = save_finding_with_dedup(session, scan_run.id, project.id, normalized)
            if result == "inserted":
                inserted_count += 1
            else:
                updated_count += 1
            # flush เพื่อให้ query dedup รอบถัดไปเห็น finding ที่เพิ่ง add
            session.flush()

        fixed_count = mark_missing_as_fixed(session, project.id, tool, seen_fingerprints)

        scan_run.status = "completed"
        scan_run.finished_at = datetime.utcnow()
        session.commit()
        print(f"[{tool}] เพิ่มใหม่ {inserted_count} | อัปเดต {updated_count} | แก้ไขแล้ว {fixed_count}")
        return True

    except Exception as e:
        session.rollback()
        scan_run.status = "failed"
        scan_run.finished_at = datetime.utcnow()
        scan_run.error_message = str(e)[:4000]
        session.commit()
        print(f"[{tool}] ล้มเหลว: {e}")
        return False


def run_scan_job(session: Session, project: Project, scans: list[str], repo_path=None, image=None, target_url=None) -> ScanJob:
    scan_job = ScanJob(
        project_id=project.id,
        requested_scans=scans,
        status="running",
        triggered_by="manual",
        created_at=datetime.utcnow(),
    )
    session.add(scan_job)
    session.commit()
    session.refresh(scan_job)
    print("สร้าง ScanJob id:", scan_job.id, "| สแกน:", ", ".join(scans))

    plan = {
        "sast": ("semgrep", lambda: collect_semgrep(repo_path)),
        "dependency": ("trivy-dep", lambda: collect_trivy_dependency(repo_path)),
        "container": ("trivy-container", lambda: collect_trivy_container(image)),
        "dast": ("zap", lambda: collect_zap(target_url)),
    }

    results = []
    for scan_type in scans:
        tool, collector = plan[scan_type]
        results.append(run_single_scan(session, scan_job, project, tool, collector))

    if all(results):
        scan_job.status = "completed"
    elif any(results):
        scan_job.status = "partial"
    else:
        scan_job.status = "failed"
    session.commit()

    print(f"\nScanJob {scan_job.id} สถานะ: {scan_job.status}")
    return scan_job

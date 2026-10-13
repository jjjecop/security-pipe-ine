import os
import secrets

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import APIKeyHeader
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from db import engine
from models import Finding, Project, ScanJob, ScanRun

app = FastAPI(title="VulnCompass API", description="ดูผลสแกนช่องโหว่จากฐานข้อมูล")


def get_session():
    # เปิด session ใหม่ทุก request แล้วปิดให้เองเมื่อตอบเสร็จ
    with Session(engine) as session:
        yield session


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Depends(api_key_header)):
    expected = os.getenv("API_KEY")
    if not expected:
        # ถ้าลืมตั้ง API_KEY ให้ปฏิเสธทุก request แทนการเปิดให้เข้าได้หมด
        raise HTTPException(status_code=503, detail="ยังไม่ได้ตั้ง API_KEY ใน .env")
    if api_key is None or not secrets.compare_digest(api_key, expected):
        raise HTTPException(status_code=401, detail="API key ไม่ถูกต้อง")


def get_project_or_404(session, project_name: str) -> Project:
    project = session.query(Project).filter(Project.name == project_name).first()
    if project is None:
        raise HTTPException(status_code=404, detail=f"ไม่พบโปรเจกต์ '{project_name}'")
    return project


@app.get("/health")
def health_check(session: Session = Depends(get_session)):
    try:
        session.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="ต่อฐานข้อมูลไม่ได้")
    return {"status": "ok", "database": "ok"}


@app.get("/projects", dependencies=[Depends(require_api_key)])
def list_projects(session: Session = Depends(get_session)):
    open_counts = dict(
        session.query(Finding.project_id, func.count(Finding.id))
        .filter(Finding.status == "open")
        .group_by(Finding.project_id)
        .all()
    )
    projects = session.query(Project).order_by(Project.name).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "repo_url": p.repo_url,
            "target_url": p.target_url,
            "open_findings": open_counts.get(p.id, 0),
        }
        for p in projects
    ]


@app.get("/projects/{project_name}/findings", dependencies=[Depends(require_api_key)])
def list_findings(
    project_name: str,
    status: str = "open",
    severity: str | None = None,
    tool: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    project = get_project_or_404(session, project_name)

    query = (
        session.query(Finding)
        .filter(Finding.project_id == project.id)
        .filter(Finding.status == status)
    )
    if severity:
        query = query.filter(Finding.severity_normalized == severity)
    if tool:
        query = query.filter(Finding.tool == tool)

    total = query.count()
    findings = (
        query.order_by(Finding.risk_score.desc().nulls_last(), Finding.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": f.id,
                "title": f.title,
                "tool": f.tool,
                "rule_id": f.tool_rule_id,
                "severity": f.severity_normalized,
                "risk_score": f.risk_score,
                "cvss_score": f.cvss_score,
                "epss_score": f.epss_score,
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
                "location_type": f.location_type,
                "location": f.location,
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
            }
            for f in findings
        ],
    }
@app.get("/scan-jobs/{job_id}", dependencies=[Depends(require_api_key)])
def get_scan_job(job_id: int, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"ไม่พบ ScanJob {job_id}")

    runs = session.query(ScanRun).filter(ScanRun.scan_job_id == job.id).order_by(ScanRun.id).all()
    return {
        "id": job.id,
        "project_id": job.project_id,
        "status": job.status,
        "requested_scans": job.requested_scans,
        "created_at": job.created_at,
        "runs": [
            {
                "tool": r.tool,
                "status": r.status,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "error_message": r.error_message,
            }
            for r in runs
        ],
    }
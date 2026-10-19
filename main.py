import logging
import os
import secrets
from datetime import datetime
from typing import Literal

import redis

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import APIKeyHeader
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import String, cast, func, or_, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from db import engine
from models import Finding, Project, Report, ScanJob, ScanRun, User
from auth import LoginRateLimiter, hash_password, verify_password
from pydantic import BaseModel, Field
from save_findings import create_scan_job, get_or_create_project
from scan_policy import is_repo_allowed, is_url_allowed, resolve_scans, split_setting
from scan_queue import enqueue_scan
from security_gate import SEVERITY_ORDER


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
app = FastAPI(title="VulnCompass API", description="ดูผลสแกนช่องโหว่จากฐานข้อมูล")

SESSION_MAX_AGE = 8 * 60 * 60

session_secret = os.getenv("SESSION_SECRET")
if not session_secret:
    # ไม่มีค่าใน .env ให้สุ่มใหม่ทุกครั้งที่เปิด API: ยังปลอดภัย แต่ทุกคนต้อง login ใหม่หลัง restart
    session_secret = secrets.token_urlsafe(32)
    print("คำเตือน: ไม่ได้ตั้ง SESSION_SECRET ใน .env ทุกคนจะต้อง login ใหม่ทุกครั้งที่ restart API")

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    session_cookie="vc_session",
    max_age=SESSION_MAX_AGE,
    same_site="strict",
    https_only=os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true",
)

logger = logging.getLogger("uvicorn.error")


@app.exception_handler(OperationalError)
def database_unavailable(request: Request, exc: OperationalError):
    # ฐานข้อมูลปิดหรือต่อไม่ได้ ไม่ใช่บั๊กในโค้ด จึงตอบ 503 (ลองใหม่ได้) แทน 500
    # รายละเอียด error มี host และ port ของฐานข้อมูล บันทึกไว้ฝั่ง server เท่านั้น ไม่ส่งให้ผู้ใช้
    logger.error("ต่อฐานข้อมูลไม่ได้ (%s %s): %s", request.method, request.url.path, exc.orig)
    return JSONResponse(status_code=503, content={"detail": "ฐานข้อมูลไม่พร้อมใช้งาน กรุณาลองใหม่ภายหลัง"})


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


def get_current_user(request: Request, db: Session = Depends(get_session)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    # เช็ก is_active ทุกครั้ง: ปิดบัญชีแล้ว cookie เก่าต้องใช้ไม่ได้ทันที
    if user is None or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=401, detail="กรุณา login")
    return user


def require_auth(
    request: Request,
    api_key: str | None = Depends(api_key_header),
    db: Session = Depends(get_session),
) -> str:
    # CI/CD ส่ง API key มา ส่วน browser ส่ง session cookie มา ผ่านอย่างใดอย่างหนึ่งก็พอ
    # คืนค่าว่าใครเป็นคนเรียก เพื่อบันทึกลง triggered_by
    if api_key is not None:
        require_api_key(api_key)
        return "api"
    user = get_current_user(request, db)
    return f"web:{user.username}"


def get_project_or_404(session, project_name: str) -> Project:
    project = session.query(Project).filter(Project.name == project_name).first()
    if project is None:
        raise HTTPException(status_code=404, detail=f"ไม่พบโปรเจกต์ '{project_name}'")
    return project


def like_pattern(text: str) -> str:
    # escape ตัวพิเศษของ LIKE ให้เป็นตัวอักษรธรรมดา ผู้ใช้จะได้ส่ง wildcard มาเองไม่ได้
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@app.get("/health")
def health_check(session: Session = Depends(get_session)):
    try:
        session.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="ต่อฐานข้อมูลไม่ได้")
    return {"status": "ok", "database": "ok"}


@app.get("/projects", dependencies=[Depends(require_auth)])
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


@app.get("/projects/{project_name}/findings", dependencies=[Depends(require_auth)])
def list_findings(
    project_name: str,
    status: str = "open",
    severity: str | None = None,
    tool: str | None = None,
    q: str | None = Query(None, max_length=100),
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
    if q:
        pattern = like_pattern(q)
        query = query.filter(
            or_(
                Finding.title.ilike(pattern, escape="\\"),
                Finding.tool_rule_id.ilike(pattern, escape="\\"),
                Finding.cwe_id.ilike(pattern, escape="\\"),
                cast(Finding.location, String).ilike(pattern, escape="\\"),
            )
        )

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




@app.get("/projects/{project_name}/summary", dependencies=[Depends(require_auth)])
def project_summary(project_name: str, session: Session = Depends(get_session)):
    project = get_project_or_404(session, project_name)
    open_findings = (
        session.query(Finding)
        .filter(Finding.project_id == project.id)
        .filter(Finding.status == "open")
    )

    # ให้ฐานข้อมูลนับด้วย GROUP BY แทนการดึงทุกแถวมานับใน Python
    severity_counts = dict(
        open_findings.with_entities(Finding.severity_normalized, func.count(Finding.id))
        .group_by(Finding.severity_normalized)
        .all()
    )
    tool_counts = dict(
        open_findings.with_entities(Finding.tool, func.count(Finding.id))
        .group_by(Finding.tool)
        .all()
    )

    last_job = (
        session.query(ScanJob)
        .filter(ScanJob.project_id == project.id)
        .order_by(ScanJob.id.desc())
        .first()
    )
    last_scan = None
    if last_job is not None:
        last_scan = {
            "id": last_job.id,
            "status": last_job.status,
            "triggered_by": last_job.triggered_by,
            "created_at": last_job.created_at,
        }

    return {
        "project": project.name,
        "open_total": sum(severity_counts.values()),
        "by_severity": {severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER},
        "by_tool": tool_counts,
        "last_scan": last_scan,
    }


@app.get("/projects/{project_name}/scan-jobs", dependencies=[Depends(require_auth)])
def list_scan_jobs(
    project_name: str,
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_session),
):
    project = get_project_or_404(session, project_name)
    jobs = (
        session.query(ScanJob)
        .filter(ScanJob.project_id == project.id)
        .order_by(ScanJob.id.desc())
        .limit(limit)
        .all()
    )

    # ดึงครั้งเดียวว่างานไหนมี report แล้ว แทนการ query ทีละงาน (ปัญหา N+1 query)
    job_ids = [job.id for job in jobs]
    with_report = {
        job_id
        for (job_id,) in session.query(Report.scan_job_id).filter(Report.scan_job_id.in_(job_ids)).distinct()
    }

    return [
        {
            "id": job.id,
            "status": job.status,
            "triggered_by": job.triggered_by,
            "requested_scans": job.requested_scans,
            "created_at": job.created_at,
            "has_report": job.id in with_report,
        }
        for job in jobs
    ]


@app.get("/scan-jobs/{job_id}", dependencies=[Depends(require_auth)])
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


class ScanRequest(BaseModel):
    project: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    scans: list[Literal["sast", "dependency", "container", "dast"]] | None = None
    repo_path: str | None = Field(None, max_length=500)
    # ห้ามขึ้นต้นด้วย - เพื่อไม่ให้ Trivy อ่านเป็น option และห้ามมีช่องว่างหรือ ;
    image: str | None = Field(None, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
    target_url: str | None = Field(None, max_length=500)
    with_remediation: bool = False


@app.post("/scans", status_code=202)
def create_scan(
    request: ScanRequest,
    triggered_by: str = Depends(require_auth),
    session: Session = Depends(get_session),
):
    try:
        scans = resolve_scans(request.scans, request.repo_path, request.image, request.target_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    repo_path = None
    if request.repo_path:
        allowed_roots = split_setting(os.getenv("SCAN_ALLOWED_REPO_ROOTS"), ";")
        if not is_repo_allowed(request.repo_path, allowed_roots):
            raise HTTPException(status_code=400, detail="repo_path ไม่อยู่ในโฟลเดอร์ที่อนุญาต (SCAN_ALLOWED_REPO_ROOTS)")
        if not os.path.isdir(request.repo_path):
            raise HTTPException(status_code=400, detail="ไม่พบโฟลเดอร์ repo_path")
        repo_path = os.path.realpath(request.repo_path)

    if request.target_url:
        allowed_hosts = split_setting(os.getenv("SCAN_ALLOWED_HOSTS"), ",")
        if not is_url_allowed(request.target_url, allowed_hosts):
            raise HTTPException(status_code=400, detail="target_url ไม่อยู่ในรายชื่อ host ที่อนุญาต (SCAN_ALLOWED_HOSTS)")

    project = get_or_create_project(session, request.project, repo_path=repo_path, target_url=request.target_url)
    scan_job = create_scan_job(session, project, scans, triggered_by=triggered_by)

    try:
        enqueue_scan(
            scan_job.id,
            repo_path=repo_path,
            image=request.image,
            target_url=request.target_url,
            with_remediation=request.with_remediation,
        )
    except redis.exceptions.RedisError:
        # ถ้าใส่คิวไม่ได้ งานจะค้าง queued ตลอดไป จึงต้องตั้งเป็น failed ทันที
        scan_job.status = "failed"
        session.commit()
        raise HTTPException(status_code=503, detail="ใส่งานเข้าคิวไม่ได้ (Redis ไม่ทำงาน)")

    return {
        "scan_job_id": scan_job.id,
        "status": scan_job.status,
        "status_url": f"/scan-jobs/{scan_job.id}",
    }

def report_file_response(report: Report, project_name: str, inline: bool = False) -> FileResponse:
    # รายงานที่สร้างบน Windows เก็บ path เป็น reports\... แปลงเป็น / ซึ่งใช้ได้ทั้ง Windows และ Linux (Docker)
    path = (report.file_path or "").replace("\\", "/")
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    # file_path มาจากฐานข้อมูล ตรวจซ้ำว่าอยู่ใต้ reports/ จริง ไม่อย่างนั้นอาจส่งไฟล์อย่าง .env ออกไปได้
    if not is_repo_allowed(path, [REPORTS_DIR]) or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="ไม่พบไฟล์รายงาน")
    filename = f"{project_name}_scanjob{report.scan_job_id}_security_report.pdf"
    # inline = เปิดดูในแท็บใหม่ (กดพิมพ์จากตัวดู PDF ได้) / attachment = ดาวน์โหลดเป็นไฟล์
    disposition = "inline" if inline else "attachment"
    return FileResponse(path, media_type="application/pdf", filename=filename, content_disposition_type=disposition)


@app.get("/scan-jobs/{job_id}/report", dependencies=[Depends(require_auth)])
def download_scan_job_report(job_id: int, inline: bool = False, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"ไม่พบ ScanJob {job_id}")

    report = (
        session.query(Report)
        .filter(Report.scan_job_id == job.id)
        .order_by(Report.id.desc())
        .first()
    )
    if report is None:
        raise HTTPException(status_code=404, detail="ScanJob นี้ยังไม่มีรายงาน (ยังสแกนไม่เสร็จ หรือสั่งแบบไม่สร้างรายงาน)")

    project = session.get(Project, job.project_id)
    return report_file_response(report, project.name, inline)


@app.get("/projects/{project_name}/report", dependencies=[Depends(require_auth)])
def download_latest_project_report(project_name: str, inline: bool = False, session: Session = Depends(get_session)):
    project = get_project_or_404(session, project_name)

    report = (
        session.query(Report)
        .join(ScanJob, Report.scan_job_id == ScanJob.id)
        .filter(ScanJob.project_id == project.id)
        .order_by(Report.id.desc())
        .first()
    )
    if report is None:
        raise HTTPException(status_code=404, detail="โปรเจกต์นี้ยังไม่มีรายงาน")

    return report_file_response(report, project.name, inline)


# ใช้ตอนไม่พบ user ให้ใช้เวลาตรวจเท่ากับ user ที่มีอยู่จริง
# คนร้ายจะจับเวลาตอบกลับแล้วเดาไม่ได้ว่า username ไหนมีอยู่ในระบบ
DUMMY_PASSWORD_HASH = hash_password("dummy-password-for-timing")
login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=15 * 60)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


@app.post("/auth/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_session)):
    client_ip = request.client.host if request.client else "unknown"
    limit_key = f"{client_ip}:{body.username.lower()}"
    if login_limiter.is_blocked(limit_key):
        raise HTTPException(status_code=429, detail="login ผิดหลายครั้งเกินไป กรุณารอ 15 นาที")

    user = db.query(User).filter(User.username == body.username).first()
    password_ok = verify_password(user.password_hash if user else DUMMY_PASSWORD_HASH, body.password)
    if user is None or not password_ok or not user.is_active:
        login_limiter.record_failure(limit_key)
        # ข้อความเดียวกันทุกกรณี ไม่บอกว่าผิดที่ username หรือรหัสผ่าน
        raise HTTPException(status_code=401, detail="username หรือรหัสผ่านไม่ถูกต้อง")

    login_limiter.reset(limit_key)
    user.last_login_at = datetime.utcnow()
    db.commit()

    request.session.clear()
    request.session["user_id"] = user.id
    return {"username": user.username}


@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username}


@app.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"status": "logged out"}


from sqlalchemy import String, ForeignKey, Text, Float, JSON, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from datetime import datetime
from sqlalchemy.dialects.postgresql import ARRAY


class Base(DeclarativeBase):
    pass

class Project(Base):
    __tablename__ = "project"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    repo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

class ScanJob(Base):
    __tablename__ = "scanjob"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id"))
    status: Mapped[str] = mapped_column(String(20), default="queued")    
    triggered_by: Mapped[str] = mapped_column(String(50), default="manual")
    created_at: Mapped[datetime | None] = mapped_column(nullable=True)
    requested_scans: Mapped[list[str]] = mapped_column(ARRAY(String))

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scanjob.id"))
    tool: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    rew_output_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_findings_project_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"))
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(50))
    tool_rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity_normalized: Mapped[str] = mapped_column(String(10))
    severity_native: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    epss_score: Mapped[float | None] = mapped_column(nullable=True)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(120), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    location_type: Mapped[str] = mapped_column(String(20))
    location: Mapped[dict] = mapped_column(JSON)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True) 
    status: Mapped[str] = mapped_column(String(20), default="open")
    first_seen: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    

class Report(Base):
    __tablename__ = "reports" 

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scanjob.id"))
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    generated_at:   Mapped[datetime] = mapped_column(default=datetime.utcnow) 


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)


class CweOwaspMapping(Base):
    __tablename__ = "cwe_owasp_mapping"

    cwe_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    owasp_top10_2021: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_workaround: Mapped[str | None] = mapped_column(Text, nullable=True)








    












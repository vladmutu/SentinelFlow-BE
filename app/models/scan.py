"""ORM models for malware-scan jobs and per-package scan results."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ScanJob(Base):
    """Represents a single malware-scan run triggered for a repository."""

    __tablename__ = "scan_jobs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)  # "npm" | "pypi"
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending",
    )  # pending → running → completed | failed
    total_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scanned_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_dependency_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_unique_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    results: Mapped[list["ScanResult"]] = relationship(
        "ScanResult", back_populates="job", cascade="all, delete-orphan", lazy="selectin",
    )

    __table_args__ = (
        Index("ix_scan_jobs_owner_repo", "owner", "repo_name"),
    )


class ScanResult(Base):
    """Stores the malware-scan verdict for a single package within a scan job."""

    __tablename__ = "scan_results"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_name: Mapped[str] = mapped_column(String(512), nullable=False)
    package_version: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)
    malware_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="unknown",
    )  # clean | malicious | error | unknown
    malware_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    scanner_version: Mapped[str] = mapped_column(String(100), nullable=False, default="1.0.0")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="results")

    __table_args__ = (
        Index("ix_scan_results_job_id", "job_id"),
        Index("ix_scan_results_package", "package_name", "package_version", "ecosystem"),
    )

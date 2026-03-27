from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IpRange(Base):
    __tablename__ = "ip_ranges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    spec: Mapped[str] = mapped_column(String(256))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    created_by_user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_range_id: Mapped[int] = mapped_column(Integer, ForeignKey("ip_ranges.id"))

    requested_by_user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    request_ip_snapshot: Mapped[str] = mapped_column(String(64), default="unknown")
    range_name_snapshot: Mapped[str] = mapped_column(String(128))
    spec_snapshot: Mapped[str] = mapped_column(String(256))

    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)

    total_ips: Mapped[int] = mapped_column(Integer, default=0)
    completed_ips: Mapped[int] = mapped_column(Integer, default=0)
    online_ips: Mapped[int] = mapped_column(Integer, default=0)
    hash_rate_sum: Mapped[float | None] = mapped_column(Float, nullable=True)

    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceResult(Base):
    __tablename__ = "device_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_jobs.id"), index=True)

    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    ip_octet_a: Mapped[int] = mapped_column(Integer, index=True)
    ip_octet_b: Mapped[int] = mapped_column(Integer, index=True)
    ip_octet_c: Mapped[int] = mapped_column(Integer, index=True)
    ip_octet_d: Mapped[int] = mapped_column(Integer, index=True)

    is_online: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    mhs_av: Mapped[float | None] = mapped_column(Float, nullable=True)

    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hwtype: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prod: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    api_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # For the Issues tab (aggregated)
    error_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Raw response(s) can be large; useful for debugging parse/protocol issues.
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    event_type: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    request_ip: Mapped[str] = mapped_column(String(64), default="unknown")
    metadata_json: Mapped[str | None] = mapped_column("metadata", Text, nullable=True)


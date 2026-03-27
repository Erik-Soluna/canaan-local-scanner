from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, User


def log_event(
    db: Session,
    *,
    user_id: int | None,
    request_ip: str,
    event_type: str,
    target_type: str,
    target_id: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    entry = AuditLog(
        ts=datetime.utcnow(),
        user_id=user_id,
        event_type=event_type,
        target_type=target_type,
        target_id=target_id,
        request_ip=request_ip or "unknown",
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(entry)
    db.commit()


def sample_audit_troubleshooting(db: Session, target_scan_job_id: int) -> list[AuditLog]:
    # Not used in the UI initially; useful during debugging.
    stmt = select(AuditLog).where(AuditLog.target_type == "scan_job", AuditLog.target_id == str(target_scan_job_id)).order_by(AuditLog.ts.desc()).limit(20)
    return list(db.execute(stmt).scalars().all())


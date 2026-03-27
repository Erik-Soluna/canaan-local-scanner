"""Persist deploy webhook URL/secret in SQLite (Settings UI); env remains optional fallback."""

from __future__ import annotations

import os

from sqlalchemy.orm import Session

from .models import DeployWebhookSetting


def get_or_create_row(db: Session) -> DeployWebhookSetting:
    row = db.get(DeployWebhookSetting, 1)
    if row is None:
        row = DeployWebhookSetting(id=1, webhook_url=None, webhook_secret=None)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def resolve_deploy_webhook(db: Session) -> tuple[str, str]:
    """Merge DB (when set) with env. DB URL wins over env when non-empty; secret uses DB if set, else env."""
    row = db.get(DeployWebhookSetting, 1)
    db_url = (row.webhook_url or "").strip() if row else ""
    db_secret = (row.webhook_secret or "").strip() if row else ""
    url = db_url or os.getenv("DEPLOY_WEBHOOK_URL", "").strip()
    secret = db_secret or os.getenv("DEPLOY_WEBHOOK_SECRET", "").strip()
    return url, secret

from __future__ import annotations

import io
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Query, Request
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, or_, select, delete, and_
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import audit
from .auth import create_initial_admin_if_missing, get_current_user, verify_password
from .db import ENGINE, SessionLocal
from .models import DeviceResult, IpRange, ScanJob, User
from .deploy_webhook_settings import get_or_create_row, resolve_deploy_webhook
from .parsing import format_hash_rate_mhs
from .scanner import ip_expansion_count, run_scan_job_background
from .update_check import build_update_payload, get_deploy_sha, trigger_deploy_webhook


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["hash_rate"] = format_hash_rate_mhs

DEBUG_EXPORT_MAX_BYTES = int(os.getenv("DEBUG_EXPORT_MAX_BYTES", str(50 * 1024 * 1024)))


class DeployWebhookSave(BaseModel):
    webhook_url: str = ""
    webhook_secret: str | None = None  # None = leave secret unchanged; "" = clear


def _utf8_bom_bytes(text: str) -> bytes:
    """UTF-8 with BOM so Windows Notepad detects encoding (avoids mojibake)."""
    return "\ufeff".encode("utf-8") + text.encode("utf-8")

def get_client_ip(request: Request) -> str:
    try:
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    return "unknown"


app = FastAPI(title="Canaan A15 IP Scanner")

session_secret = os.getenv("SESSION_SECRET", "dev-change-me")
app.add_middleware(SessionMiddleware, secret_key=session_secret)


@app.on_event("startup")
def on_startup() -> None:
    # Create tables (no migrations to keep this from-scratch setup simple).
    from .db import Base

    Base.metadata.create_all(ENGINE)
    # Seed an admin user if none exists.
    session: Session = SessionLocal()
    try:
        create_initial_admin_if_missing(session)
    finally:
        session.close()


def require_user(request: Request, db: Session) -> User | None:
    return get_current_user(db, request)


def redirect_to_login() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=RedirectResponse)
def root(request: Request):
    db = SessionLocal()
    try:
        user = require_user(request, db)
    finally:
        db.close()
    if not user:
        return redirect_to_login()
    return RedirectResponse(url="/ranges", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request, error: str | None = None):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": error, "username_prefill": ""},
        status_code=200,
    )


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if user is None or not user.is_enabled:
            return login_get(request, error="Invalid username or disabled account")
        if not verify_password(password, user.password_hash):
            return login_get(request, error="Invalid password")

        request.session["user_id"] = user.id
        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="USER_LOGIN",
            target_type="user",
            target_id=str(user.id),
            metadata={"username": user.username},
        )
        return RedirectResponse(url="/ranges", status_code=303)
    finally:
        db.close()


@app.post("/logout", response_class=RedirectResponse)
def logout_post(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/ranges", response_class=HTMLResponse)
def ranges_get(request: Request):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        ranges = list(db.execute(select(IpRange).order_by(IpRange.created_at.desc())).scalars().all())
        return templates.TemplateResponse(
            "ranges.html",
            {"request": request, "user": user, "ranges": ranges, "error": None},
        )
    finally:
        db.close()


@app.get("/jobs", response_class=HTMLResponse)
def jobs_history_get(
    request: Request,
    range_id: int | None = None,
    status: str | None = None,
    limit: int = 50,
):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        limit = max(1, min(int(limit or 50), 200))

        stmt = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
        if range_id:
            stmt = stmt.where(ScanJob.ip_range_id == range_id)
        if status:
            stmt = stmt.where(ScanJob.status == status)

        jobs = list(db.execute(stmt).scalars().all())
        ranges = list(db.execute(select(IpRange).order_by(IpRange.name.asc())).scalars().all())
        return templates.TemplateResponse(
            "history.html",
            {
                "request": request,
                "user": user,
                "jobs": jobs,
                "ranges": ranges,
                "filter_range_id": range_id,
                "filter_status": status,
                "limit": limit,
            },
        )
    finally:
        db.close()


@app.get("/settings", response_class=HTMLResponse)
def settings_get(request: Request):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()
        ctx: dict = {"request": request, "user": user, "title": "Settings"}
        if user.is_admin:
            row = get_or_create_row(db)
            ctx["deploy_webhook_url"] = row.webhook_url or ""
            ctx["deploy_webhook_secret_set"] = bool((row.webhook_secret or "").strip())
        return templates.TemplateResponse("settings.html", ctx)
    finally:
        db.close()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_get(request: Request, limit: int = 50):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        limit = max(1, min(int(limit or 50), 200))
        recent_jobs = list(
            db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)).scalars().all()
        )

        last_job = recent_jobs[0] if recent_jobs else None
        last_completed = next((j for j in recent_jobs if j.status == "completed"), None)
        completed_jobs = [j for j in recent_jobs if j.status == "completed"]
        failed_jobs = [j for j in recent_jobs if j.status == "failed"]

        def avg(nums: list[float]) -> float:
            if not nums:
                return 0.0
            return float(sum(nums) / len(nums))

        stats = {
            "total_jobs": len(recent_jobs),
            "completed_jobs": len(completed_jobs),
            "failed_jobs": len(failed_jobs),
            "avg_online": avg([float(j.online_ips or 0) for j in completed_jobs]),
            "avg_hash_sum": avg([float(j.hash_rate_sum or 0.0) for j in completed_jobs]),
        }

        admin_jobs = recent_jobs if user.is_admin else []

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                "limit": limit,
                "last_job": last_job,
                "last_completed_job_id": last_completed.id if last_completed else None,
                "stats": stats,
                "admin_jobs": admin_jobs,
            },
        )
    finally:
        db.close()


@app.post("/ranges", response_class=HTMLResponse)
def ranges_create(
    request: Request,
    name: str = Form(...),
    spec: str = Form(...),
):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        name = name.strip()
        spec = spec.strip()
        try:
            total_ips = ip_expansion_count(spec)
        except Exception as e:
            ranges = list(db.execute(select(IpRange).order_by(IpRange.created_at.desc())).scalars().all())
            return templates.TemplateResponse(
                "ranges.html",
                {"request": request, "user": user, "ranges": ranges, "error": f"Invalid IP spec: {e}"},
                status_code=400,
            )

        ip_range = IpRange(name=name, spec=spec, enabled=True, created_by_user_id=user.id)
        db.add(ip_range)
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="RANGE_CREATE",
            target_type="ip_range",
            target_id=str(ip_range.id),
            metadata={"name": name, "spec": spec, "expanded_ips": total_ips},
        )
        return RedirectResponse(url="/ranges", status_code=303)
    finally:
        db.close()


@app.post("/ranges/{range_id}/toggle", response_class=RedirectResponse)
def ranges_toggle(request: Request, range_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        ip_range = db.execute(select(IpRange).where(IpRange.id == range_id)).scalar_one_or_none()
        if not ip_range:
            return RedirectResponse(url="/ranges", status_code=303)

        ip_range.enabled = not bool(ip_range.enabled)
        db.commit()
        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="RANGE_TOGGLE",
            target_type="ip_range",
            target_id=str(ip_range.id),
            metadata={"enabled": ip_range.enabled, "name": ip_range.name},
        )
        return RedirectResponse(url="/ranges", status_code=303)
    finally:
        db.close()


@app.get("/ranges/{range_id}/edit", response_class=HTMLResponse)
def range_edit_get(request: Request, range_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        ip_range = db.execute(select(IpRange).where(IpRange.id == range_id)).scalar_one_or_none()
        if not ip_range:
            return RedirectResponse(url="/ranges", status_code=303)

        return templates.TemplateResponse(
            "range_form.html",
            {"request": request, "user": user, "mode": "edit", "range": ip_range, "error": None},
        )
    finally:
        db.close()


@app.post("/ranges/{range_id}/edit", response_class=HTMLResponse)
def range_edit_post(
    request: Request,
    range_id: int,
    name: str = Form(...),
    spec: str = Form(...),
):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        ip_range = db.execute(select(IpRange).where(IpRange.id == range_id)).scalar_one_or_none()
        if not ip_range:
            return RedirectResponse(url="/ranges", status_code=303)

        name = name.strip()
        spec = spec.strip()
        try:
            total_ips = ip_expansion_count(spec)
        except Exception as e:
            return templates.TemplateResponse(
                "range_form.html",
                {"request": request, "user": user, "mode": "edit", "range": ip_range, "error": f"Invalid spec: {e}"},
                status_code=400,
            )

        ip_range.name = name
        ip_range.spec = spec
        db.commit()
        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="RANGE_UPDATE",
            target_type="ip_range",
            target_id=str(ip_range.id),
            metadata={"name": name, "spec": spec, "expanded_ips": total_ips},
        )

        return RedirectResponse(url="/ranges", status_code=303)
    finally:
        db.close()


@app.post("/ranges/{range_id}/delete", response_class=RedirectResponse)
def range_delete_post(request: Request, range_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        ip_range = db.execute(select(IpRange).where(IpRange.id == range_id)).scalar_one_or_none()
        if not ip_range:
            return RedirectResponse(url="/ranges", status_code=303)

        # Best-effort cleanup.
        jobs = list(db.execute(select(ScanJob).where(ScanJob.ip_range_id == ip_range.id)).scalars().all())
        for job in jobs:
            db.execute(delete(DeviceResult).where(DeviceResult.scan_job_id == job.id))
        db.execute(delete(ScanJob).where(ScanJob.ip_range_id == ip_range.id))
        db.delete(ip_range)
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="RANGE_DELETE",
            target_type="ip_range",
            target_id=str(ip_range.id),
            metadata={"name": ip_range.name},
        )
        return RedirectResponse(url="/ranges", status_code=303)
    finally:
        db.close()


@app.post("/scan/range/{range_id}", response_class=RedirectResponse)
def scan_start_post(request: Request, range_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        ip_range = db.execute(select(IpRange).where(IpRange.id == range_id)).scalar_one_or_none()
        if not ip_range:
            return RedirectResponse(url="/ranges", status_code=303)

        spec = ip_range.spec
        expanded_ips = ip_expansion_count(spec)

        scan_job = ScanJob(
            ip_range_id=ip_range.id,
            requested_by_user_id=user.id,
            request_ip_snapshot=get_client_ip(request),
            range_name_snapshot=ip_range.name,
            spec_snapshot=ip_range.spec,
            status="queued",
            total_ips=expanded_ips,
            completed_ips=0,
            online_ips=0,
            hash_rate_sum=0.0,
            error_message=None,
        )
        db.add(scan_job)
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="SCAN_START",
            target_type="scan_job",
            target_id=str(scan_job.id),
            metadata={"range_id": ip_range.id, "range_name": ip_range.name, "spec": ip_range.spec, "expanded_ips": expanded_ips},
        )

        # Start background scanning in a new daemon thread.
        import threading

        t = threading.Thread(
            target=run_scan_job_background,
            args=(scan_job.id,),
            daemon=True,
        )
        t.start()

        return RedirectResponse(url=f"/jobs/{scan_job.id}", status_code=303)
    finally:
        db.close()


def _device_results_agg_by_c(db: Session, scan_job_id: int) -> list[dict]:
    row_stmt = (
        select(
            DeviceResult.ip_octet_c.label("c"),
            func.count(DeviceResult.id).label("attempted_count"),
            func.sum(case((DeviceResult.is_online == True, 1), else_=0)).label("online_count"),
            func.sum(case((DeviceResult.is_online == True, DeviceResult.mhs_av), else_=0)).label("mhs_sum"),
        )
        .where(DeviceResult.scan_job_id == scan_job_id)
        .group_by(DeviceResult.ip_octet_c)
        .order_by(DeviceResult.ip_octet_c.asc())
    )
    rows = list(db.execute(row_stmt).mappings().all())
    # Convert values safely for templates (RowMapping is immutable).
    fixed: list[dict] = []
    for r in rows:
        fixed.append(
            {
                "c": r["c"],
                "attempted_count": int(r["attempted_count"] or 0),
                "online_count": int(r["online_count"] or 0),
                "mhs_sum": float(r["mhs_sum"] or 0.0),
            }
        )
    return fixed


@app.get("/api/jobs/recent", response_class=JSONResponse)
def api_recent_jobs(request: Request, limit: int = 50):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        limit = max(1, min(int(limit or 50), 200))
        jobs = list(db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)).scalars().all())
        return {
            "jobs": [
                {
                    "id": j.id,
                    "created_at": j.created_at.isoformat(),
                    "status": j.status,
                    "range_name": j.range_name_snapshot,
                    "total_ips": j.total_ips,
                    "completed_ips": j.completed_ips,
                    "online_ips": j.online_ips,
                    "hash_rate_sum": float(j.hash_rate_sum or 0.0),
                }
                for j in jobs
            ]
        }
    finally:
        db.close()


@app.get("/api/jobs/{job_id}/status", response_class=JSONResponse)
def api_job_status(request: Request, job_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        j = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not j:
            return JSONResponse({"error": "not_found"}, status_code=404)

        return {
            "id": j.id,
            "status": j.status,
            "created_at": j.created_at.isoformat(),
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            "total_ips": j.total_ips,
            "completed_ips": j.completed_ips,
            "online_ips": j.online_ips,
            "hash_rate_sum": float(j.hash_rate_sum or 0.0),
            "error_message": j.error_message,
        }
    finally:
        db.close()


@app.get("/api/jobs/{job_id}/agg_by_c", response_class=JSONResponse)
def api_job_agg_by_c(request: Request, job_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        j = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not j:
            return JSONResponse({"error": "not_found"}, status_code=404)

        buckets = _device_results_agg_by_c(db, job_id)
        return {"job_id": job_id, "buckets": buckets}
    finally:
        db.close()


@app.get("/api/jobs/errors-trend", response_class=JSONResponse)
def api_errors_trend(request: Request, limit: int = 50, top: int = 5):
    """
    Returns stacked-bar compatible series across recent jobs for top error types.
    """
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        limit = max(1, min(int(limit or 50), 200))
        top = max(1, min(int(top or 5), 20))

        jobs = list(db.execute(select(ScanJob.id, ScanJob.created_at).order_by(ScanJob.created_at.desc()).limit(limit)).all())
        job_ids = [int(r[0]) for r in jobs]
        labels = [r[1].isoformat() for r in jobs][::-1]
        job_ids_asc = job_ids[::-1]

        if not job_ids:
            return {"labels": [], "series": []}

        # counts per job_id,error_type
        counts_rows = list(
            db.execute(
                select(DeviceResult.scan_job_id, DeviceResult.error_type, func.count(DeviceResult.id))
                .where(DeviceResult.scan_job_id.in_(job_ids), DeviceResult.error_type.is_not(None))
                .group_by(DeviceResult.scan_job_id, DeviceResult.error_type)
            ).all()
        )

        total_by_type: dict[str, int] = {}
        by_job: dict[int, dict[str, int]] = {}
        for jid, et, cnt in counts_rows:
            et = str(et)
            cnt_i = int(cnt)
            total_by_type[et] = total_by_type.get(et, 0) + cnt_i
            by_job.setdefault(int(jid), {})[et] = cnt_i

        top_types = [t for t, _ in sorted(total_by_type.items(), key=lambda kv: kv[1], reverse=True)[:top]]

        series = []
        for et in top_types:
            series.append(
                {
                    "error_type": et,
                    "counts": [int(by_job.get(jid, {}).get(et, 0)) for jid in job_ids_asc],
                }
            )

        return {"labels": labels, "series": series}
    finally:
        db.close()


def _devices_where(
    job_id: int,
    c: int | None,
    online: bool | None,
    q: str | None,
    errors_only: bool,
):
    parts: list = [DeviceResult.scan_job_id == job_id]
    if c is not None:
        parts.append(DeviceResult.ip_octet_c == c)
    if online is True:
        parts.append(DeviceResult.is_online == True)  # noqa: E712
    elif online is False:
        parts.append(DeviceResult.is_online == False)  # noqa: E712
    if q and q.strip():
        parts.append(DeviceResult.ip_address.like(f"{q.strip()}%"))
    if errors_only:
        parts.append(
            or_(
                DeviceResult.error_type.is_not(None),
                and_(DeviceResult.error_message.is_not(None), DeviceResult.error_message != ""),
            )
        )
    return and_(*parts)


@app.get("/api/update-status", response_class=JSONResponse)
def api_update_status(request: Request, refresh: bool = Query(False)):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        deployed = get_deploy_sha(BASE_DIR)
        return build_update_payload(deployed, force_refresh=refresh)
    finally:
        db.close()


@app.get("/api/deploy-webhook-settings", response_class=JSONResponse)
def api_deploy_webhook_settings_get(request: Request):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not user.is_admin:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        row = get_or_create_row(db)
        return JSONResponse(
            {
                "webhook_url": row.webhook_url or "",
                "secret_set": bool((row.webhook_secret or "").strip()),
            }
        )
    finally:
        db.close()


@app.post("/api/deploy-webhook-settings", response_class=JSONResponse)
def api_deploy_webhook_settings_post(request: Request, body: DeployWebhookSave):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not user.is_admin:
            return JSONResponse({"error": "forbidden"}, status_code=403)

        row = get_or_create_row(db)
        row.webhook_url = body.webhook_url.strip() or None
        if body.webhook_secret is not None:
            row.webhook_secret = body.webhook_secret.strip() or None
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="DEPLOY_WEBHOOK_SETTINGS",
            target_type="settings",
            target_id="deploy_webhook",
            metadata={
                "webhook_url_set": bool(row.webhook_url),
                "secret_set": bool(row.webhook_secret),
            },
        )
        return JSONResponse({"ok": True})
    finally:
        db.close()


@app.post("/api/trigger-deploy", response_class=JSONResponse)
def api_trigger_deploy(request: Request):
    """Admin-only: POST deploy webhook when GitHub main is ahead of this deploy."""
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not user.is_admin:
            return JSONResponse({"error": "forbidden"}, status_code=403)

        deployed = get_deploy_sha(BASE_DIR)
        payload = build_update_payload(deployed, force_refresh=True)
        if not payload.get("update_available"):
            return JSONResponse(
                {
                    "ok": False,
                    "error": "no_update",
                    "message": "No update is available according to GitHub main.",
                },
                status_code=409,
            )

        hook_url, hook_secret = resolve_deploy_webhook(db)
        ok, http_status, err = trigger_deploy_webhook(hook_url, hook_secret)
        if err == "not_configured":
            return JSONResponse(
                {
                    "ok": False,
                    "error": "not_configured",
                    "message": "Set the deploy webhook below (admin) or DEPLOY_WEBHOOK_URL in the environment.",
                },
                status_code=503,
            )
        if not ok:
            return JSONResponse(
                {
                    "ok": False,
                    "error": "webhook_failed",
                    "message": err or "webhook request failed",
                    "http_status": http_status,
                },
                status_code=502,
            )

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="DEPLOY_TRIGGER",
            target_type="deploy",
            target_id=(payload.get("github_sha") or "")[:40],
            metadata={"http_status": http_status, "github_sha": payload.get("github_sha")},
        )
        return JSONResponse(
            {
                "ok": True,
                "message": "Deploy webhook accepted.",
                "http_status": http_status,
                "github_sha": payload.get("github_sha"),
            }
        )
    finally:
        db.close()


@app.get("/api/jobs/{job_id}/devices", response_class=JSONResponse)
def api_job_devices(
    request: Request,
    job_id: int,
    page: int = 1,
    page_size: int = 50,
    c: int | None = None,
    online: str | None = None,
    q: str | None = None,
    errors_only: bool = False,
):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        j = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not j:
            return JSONResponse({"error": "not_found"}, status_code=404)

        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 50), 200))
        online_bool = None
        if online in ("true", "1", "yes"):
            online_bool = True
        elif online in ("false", "0", "no"):
            online_bool = False

        where_clause = _devices_where(job_id, c, online_bool, q, errors_only)
        total = db.execute(select(func.count(DeviceResult.id)).where(where_clause)).scalar_one()
        total_i = int(total or 0)

        stmt = (
            select(DeviceResult)
            .where(where_clause)
            .order_by(DeviceResult.ip_address.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = list(db.execute(stmt).scalars().all())
        out = []
        for dr in rows:
            out.append(
                {
                    "ip_address": dr.ip_address,
                    "is_online": dr.is_online,
                    "mhs_av": float(dr.mhs_av) if dr.mhs_av is not None else None,
                    "mhs_av_formatted": format_hash_rate_mhs(dr.mhs_av),
                    "model": dr.model,
                    "prod": dr.prod,
                    "hwtype": dr.hwtype,
                    "device_version": dr.device_version,
                    "api_version": dr.api_version,
                    "error_type": dr.error_type,
                    "stage": dr.stage,
                    "error_message": ((dr.error_message or "")[:500] if dr.error_message else None),
                }
            )

        return {
            "job_id": job_id,
            "page": page,
            "page_size": page_size,
            "total": total_i,
            "rows": out,
        }
    finally:
        db.close()


@app.get("/jobs/{job_id}/devices", response_class=HTMLResponse)
def job_devices_list_get(request: Request, job_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()
        scan_job = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not scan_job:
            return RedirectResponse(url="/ranges", status_code=303)
        c_rows = db.execute(
            select(DeviceResult.ip_octet_c)
            .where(DeviceResult.scan_job_id == job_id)
            .distinct()
            .order_by(DeviceResult.ip_octet_c.asc())
        ).all()
        c_list = [int(r[0]) for r in c_rows]
        return templates.TemplateResponse(
            "devices_list.html",
            {"request": request, "user": user, "scan_job": scan_job, "c_list": c_list},
        )
    finally:
        db.close()


@app.get("/jobs/{job_id}/device", response_class=HTMLResponse)
def job_device_detail_get(request: Request, job_id: int, ip: str = Query(..., min_length=1)):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()
        ip = ip.strip()
        scan_job = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not scan_job:
            return RedirectResponse(url="/ranges", status_code=303)
        dr = db.execute(
            select(DeviceResult).where(
                DeviceResult.scan_job_id == job_id,
                DeviceResult.ip_address == ip,
            )
        ).scalar_one_or_none()
        if not dr:
            return templates.TemplateResponse(
                "device_detail.html",
                {
                    "request": request,
                    "user": user,
                    "scan_job": scan_job,
                    "device": None,
                    "missing_ip": ip,
                },
                status_code=404,
            )
        raw = dr.raw_response or ""
        raw_preview_len = 12000
        raw_truncated = len(raw) > raw_preview_len
        raw_show = raw[:raw_preview_len] if raw_truncated else raw
        return templates.TemplateResponse(
            "device_detail.html",
            {
                "request": request,
                "user": user,
                "scan_job": scan_job,
                "device": dr,
                "raw_show": raw_show,
                "raw_truncated": raw_truncated,
                "missing_ip": None,
            },
        )
    finally:
        db.close()


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail_get(request: Request, job_id: int):

    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        scan_job = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not scan_job:
            return RedirectResponse(url="/ranges", status_code=303)

        agg_by_c = _device_results_agg_by_c(db, job_id)
        return templates.TemplateResponse(
            "jobs.html",
            {
                "request": request,
                "user": user,
                "scan_job": scan_job,
                "agg_by_c": agg_by_c,
            },
        )
    finally:
        db.close()


@app.get("/jobs/{job_id}/issues", response_class=HTMLResponse)
def job_issues_get(request: Request, job_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()

        scan_job = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not scan_job:
            return RedirectResponse(url="/ranges", status_code=303)

        agg_stmt = (
            select(
                DeviceResult.error_type.label("error_type"),
                DeviceResult.stage.label("stage"),
                func.count(DeviceResult.id).label("count"),
            )
            .where(DeviceResult.scan_job_id == job_id, DeviceResult.error_type.is_not(None))
            .group_by(DeviceResult.error_type, DeviceResult.stage)
            .order_by(func.count(DeviceResult.id).desc())
            .limit(50)
        )
        agg_rows = list(db.execute(agg_stmt).mappings().all())

        # Pull examples for the top few error buckets.
        examples: list[dict] = []
        for bucket in agg_rows[:5]:
            et = bucket["error_type"]
            stage = bucket["stage"]
            ex_stmt = (
                select(DeviceResult.ip_address, DeviceResult.stage, DeviceResult.error_message, DeviceResult.raw_response)
                .where(DeviceResult.scan_job_id == job_id, DeviceResult.error_type == et)
                .order_by(DeviceResult.created_at.desc())
                .limit(5)
            )
            ex_rows = list(db.execute(ex_stmt).mappings().all())
            examples.append(
                {
                    "error_type": et,
                    "stage": stage,
                    "count": bucket["count"],
                    "examples": [
                        {
                            "ip": r["ip_address"],
                            "stage": r["stage"],
                            "message": (r["error_message"] or "")[:200],
                            "raw_preview": (r["raw_response"] or "")[:200],
                        }
                        for r in ex_rows
                    ],
                }
            )

        return templates.TemplateResponse(
            "issues.html",
            {"request": request, "user": user, "scan_job": scan_job, "agg_rows": agg_rows, "examples": examples},
        )
    finally:
        db.close()



@app.get("/admin/debug/export")
def admin_debug_export(
    request: Request,
    job_id: int | None = None,
    mode: str = "errors_only",
):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user or not user.is_admin:
            return redirect_to_login()

        mode_norm = (mode or "errors_only").strip().lower()
        if mode_norm not in ("errors_only", "all"):
            mode_norm = "errors_only"

        if job_id is None:
            last_c = db.execute(
                select(ScanJob)
                .where(ScanJob.status == "completed")
                .order_by(ScanJob.id.desc())
                .limit(1)
            ).scalar_one_or_none()
            if not last_c:
                last_c = db.execute(select(ScanJob).order_by(ScanJob.id.desc()).limit(1)).scalar_one_or_none()
            if not last_c:
                raise HTTPException(status_code=404, detail="No scan jobs found.")
            job_id = last_c.id

        job = db.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one_or_none()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")

        stmt = select(DeviceResult).where(DeviceResult.scan_job_id == job_id).order_by(DeviceResult.ip_address.asc())
        if mode_norm == "errors_only":
            stmt = stmt.where(
                or_(
                    DeviceResult.error_type.is_not(None),
                    and_(DeviceResult.error_message.is_not(None), DeviceResult.error_message != ""),
                )
            )
        rows = list(db.execute(stmt).scalars().all())

        buf = io.BytesIO()
        total_bytes = 0
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        zip_name = f"canaan-debug-job-{job_id}-{stamp}.zip"

        readme_lines = [
            "encoding=UTF-8 with BOM (open as UTF-8 if text looks wrong)",
            f"scan_job_id={job.id}",
            f"range_name={job.range_name_snapshot}",
            f"spec={job.spec_snapshot}",
            f"status={job.status}",
            f"total_ips={job.total_ips}",
            f"completed_ips={job.completed_ips}",
            f"online_ips={job.online_ips}",
            f"hash_rate_sum_mhs={job.hash_rate_sum}",
            f"export_mode={mode_norm}",
            f"device_files={len(rows)}",
        ]
        readme_body = "\n".join(readme_lines) + "\n"

        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            readme_b = _utf8_bom_bytes(readme_body)
            zf.writestr("README.txt", readme_b)
            total_bytes += len(readme_b)

            for dr in rows:
                ip_safe = dr.ip_address.replace(":", "_").replace("/", "_")
                head = (
                    f"ip={dr.ip_address}\n"
                    f"online={dr.is_online}\n"
                    f"mhs_av={dr.mhs_av}\n"
                    f"error_type={dr.error_type}\n"
                    f"stage={dr.stage}\n"
                    f"error_message={dr.error_message}\n\n"
                )
                body = dr.raw_response or "(no raw_response stored)\n"
                content = head + body
                b = _utf8_bom_bytes(content)
                total_bytes += len(b)
                if total_bytes > DEBUG_EXPORT_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Export exceeds limit of {DEBUG_EXPORT_MAX_BYTES} bytes; try errors_only or a smaller job.",
                    )
                zf.writestr(f"devices/{ip_safe}.txt", b)

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="DEBUG_EXPORT",
            target_type="scan_job",
            target_id=str(job_id),
            metadata={"mode": mode_norm, "file_count": len(rows)},
        )

        buf.seek(0)
        headers = {"Content-Disposition": f'attachment; filename="{zip_name}"'}
        return StreamingResponse(buf, media_type="application/zip", headers=headers)
    finally:
        db.close()

@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_get(request: Request):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()
        if not user.is_admin:
            return redirect_to_login()

        users = list(db.execute(select(User).order_by(User.id.asc())).scalars().all())
        return templates.TemplateResponse(
            "admin_users.html", {"request": request, "user": user, "users": users, "error": None}
        )
    finally:
        db.close()


@app.post("/admin/users", response_class=HTMLResponse)
def admin_users_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin: str = Form("off"),
):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user:
            return redirect_to_login()
        if not user.is_admin:
            return redirect_to_login()

        username = username.strip()
        if not username:
            users = list(db.execute(select(User).order_by(User.id.asc())).scalars().all())
            return templates.TemplateResponse(
                "admin_users.html",
                {"request": request, "user": user, "users": users, "error": "Username required"},
                status_code=400,
            )

        # Hashing is handled inline to keep this app minimal.
        from .auth import hash_password

        password_hash = hash_password(password)
        new_user = User(
            username=username,
            password_hash=password_hash,
            is_admin=(is_admin == "on"),
            is_enabled=True,
        )
        db.add(new_user)
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="USER_CREATE",
            target_type="user",
            target_id=str(new_user.id),
            metadata={"username": username, "is_admin": new_user.is_admin},
        )

        return RedirectResponse(url="/admin/users", status_code=303)
    finally:
        db.close()


@app.post("/admin/users/{user_id}/toggle", response_class=RedirectResponse)
def admin_user_toggle_enabled(request: Request, user_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user or not user.is_admin:
            return redirect_to_login()

        target = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not target:
            return RedirectResponse(url="/admin/users", status_code=303)

        # Prevent disabling the last enabled admin.
        if target.is_admin:
            enabled_admin_count = db.execute(select(func.count(User.id)).where(User.is_admin == True, User.is_enabled == True)).scalar_one()  # noqa: E712
            if enabled_admin_count <= 1:
                return RedirectResponse(url="/admin/users", status_code=303)

        target.is_enabled = not bool(target.is_enabled)
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="USER_TOGGLE_ENABLED",
            target_type="user",
            target_id=str(target.id),
            metadata={"username": target.username, "enabled": target.is_enabled},
        )

        return RedirectResponse(url="/admin/users", status_code=303)
    finally:
        db.close()


@app.post("/admin/users/{user_id}/toggle-admin", response_class=RedirectResponse)
def admin_user_toggle_admin(request: Request, user_id: int):
    db = SessionLocal()
    try:
        user = require_user(request, db)
        if not user or not user.is_admin:
            return redirect_to_login()

        target = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not target:
            return RedirectResponse(url="/admin/users", status_code=303)

        if target.id == user.id:
            # Prevent removing your own admin privileges by default.
            return RedirectResponse(url="/admin/users", status_code=303)

        enabled_admin_count = db.execute(select(func.count(User.id)).where(User.is_admin == True, User.is_enabled == True)).scalar_one()  # noqa: E712
        if target.is_admin and enabled_admin_count <= 1:
            return RedirectResponse(url="/admin/users", status_code=303)

        target.is_admin = not bool(target.is_admin)
        db.commit()

        audit.log_event(
            db,
            user_id=user.id,
            request_ip=get_client_ip(request),
            event_type="USER_TOGGLE_ADMIN",
            target_type="user",
            target_id=str(target.id),
            metadata={"username": target.username, "is_admin": target.is_admin},
        )

        return RedirectResponse(url="/admin/users", status_code=303)
    finally:
        db.close()



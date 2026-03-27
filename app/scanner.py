from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import log_event
from .device_api import DeviceQueryException, query_device_text_async
from .models import DeviceResult, IpRange, ScanJob
from .parsing import parse_bootby, parse_fans_from_msg, parse_status_payload, parse_summary, parse_version


@dataclass(frozen=True)
class IpParts:
    a: int
    b: int
    c: int
    d: int

    @property
    def ip(self) -> str:
        return f"{self.a}.{self.b}.{self.c}.{self.d}"


def parse_octet_part(part: str) -> list[int]:
    part = part.strip()
    if not part:
        raise ValueError("Empty octet part")

    if "-" in part:
        start_s, end_s = part.split("-", 1)
        start = int(start_s)
        end = int(end_s)
        if start > end:
            start, end = end, start
        if start < 0 or end > 255:
            raise ValueError(f"Octet range out of bounds: {part}")
        return list(range(start, end + 1))

    v = int(part)
    if v < 0 or v > 255:
        raise ValueError(f"Octet out of bounds: {part}")
    return [v]


def parse_ip_spec_to_octet_values(spec: str) -> tuple[list[int], list[int], list[int], list[int]]:
    parts = [p.strip() for p in spec.strip().split(".")]
    if len(parts) != 4:
        raise ValueError("IP spec must have 4 octets: A.B.C.D")

    octets = [parse_octet_part(p) for p in parts]
    return octets[0], octets[1], octets[2], octets[3]


def ip_expansion_count(spec: str) -> int:
    a_vals, b_vals, c_vals, d_vals = parse_ip_spec_to_octet_values(spec)
    return len(a_vals) * len(b_vals) * len(c_vals) * len(d_vals)


def iter_ip_parts(spec: str) -> Iterable[IpParts]:
    a_vals, b_vals, c_vals, d_vals = parse_ip_spec_to_octet_values(spec)
    for a in a_vals:
        for b in b_vals:
            for c in c_vals:
                for d in d_vals:
                    yield IpParts(a=a, b=b, c=c, d=d)


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


async def scan_ip_one_async(
    ip_parts: IpParts,
    *,
    port: int,
    connect_timeout_s: float,
    read_timeout_s: float,
) -> dict:
    """
    Returns a dict suitable for DeviceResult fields.
    Network errors become `error_type` + `stage` + `error_message`.
    """
    ip = ip_parts.ip

    # Order matters for parse success.
    queries = [
        ("version", "version"),
        ("summary", "summary"),
        ("estats", "estats"),
        ("pools", "pools"),
        ("bootby", "ascset|0,bootby"),
        ("fan-global", "ascset|0,fan-global"),
    ]

    parsed_version = None
    parsed_summary = None
    raw_fragments: list[str] = []
    first_error: dict | None = None

    is_online = False

    for stage, query in queries:
        try:
            resp = await query_device_text_async(
                ip,
                port=port,
                query=query,
                connect_timeout_s=connect_timeout_s,
                read_timeout_s=read_timeout_s,
            )
            raw_fragments.append(f"[{stage}] {resp.raw_text}")

            status = parse_status_payload(resp.raw_text)
            if status is None:
                raise DeviceQueryException(f"no_status_line:{stage}")

            if stage == "version":
                if status.status and status.status.strip():
                    # Parse the Description segment for device identity.
                    parsed_version = parse_version(status.description)
                    is_online = True
                else:
                    raise DeviceQueryException("unexpected_version_status")

            elif stage == "summary":
                parsed_summary = parse_summary(status.description)

            # For estats/pools/bootby/fan-global we don't require parsed fields for the UI,
            # but we keep parse stage errors visible in Issues.
            if stage == "bootby":
                _ = parse_bootby(status.msg)  # best-effort (BOOTBY appears in Msg)
            if stage == "fan-global":
                _ = parse_fans_from_msg(status.msg)  # best-effort (fan info appears in Msg)

        except DeviceQueryException as e:
            if first_error is None:
                is_online = False
                first_error = {
                    "error_type": f"query_error_{stage}",
                    "stage": stage,
                    "error_message": str(e),
                }
            # Continue best-effort: keep scanning remaining commands even if one failed.
            continue
        except Exception as e:
            if first_error is None:
                is_online = False
                first_error = {
                    "error_type": "unexpected_error",
                    "stage": stage,
                    "error_message": str(e),
                }
            continue

    # If we got version parse but summary parse fails, mark summary parse error.
    mhs_av = None
    if parsed_summary is not None:
        mhs_av = parsed_summary.get("mhs_av")

    if is_online:
        # If we never parsed summary, treat that as a parse issue.
        if parsed_summary is None:
            first_error = first_error or {
                "error_type": "parse_error_summary",
                "stage": "summary",
                "error_message": "missing/invalid summary response",
            }

    raw_response = "\n".join(raw_fragments) if raw_fragments else None

    # Normalize: if no error_type chosen but is_online false, set generic error.
    if not is_online and first_error is None:
        first_error = {
            "error_type": "unreachable",
            "stage": "connect",
            "error_message": "device did not respond",
        }

    error_type = first_error.get("error_type") if first_error else None
    stage = first_error.get("stage") if first_error else None
    error_message = first_error.get("error_message") if first_error else None

    version_fields = parsed_version or {}

    return {
        "ip_address": ip,
        "ip_octet_a": ip_parts.a,
        "ip_octet_b": ip_parts.b,
        "ip_octet_c": ip_parts.c,
        "ip_octet_d": ip_parts.d,
        "is_online": bool(is_online),
        "mhs_av": mhs_av,
        "model": version_fields.get("model"),
        "hwtype": version_fields.get("hwtype"),
        "prod": version_fields.get("prod"),
        "device_version": version_fields.get("device_version"),
        "api_version": version_fields.get("api_version"),
        "error_type": error_type,
        "stage": stage,
        "error_message": error_message,
        "raw_response": raw_response,
    }


async def _scan_ip_bounded(
    ip_parts: IpParts,
    *,
    sem: asyncio.Semaphore,
    port: int,
    connect_timeout_s: float,
    read_timeout_s: float,
) -> dict:
    async with sem:
        return await scan_ip_one_async(
            ip_parts,
            port=port,
            connect_timeout_s=connect_timeout_s,
            read_timeout_s=read_timeout_s,
        )


def run_scan_job_background(scan_job_id: int) -> None:
    # Run in its own thread (safe with SQLite check_same_thread=False).
    # Network I/O is asynchronous within this thread (asyncio).
    from .db import SessionLocal

    session: Session = SessionLocal()
    try:
        asyncio.run(_run_scan_job_async(session, scan_job_id))
    except Exception as e:
        # Hard failure: mark job as failed.
        try:
            scan_job = session.execute(select(ScanJob).where(ScanJob.id == scan_job_id)).scalar_one_or_none()
            if scan_job is not None:
                scan_job.status = "failed"
                scan_job.error_message = str(e)
                scan_job.finished_at = datetime.utcnow()
                session.commit()

                log_event(
                    session,
                    user_id=scan_job.requested_by_user_id,
                    request_ip=scan_job.request_ip_snapshot,
                    event_type="SCAN_FINISH",
                    target_type="scan_job",
                    target_id=str(scan_job.id),
                    metadata={
                        "status": "failed",
                        "error_message": scan_job.error_message,
                    },
                )
        except Exception:
            pass
    finally:
        session.close()


async def _run_scan_job_async(session: Session, scan_job_id: int) -> None:
    scan_job = session.execute(select(ScanJob).where(ScanJob.id == scan_job_id)).scalar_one()
    ip_range = session.execute(select(IpRange).where(IpRange.id == scan_job.ip_range_id)).scalar_one()

    scan_spec = scan_job.spec_snapshot or ip_range.spec

    max_ips = _get_env_int("MAX_IPS_PER_SCAN", 5000)
    total_ips = ip_expansion_count(scan_spec)
    if total_ips > max_ips:
        scan_job.status = "failed"
        scan_job.error_message = f"Spec expands to {total_ips} IPs, exceeds MAX_IPS_PER_SCAN={max_ips}"
        session.commit()
        return

    scan_job.status = "running"
    scan_job.started_at = datetime.utcnow()
    scan_job.total_ips = total_ips
    scan_job.completed_ips = 0
    scan_job.online_ips = 0
    scan_job.hash_rate_sum = 0.0
    scan_job.error_message = None
    session.commit()

    port = int(os.getenv("MINER_PORT", "4028"))
    connect_timeout_s = float(os.getenv("CONNECT_TIMEOUT_S", "2.0"))
    read_timeout_s = float(os.getenv("READ_TIMEOUT_S", "5.0"))
    concurrency = _get_env_int("SCAN_CONCURRENCY", 50)

    sem = asyncio.Semaphore(concurrency)
    ip_iter = iter_ip_parts(scan_spec)

    completed_ips = 0
    online_ips = 0
    hash_rate_sum = 0.0
    batch: list[DeviceResult] = []
    batch_commit_every = 25

    tasks: set[asyncio.Task] = set()

    def enqueue_next() -> None:
        nonlocal tasks
        try:
            ip_parts = next(ip_iter)
        except StopIteration:
            return
        tasks.add(
            asyncio.create_task(
                _scan_ip_bounded(
                    ip_parts,
                    sem=sem,
                    port=port,
                    connect_timeout_s=connect_timeout_s,
                    read_timeout_s=read_timeout_s,
                )
            )
        )

    # Prime the task set.
    for _ in range(min(concurrency, total_ips)):
        enqueue_next()

    while tasks:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        tasks = set(pending)

        for d in done:
            data = await d
            dev = DeviceResult(scan_job_id=scan_job_id, **data)
            batch.append(dev)

            completed_ips += 1
            if dev.is_online:
                online_ips += 1
                if dev.mhs_av is not None:
                    hash_rate_sum += float(dev.mhs_av)

            enqueue_next()

            if len(batch) >= batch_commit_every:
                session.add_all(batch)
                session.commit()
                batch.clear()
                scan_job.completed_ips = completed_ips
                scan_job.online_ips = online_ips
                scan_job.hash_rate_sum = hash_rate_sum
                session.commit()

        await asyncio.sleep(0)  # yield

    if batch:
        session.add_all(batch)
        session.commit()

    scan_job.completed_ips = completed_ips
    scan_job.online_ips = online_ips
    scan_job.hash_rate_sum = hash_rate_sum
    scan_job.status = "completed"
    scan_job.finished_at = datetime.utcnow()
    session.commit()

    log_event(
        session,
        user_id=scan_job.requested_by_user_id,
        request_ip=scan_job.request_ip_snapshot,
        event_type="SCAN_FINISH",
        target_type="scan_job",
        target_id=str(scan_job.id),
        metadata={
            "status": "completed",
            "total_ips": scan_job.total_ips,
            "completed_ips": scan_job.completed_ips,
            "online_ips": scan_job.online_ips,
            "hash_rate_sum": scan_job.hash_rate_sum,
        },
    )


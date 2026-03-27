from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

_HASH_RATE_UNITS: tuple[str, ...] = ("MH/s", "GH/s", "TH/s", "PH/s", "EH/s")


def format_hash_rate_mhs(mhs: float | None) -> str:
    """Format a value in MH/s using the largest unit where the number is >= 1."""
    if mhs is None:
        return "\u2014"
    try:
        v = float(mhs)
    except (TypeError, ValueError):
        return "\u2014"
    if not math.isfinite(v):
        return "\u2014"
    if v == 0:
        return "0 MH/s"
    power = 0
    for p in range(4, -1, -1):
        if v / (1000**p) >= 1.0:
            power = p
            break
    scaled = v / (1000**power)
    s = f"{scaled:.10f}".rstrip("0").rstrip(".")
    return f"{s} {_HASH_RATE_UNITS[power]}"


def hash_rate_chart_scale(mhs_values: list[float]) -> tuple[int, str]:
    """Pick a single SI unit for a chart from the max MH/s in the series."""
    if not mhs_values:
        return 0, _HASH_RATE_UNITS[0]
    m = max(float(x or 0.0) for x in mhs_values)
    if not math.isfinite(m) or m <= 0:
        return 0, _HASH_RATE_UNITS[0]
    power = 0
    for p in range(4, -1, -1):
        if m / (1000**p) >= 1.0:
            power = p
            break
    return power, _HASH_RATE_UNITS[0]


STATUS_LINE_RE = re.compile(
    r"^STATUS=([^,]*),When=([^,]*),Code=([^,]*),Msg=([^,]*),Description=(.*)$",
    re.DOTALL,
)


def _to_int_maybe(v: str) -> int | None:
    v = v.strip()
    if not v:
        return None
    if re.fullmatch(r"-?\d+", v):
        try:
            return int(v)
        except ValueError:
            return None
    return None


def _to_float_maybe(v: str) -> float | None:
    v = v.strip()
    if not v:
        return None
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        try:
            return float(v)
        except ValueError:
            return None
    return None


@dataclass
class ParsedStatus:
    status: str
    when: str | None
    code: int | str | None
    msg: str
    description: str


def parse_status_payload(payload_text: str) -> ParsedStatus | None:
    # Device replies are typically a single line beginning with STATUS=...
    text = (payload_text or "").strip().replace("\x00", "").strip()
    if not text:
        return None

    # Some firmware might include multiple lines; pick the first STATUS= line.
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("STATUS="):
            m = STATUS_LINE_RE.match(line)
            if not m:
                continue
            status = m.group(1).strip()
            when = m.group(2).strip() or None
            code_raw = m.group(3).strip()
            code_int = _to_int_maybe(code_raw)
            code: int | str | None = code_int if code_int is not None else code_raw or None
            msg = m.group(4).strip()
            description = m.group(5).strip()
            return ParsedStatus(
                status=status,
                when=when,
                code=code,
                msg=msg,
                description=description,
            )
    return None


def parse_version(description: str) -> dict[str, Any]:
    # Example (from docs):
    # cgminer 4.11.1|VERSION,CGMiner=4.11.1,API=3.7,STM8=20.08.01,PROD=AvalonMiner 1566,MODEL=1566,...
    # Values are comma-separated KV pairs after the first "VERSION," marker, but PROD contains spaces.
    def grab(key: str) -> str | None:
        m = re.search(rf"{re.escape(key)}=([^,|]+)", description)
        if not m:
            return None
        return m.group(1).strip()

    return {
        "api_version": grab("API"),
        "prod": grab("PROD"),
        "model": grab("MODEL"),
        "hwtype": grab("HWTYPE"),
        "device_version": grab("VERSION"),
        "cgminer_version": grab("CGMiner"),
        "mac": grab("MAC"),
        "stm8": grab("STM8"),
        "upapi": grab("UPAPI"),
    }


def parse_summary(description: str) -> dict[str, Any]:
    # Example contains: MHS av=120765750.85, Elapsed=898, ...
    mhs_av = None
    m = re.search(r"MHS av=([0-9]+(?:\.[0-9]+)?)", description)
    if m:
        mhs_av = _to_float_maybe(m.group(1))

    elapsed = None
    m2 = re.search(r"Elapsed=([0-9]+)", description)
    if m2:
        elapsed = _to_int_maybe(m2.group(1))

    return {"mhs_av": mhs_av, "elapsed": elapsed}


def parse_bootby(description_msg: str) -> dict[str, Any]:
    # BOOTBY appears in Msg portion in the docs examples: "... BOOTBY[0x05.0000],Description=..."
    m = re.search(r"BOOTBY\[(.*?)\]", description_msg)
    return {"bootby": m.group(1) if m else None}


def parse_fans_from_msg(description_msg: str) -> dict[str, Any]:
    # Example: "... Msg=ASC 0 set info: Fan0[2878] Fan1[2900] ,Description=..."
    def grab(tag: str) -> str | None:
        m = re.search(rf"{re.escape(tag)}\[(.*?)\]", description_msg)
        return m.group(1).strip() if m else None

    return {
        "fan0": grab("Fan0"),
        "fan1": grab("Fan1"),
        "fanr": grab("FanR"),
    }


def split_raw_stages(raw: str | None) -> dict[str, str]:
    """Split concatenated `[stage] payload` blocks from a stored raw_response."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    parts = re.split(r"(?m)^\[([^\]]+)\]\s*", raw)
    if parts and parts[0] == "":
        parts = parts[1:]
    out: dict[str, str] = {}
    for i in range(0, len(parts), 2):
        if i + 1 >= len(parts):
            break
        name = parts[i].strip().lower()
        body = parts[i + 1].strip()
        out[name] = body
    return out


def parse_summary_metrics(description: str) -> dict[str, Any]:
    """Extra counters from SUMMARY,Description=... line (comma-separated KV)."""
    d: dict[str, Any] = dict(parse_summary(description))
    for key, rgx in (
        ("accepted", r"Accepted=([0-9]+)"),
        ("rejected", r"Rejected=([0-9]+)"),
        ("hw_errors", r"Hardware Errors=([0-9]+)"),
        ("discarded", r"Discarded=([0-9]+)"),
        ("stale", r"Stale=([0-9]+)"),
        ("get_failures", r"Get Failures=([0-9]+)"),
        ("utility", r"Utility=([0-9.]+)"),
        ("best_share", r"Best Share=([0-9]+)"),
    ):
        m = re.search(rgx, description)
        if m:
            v = m.group(1)
            d[key] = _to_float_maybe(v) if "." in v else _to_int_maybe(v)
    return d


def parse_primary_pool(pools_text: str) -> dict[str, Any]:
    """First POOL=0 block: URL and User."""
    if not pools_text:
        return {"url": None, "user": None}
    m = re.search(r"POOL=0,URL=([^,|]+)", pools_text)
    url = m.group(1).strip() if m else None
    # User appears after pool-specific fields; take first User= in POOL=0 section before |POOL=1
    block0 = pools_text.split("|POOL=1", 1)[0] if "|POOL=1" in pools_text else pools_text
    mu = re.search(r"User=([^,|]+)", block0)
    user = mu.group(1).strip() if mu else None
    return {"url": url, "user": user}


def parse_estats_key_metrics(text: str) -> dict[str, Any]:
    """Pull a few fields from the long STATS / MM line in estats."""

    def grab(pat: str) -> str | None:
        m = re.search(pat, text)
        return m.group(1).strip() if m else None

    return {
        "temp": grab(r"Temp\[(\d+)\]"),
        "tmax": grab(r"TMax\[(\d+)\]"),
        "tavg": grab(r"TAvg\[(\d+)\]"),
        "fan1": grab(r"Fan1\[(\d+)\]"),
        "fan2": grab(r"Fan2\[(\d+)\]"),
        "fanr": grab(r"FanR\[(\d+)%\]"),
        "wall_power": grab(r"WALLPOWER\[(\d+)\]"),
        "ghs_avg": grab(r"GHSavg\[([0-9.]+)\]"),
        "ghs_mm": grab(r"GHSmm\[([0-9.]+)\]"),
    }


def _short_url_host(url: str | None) -> str | None:
    if not url:
        return None
    u = url.strip()
    for prefix in ("stratum+tcp://", "stratum+ssl://", "stratum://"):
        if u.startswith(prefix):
            u = u[len(prefix) :]
            break
    host = u.split("/")[0].split(":")[0]
    return host or None


def enrich_device_from_raw(raw: str | None) -> dict[str, Any]:
    """Structured fields for API/list/detail views derived from stored raw_response."""
    sections = split_raw_stages(raw)
    summary_text = sections.get("summary", "")
    ps = parse_status_payload(summary_text)
    desc = ps.description if ps else ""
    metrics = parse_summary_metrics(desc) if desc else {}
    pool = parse_primary_pool(sections.get("pools", ""))
    est = parse_estats_key_metrics(sections.get("estats", ""))
    boot = sections.get("bootby", "")
    fan_g = sections.get("fan-global", "")

    return {
        "elapsed_s": metrics.get("elapsed"),
        "accepted": metrics.get("accepted"),
        "rejected": metrics.get("rejected"),
        "hw_errors": metrics.get("hw_errors"),
        "discarded": metrics.get("discarded"),
        "stale": metrics.get("stale"),
        "utility": metrics.get("utility"),
        "best_share": metrics.get("best_share"),
        "pool_url": pool.get("url"),
        "pool_user": pool.get("user"),
        "pool_host": _short_url_host(pool.get("url")),
        "estats": est,
        "bootby_line": boot[:500] if boot else None,
        "fan_global_line": fan_g[:500] if fan_g else None,
        "sections": {k: (v[:2000] + ("…" if len(v) > 2000 else "")) for k, v in sections.items()},
    }


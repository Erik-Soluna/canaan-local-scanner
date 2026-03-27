from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


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


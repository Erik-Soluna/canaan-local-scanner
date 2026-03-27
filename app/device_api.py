from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass


@dataclass
class DeviceQueryResult:
    raw_text: str


class DeviceQueryException(Exception):
    pass


async def query_device_text_async(
    ip: str,
    *,
    port: int = 4028,
    query: str,
    connect_timeout_s: float = 2.0,
    read_timeout_s: float = 5.0,
) -> DeviceQueryResult:
    """
    Async version of the Canaan TCP API query.

    Reads until the remote closes the connection. If the miner doesn't close the socket,
    we treat a read timeout as either:
    - success (if we already received some bytes), or
    - error (if we received nothing).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=connect_timeout_s,
        )
    except asyncio.TimeoutError as e:
        raise DeviceQueryException("connect_timeout") from e
    except OSError as e:
        raise DeviceQueryException(f"connect_error:{e}") from e

    chunks: list[bytes] = []
    try:
        writer.write(query.encode("ascii", errors="ignore"))
        await writer.drain()

        while True:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=read_timeout_s)
            except asyncio.TimeoutError:
                if chunks:
                    break
                raise DeviceQueryException("read_timeout")
            if not data:
                break
            chunks.append(data)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    raw = b"".join(chunks).decode("utf-8", errors="replace")
    return DeviceQueryResult(raw_text=raw)


def query_device_text(
    ip: str,
    *,
    port: int = 4028,
    query: str,
    connect_timeout_s: float = 2.0,
    read_timeout_s: float = 5.0,
) -> DeviceQueryResult:
    # Protocol mirrors the docs examples that use: echo -n "<query>" | socat ...
    # So we send raw query bytes without newline.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(connect_timeout_s)
        sock.connect((ip, port))

        sock.settimeout(read_timeout_s)
        sock.sendall(query.encode("ascii", errors="ignore"))

        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                # If the device doesn't close the socket, we still fail fast.
                raise DeviceQueryException("read_timeout")
            if not data:
                break
            chunks.append(data)

    raw = b"".join(chunks).decode("utf-8", errors="replace")
    return DeviceQueryResult(raw_text=raw)


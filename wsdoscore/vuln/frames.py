"""Frame-level fuzz: send malformed WebSocket frames and observe behaviour.

We bypass `websockets` library framing and craft raw RFC 6455 frames over
a low-level socket. Tests cover:

  1. Unmasked client frame (servers MUST close with 1002)
  2. Reserved bits set (RSV1-3) when no extension negotiated
  3. Continuation frame without prior FIN=0 fragment
  4. Oversize length encoding (8-byte length on a small payload)
  5. Invalid opcode (0xB-0xF reserved)

A correct server closes the connection on each. A buggy server may
process or hang, indicating an exploitable parser.
"""

from __future__ import annotations

import asyncio
import base64
import os
import ssl
import struct
from urllib.parse import urlparse

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
    random_ws_key,
)


def _ws_handshake_bytes(host: str, path: str, headers: dict) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


async def _open_raw(url: str, ssl_ctx, headers: dict, timeout: float):
    """Open a raw socket, do the WS handshake, return (reader, writer)."""
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    if u.scheme == "wss":
        ctx = ssl_ctx or ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

    writer.write(_ws_handshake_bytes(f"{host}:{port}", path, headers))
    await writer.drain()

    # Read handshake response
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            raise ConnectionError("server closed during handshake")
        resp += chunk
    status_line = resp.split(b"\r\n", 1)[0].decode("latin-1")
    if " 101 " not in status_line:
        raise ConnectionError(f"handshake refused: {status_line}")
    return reader, writer


def _frame(opcode: int, payload: bytes, fin: bool = True,
           rsv: int = 0, mask: bool = True,
           length_override: int = None) -> bytes:
    """Craft a raw WebSocket frame."""
    b1 = (0x80 if fin else 0) | (rsv << 4) | (opcode & 0x0F)
    masked_bit = 0x80 if mask else 0
    L = length_override if length_override is not None else len(payload)
    if L <= 125:
        b2 = masked_bit | L
        header = bytes([b1, b2])
    elif L <= 0xFFFF:
        header = bytes([b1, masked_bit | 126]) + struct.pack(">H", L)
    else:
        header = bytes([b1, masked_bit | 127]) + struct.pack(">Q", L)
    if mask:
        mk = os.urandom(4)
        masked_payload = bytes(b ^ mk[i % 4] for i, b in enumerate(payload))
        return header + mk + masked_payload
    return header + payload


async def _send_and_observe(url, ssl_ctx, headers, timeout, frame_bytes, label):
    """Send raw bytes after handshake, watch server reaction."""
    try:
        reader, writer = await _open_raw(url, ssl_ctx, headers, timeout)
    except Exception as exc:  # noqa: BLE001
        return {"label": label, "handshake_ok": False, "error": str(exc)}
    try:
        writer.write(frame_bytes)
        await writer.drain()
        try:
            reply = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            return {"label": label, "handshake_ok": True,
                    "reply_bytes": len(reply),
                    "first_byte": reply[0] if reply else None,
                    "closed": len(reply) == 0}
        except asyncio.TimeoutError:
            return {"label": label, "handshake_ok": True, "reply_bytes": 0,
                    "closed": False, "note": "no reply within 2s (server may be hung)"}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    findings: list = []

    tests = [
        ("unmasked-client-frame",
         _frame(0x1, b"AAAA", mask=False),
         "client text frame without mask (RFC 6455 violation; must close with 1002)"),
        ("rsv1-set-no-extension",
         _frame(0x1, b"AAAA", rsv=1),
         "RSV1 set with no permessage-deflate negotiated"),
        ("invalid-opcode-0xB",
         _frame(0xB, b""),
         "reserved opcode 0xB (must close with 1002)"),
        ("oversize-length-claim",
         _frame(0x1, b"A", length_override=0x7FFFFFFF),
         "claim 2 GiB length on a 1-byte payload (reading-past-buffer test)"),
        ("continuation-without-prior",
         _frame(0x0, b"AAAA"),
         "continuation (opcode 0) without a preceding fragment"),
    ]

    bad_behaviour = 0
    handshake_failures = 0
    detail_lines = []
    for label, payload, desc in tests:
        result = await _send_and_observe(url, ssl_ctx, headers,
                                         args.timeout, payload, label)
        if not result.get("handshake_ok"):
            handshake_failures += 1
            detail_lines.append(
                f"  {label}: handshake failed ({result.get('error')})"
            )
            continue
        compliant = result.get("closed") or result.get("reply_bytes", 0) > 0
        if not compliant:
            bad_behaviour += 1
        detail_lines.append(
            f"  {label}: handshake=OK "
            f"reply_bytes={result.get('reply_bytes')} "
            f"closed={result.get('closed')} {result.get('note', '')}"
        )

    if handshake_failures == len(tests):
        findings.append(Finding(
            check="frames.rfc6455-compliance",
            severity="INFO",
            title="Could not test frame compliance (no successful handshake)",
            detail="All handshakes failed; frame fuzzing was not performed.\n"
                   + "\n".join(detail_lines),
            evidence={"handshake_failures": handshake_failures},
            references=[],
        ))
        return findings

    if bad_behaviour:
        sev = "HIGH" if bad_behaviour >= 3 else "MEDIUM"
        findings.append(Finding(
            check="frames.rfc6455-compliance",
            severity=sev,
            title=f"Server tolerates {bad_behaviour}/{len(tests)} malformed frames",
            detail="A compliant server closes immediately on these inputs. "
                   "Tolerating them suggests a custom (possibly buggy) parser.\n"
                   + "\n".join(detail_lines),
            evidence={"tests": tests and len(tests), "bad_behaviour": bad_behaviour},
            references=[
                "https://datatracker.ietf.org/doc/html/rfc6455#section-5",
            ],
        ))
    else:
        findings.append(Finding(
            check="frames.rfc6455-compliance",
            severity="INFO",
            title="Server enforces RFC 6455 frame validation",
            detail="All 5 malformed frames were rejected or connection closed.",
            evidence={},
            references=[],
        ))
    return findings

"""Safe recon: single handshake to capture target's WebSocket fingerprint."""

from __future__ import annotations

import time
from typing import Optional

import websockets

from .common import build_ssl_context, normalize_target, parse_headers


async def probe(url: str, ssl_ctx, headers: dict, timeout: float) -> dict:
    """Connect once, capture handshake info."""
    info = {
        "url": url,
        "ok": False,
        "rtt_ms": None,
        "subprotocol": None,
        "headers_seen": {},
        "compression": False,
        "error": None,
    }
    start = time.monotonic()
    try:
        async with websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=list(headers.items()) if headers else None,
            close_timeout=timeout,
            open_timeout=timeout,
            ping_interval=None,
        ) as ws:
            info["ok"] = True
            info["rtt_ms"] = round((time.monotonic() - start) * 1000, 2)
            info["subprotocol"] = ws.subprotocol
            if ws.response_headers:
                for k in ("Server", "X-Powered-By", "Sec-WebSocket-Protocol",
                          "Sec-WebSocket-Extensions", "Sec-WebSocket-Accept"):
                    v = ws.response_headers.get(k)
                    if v:
                        info["headers_seen"][k] = v
                ext = ws.response_headers.get("Sec-WebSocket-Extensions", "")
                info["compression"] = "permessage-deflate" in ext
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


async def run(args):
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    return await probe(url, ssl_ctx, headers, args.timeout)

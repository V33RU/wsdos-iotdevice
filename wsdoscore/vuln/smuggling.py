"""HTTP request smuggling via the WebSocket Upgrade boundary.

WebSocket handshake is an HTTP/1.1 upgrade. If a frontend proxy and
the WebSocket server disagree on Content-Length / Transfer-Encoding /
case-insensitive header parsing, you can smuggle a second request.

We send a probe with a body after the handshake and a Content-Length
that should be ignored by RFC but is honored by some servers. We also
test Transfer-Encoding parsing variants.

References:
  - https://portswigger.net/web-security/request-smuggling
  - https://portswigger.net/research/upgrade-header-smuggling
"""

from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlparse

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
    random_ws_key,
)


VARIANTS = [
    ("cl-with-body", "Content-Length: 42\r\n", b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"),
    ("te-chunked-after-upgrade", "Transfer-Encoding: chunked\r\n", b"0\r\n\r\n"),
    ("te-gzip-bogus", "Transfer-Encoding: gzip\r\n", b""),
    ("double-host", "Host: smuggled.example\r\n", b""),
]


async def _send_handshake_with_variant(url, ssl_ctx, headers, timeout,
                                       extra_header, trailing_body):
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    key = random_ws_key()

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

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"{extra_header}"
        f"\r\n"
    ).encode() + trailing_body

    try:
        writer.write(req)
        await writer.drain()
        try:
            reply = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        except asyncio.TimeoutError:
            reply = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return reply
    except Exception as exc:  # noqa: BLE001
        return f"ERR: {exc}".encode()


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    findings: list = []

    suspicious = []
    for label, extra, body in VARIANTS:
        reply = await _send_handshake_with_variant(
            url, ssl_ctx, headers, args.timeout, extra, body
        )
        first_line = reply.split(b"\r\n", 1)[0] if reply else b""
        # Multiple status lines in one reply is a smoking gun for smuggling
        status_count = reply.count(b"HTTP/1.")
        if status_count > 1:
            suspicious.append((label, status_count, first_line.decode("latin-1", errors="replace")))

    if suspicious:
        findings.append(Finding(
            check="smuggling.upgrade-boundary",
            severity="HIGH",
            title="Possible HTTP smuggling at the WebSocket Upgrade boundary",
            detail="The server returned multiple HTTP status lines in a single "
                   "response for at least one upgrade variant. This is a strong "
                   "indicator the server is parsing two requests where the client "
                   "sent one.\n"
                   + "\n".join(f"  {l}: {n} status lines, first: {s}"
                               for l, n, s in suspicious),
            evidence={"suspicious_variants": [s[0] for s in suspicious]},
            references=[
                "https://portswigger.net/research/upgrade-header-smuggling",
                "https://datatracker.ietf.org/doc/html/rfc7230#section-3.3",
            ],
        ))
    else:
        findings.append(Finding(
            check="smuggling.upgrade-boundary",
            severity="INFO",
            title="No smuggling indicators on Upgrade boundary",
            detail=f"Sent {len(VARIANTS)} crafted variants, none produced "
                   "duplicated status lines.",
            evidence={},
            references=[],
        ))
    return findings

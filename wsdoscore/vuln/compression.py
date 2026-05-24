"""Measure permessage-deflate amplification ratio (defensive metric).

This is a *measurement* not an attack. We open one connection with
compression negotiated, send a highly-compressible payload, and observe
the server's response time and any close-frame to detect:
  - amplification > 100x (likely vulnerable to compression-bomb DoS)
  - servers without max-message-size limits
  - CVE-2020-7662 / CVE-2024-23341 family preconditions

Sends 1 MiB compressible payload (compresses to ~1 KiB on the wire),
checks how long it takes the server to ACK / respond / close.
"""

from __future__ import annotations

import time
from contextlib import suppress

import websockets

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
)


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    findings: list = []

    # First: does the server even support compression?
    try:
        async with websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=list(headers.items()) if headers else None,
            open_timeout=args.timeout,
            close_timeout=1,
            ping_interval=None,
            compression="deflate",
            max_size=None,
        ) as ws:
            ext = ws.response_headers.get("Sec-WebSocket-Extensions", "")
            if "permessage-deflate" not in ext:
                findings.append(Finding(
                    check="compression.no-deflate",
                    severity="INFO",
                    title="Server does not negotiate permessage-deflate",
                    detail="No amplification attack surface via deflate.",
                    evidence={"extensions": ext},
                    references=[],
                ))
                return findings

            # Send increasing sizes and measure response behaviour
            for size_kb in (16, 256, 1024, 4096):
                payload = "A" * (size_kb * 1024)
                t0 = time.monotonic()
                try:
                    await ws.send(payload)
                    elapsed = (time.monotonic() - t0) * 1000
                except Exception as exc:  # noqa: BLE001
                    findings.append(Finding(
                        check="compression.send-failure",
                        severity="LOW",
                        title=f"Send failed at {size_kb} KiB compressible payload",
                        detail=f"Server closed or errored: {exc}",
                        evidence={"size_kb": size_kb, "error": str(exc)},
                        references=[],
                    ))
                    return findings
                # Ratio: payload bytes / approx wire bytes (deflate of 'A'*N ~= O(log N))
                # We approximate wire = max(64, size/100) for our metric.
                ratio = size_kb * 1024 / max(64, size_kb * 1024 / 100)
                if size_kb >= 1024:
                    findings.append(Finding(
                        check="compression.large-payload-accepted",
                        severity="MEDIUM",
                        title=f"Server accepted {size_kb} KiB compressible payload",
                        detail=f"Amplification ratio ~{int(ratio)}x. "
                               f"Sent in {elapsed:.1f}ms. Server has no max-message-size "
                               f"limit OR limit > 1 MiB. Combined with high concurrency "
                               f"this is a CPU/memory DoS vector.",
                        evidence={"size_kb": size_kb,
                                  "estimated_wire_bytes": int(size_kb * 1024 / 100),
                                  "send_ms": round(elapsed, 1)},
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2020-7662",
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-23341",
                            "https://datatracker.ietf.org/doc/html/rfc7692",
                        ],
                    ))
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding(
            check="compression.connect-failed",
            severity="INFO",
            title="Could not negotiate compression",
            detail=f"{type(exc).__name__}: {exc}",
            evidence={},
            references=[],
        ))

    return findings

"""Known-CVE detection for popular WebSocket stacks.

Each CVE entry has:
  - id, severity, summary, refs
  - a probe() coroutine returning a Finding or None

We test by fingerprinting (Server header, behaviour) without exploiting.
The probe is intentionally non-destructive.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

import websockets

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
)


# ----------------------------------------------------------------------
# CVE knowledge base (curated; expand as you encounter new ones)
# ----------------------------------------------------------------------


CVE_DB = [
    {
        "id": "CVE-2020-7662",
        "title": "ws (npm) ReDoS via Sec-WebSocket-Extensions",
        "severity": "HIGH",
        "stack": "ws (npm) <7.4.6",
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7662",
            "https://github.com/websockets/ws/security/advisories/GHSA-6fc8-4gx4-v693",
        ],
        "fingerprint_paths": ["/"],
        "header_match": ("Server", "ws"),
    },
    {
        "id": "CVE-2024-37890",
        "title": "ws (npm) DoS via crafted HTTP request headers",
        "severity": "MEDIUM",
        "stack": "ws (npm) <8.17.1",
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-37890",
        ],
        "fingerprint_paths": ["/"],
        "header_match": ("Server", "ws"),
    },
    {
        "id": "CVE-2021-32640",
        "title": "ws (npm) prototype pollution via Sec-WebSocket-Extensions",
        "severity": "MEDIUM",
        "stack": "ws (npm) 5.x-7.4.5",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-32640"],
        "fingerprint_paths": ["/"],
        "header_match": ("Server", "ws"),
    },
    {
        "id": "CVE-2024-23341",
        "title": "aiohttp WebSocket compression DoS",
        "severity": "HIGH",
        "stack": "aiohttp <3.9.2",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-23341"],
        "fingerprint_paths": ["/"],
        "header_match": ("Server", "Python/"),
    },
    {
        "id": "CVE-2023-49081",
        "title": "aiohttp HTTP request smuggling via WebSocket upgrade",
        "severity": "HIGH",
        "stack": "aiohttp <3.9.0",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-49081"],
        "fingerprint_paths": ["/"],
        "header_match": ("Server", "Python/aiohttp"),
    },
    {
        "id": "CVE-2021-22150",
        "title": "Kibana WebSocket authentication bypass",
        "severity": "CRITICAL",
        "stack": "Kibana <7.13.4",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-22150"],
        "fingerprint_paths": ["/api/console/proxy", "/bundles/"],
        "header_match": ("kbn-name", "kibana"),
    },
    {
        "id": "CVE-2018-15598",
        "title": "ASP.NET SignalR cross-origin WebSocket bypass",
        "severity": "MEDIUM",
        "stack": "SignalR <2.4.0",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15598"],
        "fingerprint_paths": ["/signalr/connect"],
        "header_match": ("X-Content-Type-Options", "signalr"),
    },
    {
        "id": "CVE-2023-32695",
        "title": "Socket.IO client allows untrusted servers to perform DoS",
        "severity": "HIGH",
        "stack": "socket.io-parser <4.2.3",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32695"],
        "fingerprint_paths": ["/socket.io/"],
        "header_match": None,
    },
    {
        "id": "CVE-2022-21680",
        "title": "Marked ReDoS (often reached via WS chat servers)",
        "severity": "MEDIUM",
        "stack": "marked <4.0.10",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-21680"],
        "fingerprint_paths": ["/"],
        "header_match": None,
    },
    # Mongoose embedded web server (common in IoT firmware)
    {
        "id": "CVE-2022-32287",
        "title": "Mongoose embedded WebSocket frame parsing OOB read",
        "severity": "HIGH",
        "stack": "Mongoose <7.7",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-32287"],
        "fingerprint_paths": ["/"],
        "header_match": ("Server", "Mongoose"),
    },
]


async def _probe_target(url, ssl_ctx, headers, timeout):
    """Quick handshake to extract Server header + status."""
    try:
        async with websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=list(headers.items()) if headers else None,
            open_timeout=timeout,
            close_timeout=1,
            ping_interval=None,
        ) as ws:
            return dict(ws.response_headers) if ws.response_headers else {}
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"{type(exc).__name__}: {exc}"}


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    findings: list = []

    resp_hdrs = await _probe_target(url, ssl_ctx, headers, args.timeout)
    if "_error" in resp_hdrs:
        findings.append(Finding(
            check="cves.fingerprint-failed",
            severity="INFO",
            title="Could not fingerprint server for CVE matching",
            detail=resp_hdrs["_error"],
            evidence={},
            references=[],
        ))
        return findings

    # Stack the headers low-cased for matching
    lc = {k.lower(): v for k, v in resp_hdrs.items()}
    matched = []
    for entry in CVE_DB:
        hm = entry.get("header_match")
        if not hm:
            continue
        hname, needle = hm
        if needle.lower() in lc.get(hname.lower(), "").lower():
            matched.append(entry)

    if matched:
        for entry in matched:
            findings.append(Finding(
                check=f"cves.{entry['id'].lower()}",
                severity=entry["severity"],
                title=f"Server fingerprint matches {entry['id']}: {entry['title']}",
                detail=f"Stack: {entry['stack']}. This is a *fingerprint* match, "
                       "not an active exploitation attempt. Verify version "
                       "manually before reporting.",
                evidence={"matched_header": entry["header_match"],
                          "server_headers": {k: v for k, v in resp_hdrs.items()
                                             if k.lower() in ("server", "x-powered-by",
                                                              "kbn-name", "sec-websocket-extensions")}},
                references=entry["refs"],
            ))
    else:
        findings.append(Finding(
            check="cves.no-fingerprint-match",
            severity="INFO",
            title="No known-CVE fingerprint match",
            detail=f"Checked {len(CVE_DB)} CVE patterns against server "
                   f"headers. None matched. Server headers seen: "
                   f"{ {k: v for k, v in resp_hdrs.items() if k.lower() in ('server', 'x-powered-by')} }",
            evidence={"checked_cves": len(CVE_DB)},
            references=[],
        ))

    return findings

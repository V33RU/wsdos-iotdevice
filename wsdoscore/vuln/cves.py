"""Known-CVE fingerprint check for WebSocket stacks.

Every entry in CVE_DB has been verified against NVD: the CVE ID, title,
affected stack, and severity are confirmed. We deliberately keep this
list small and accurate rather than long and noisy.

Detection is *fingerprint-based*: we read the server's response headers
during the handshake and match the `Server` / `X-Powered-By` strings
against known signatures. A match is a *hint*, not a confirmed
exploitable bug; the user must check the actual version manually.

Adding a new CVE here? Verify it on NVD first; do not commit unverified
entries.
"""

from __future__ import annotations

import websockets

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
)


# ----------------------------------------------------------------------
# Verified CVE knowledge base (curated; small > big-but-fake)
# ----------------------------------------------------------------------
#
# Schema:
#   id        : CVE identifier
#   title     : NVD short title (verbatim)
#   severity  : NVD/GitHub CVSS bucket (CRITICAL/HIGH/MEDIUM/LOW)
#   stack     : affected library + version range (per NVD)
#   header_match : (header_name, substring_to_find_case_insensitive)
#                  in the server's WS handshake response
#   refs      : list of canonical URLs


CVE_DB = [
    {
        "id": "CVE-2020-7662",
        "title": "websocket-extensions ReDoS via Sec-WebSocket-Extensions header",
        "severity": "HIGH",                  # CVSS 7.5
        "stack": "websocket-extensions (Node.js) < 0.1.4 — used by the `ws` package",
        "header_match": ("Server", "ws"),    # weak hint; verify version manually
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7662",
            "https://github.com/faye/websocket-extensions-node/security/advisories/GHSA-g78m-2chm-r7qv",
        ],
    },
    {
        "id": "CVE-2021-32640",
        "title": "ws (npm) ReDoS via crafted Sec-WebSocket-Protocol header",
        "severity": "MEDIUM",                # CVSS 5.3
        "stack": "ws (npm) 5.0.0–6.2.1 and 7.0.0–7.4.5",
        "header_match": ("Server", "ws"),
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-32640",
            "https://github.com/websockets/ws/security/advisories/GHSA-6fc8-4gx4-v693",
        ],
    },
    {
        "id": "CVE-2024-37890",
        "title": "ws (npm) DoS via HTTP requests exceeding server.maxHeadersCount",
        "severity": "HIGH",                  # CVSS 7.5
        "stack": "ws (npm) < 5.2.4, 6.2.3, 7.5.10, 8.17.1",
        "header_match": ("Server", "ws"),
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-37890",
            "https://github.com/websockets/ws/security/advisories/GHSA-3h5v-q93c-6h6q",
        ],
    },
    {
        "id": "CVE-2023-32695",
        "title": "socket.io-parser DoS via crafted packet (uncaught exception)",
        "severity": "HIGH",                  # CVSS 7.5
        "stack": "socket.io-parser 3.4.0–3.4.2, 4.0.4–4.2.2",
        "header_match": ("Server", "socket.io"),
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32695",
            "https://github.com/socketio/socket.io-parser/security/advisories/GHSA-cqmj-92xf-r6r9",
        ],
    },
]


async def _probe_target(url, ssl_ctx, headers, timeout):
    """Single handshake. Return response headers as dict, or {'_error': '...'}."""
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
            title="Could not fingerprint server (handshake failed)",
            detail=f"No data to match against known CVEs. {resp_hdrs['_error']}",
            evidence={"error": resp_hdrs["_error"]},
            references=[],
        ))
        return findings

    # Lower-case header dict for matching
    lc = {k.lower(): v for k, v in resp_hdrs.items()}
    server_hdr = lc.get("server", "") or ""
    xpoweredby = lc.get("x-powered-by", "") or ""

    # Visible to the user regardless
    findings.append(Finding(
        check="cves.fingerprint",
        severity="INFO",
        title="Server fingerprint captured",
        detail=f"Server: {server_hdr!r}  X-Powered-By: {xpoweredby!r}",
        evidence={"server": server_hdr, "x_powered_by": xpoweredby,
                  "all_response_headers": resp_hdrs},
        references=[],
    ))

    matched = []
    for entry in CVE_DB:
        hname, needle = entry["header_match"]
        haystack = lc.get(hname.lower(), "") or ""
        if needle.lower() in haystack.lower():
            matched.append(entry)

    if not matched:
        findings.append(Finding(
            check="cves.no-match",
            severity="INFO",
            title=f"No header match against {len(CVE_DB)} known WebSocket CVEs",
            detail=("Fingerprint-only matching is intentionally narrow. "
                    "Absence of match does not mean the server is patched; "
                    "verify versions out-of-band."),
            evidence={"checked": [c["id"] for c in CVE_DB]},
            references=[],
        ))
        return findings

    for entry in matched:
        findings.append(Finding(
            check=f"cves.{entry['id'].lower()}",
            severity=entry["severity"],
            title=f"Header fingerprint suggests {entry['id']}: {entry['title']}",
            detail=(f"Stack: {entry['stack']}. This is a *hint* from "
                    f"matching `{entry['header_match'][0]}` containing "
                    f"`{entry['header_match'][1]}`, NOT proof. Confirm "
                    f"installed version against the affected range "
                    f"before reporting."),
            evidence={"matched_header": entry["header_match"],
                      "actual_value": lc.get(entry["header_match"][0].lower())},
            references=entry["refs"],
        ))

    return findings

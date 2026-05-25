"""Cross-Site WebSocket Hijacking (CSWSH) detection.

Origin header enforcement is the only thing standing between a malicious
website and your authenticated WebSocket. Many embedded servers either:
  - never check Origin,
  - check it with a substring match,
  - or accept null/empty Origin.

If a server accepts a forged Origin while you hold a session cookie, an
attacker page can open the same session in the user's browser and
exfiltrate/inject. We test the handshake response.

References:
  - https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking_(CSWSH)
  - PortSwigger: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

import websockets
from websockets.exceptions import InvalidHandshake, InvalidStatusCode

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
)

EVIL_ORIGINS = [
    "https://attacker.example",
    "http://attacker.example",
    "null",
    "",
    "https://evil.com",
    "file://",
]


async def _try_origin(url: str, ssl_ctx, headers: dict, origin: str, timeout: float):
    """Return (accepted: bool, status_or_subprotocol)."""
    hdrs = list(headers.items()) if headers else []
    if origin:
        hdrs.append(("Origin", origin))
    try:
        ws = await websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=hdrs,
            open_timeout=timeout,
            close_timeout=1,
            ping_interval=None,
        )
        sub = ws.subprotocol
        with suppress(Exception):
            await ws.close()
        return True, sub
    except InvalidStatusCode as exc:
        return False, f"HTTP {exc.status_code}"
    except InvalidHandshake as exc:
        return False, f"handshake: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"err: {type(exc).__name__}"


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    findings: list = []

    # Baseline: connect with NO Origin header
    baseline_ok, baseline_info = await _try_origin(
        url, ssl_ctx, headers, "", args.timeout
    )

    # Probe with each forged Origin
    accepted = {}
    for origin in EVIL_ORIGINS:
        ok, info = await _try_origin(url, ssl_ctx, headers, origin, args.timeout)
        accepted[origin or "<none>"] = (ok, info)

    accepting = [o for o, (ok, _) in accepted.items() if ok]

    # Falsifiability:
    #   - If baseline (no Origin) was REJECTED but evil Origins are ACCEPTED,
    #     that's a clear gap (HIGH confidence).
    #   - If baseline is also accepted, this is a no-Origin-enforcement state
    #     by design (still CSWSH-relevant, but we can't distinguish "all
    #     Origins accepted" from "Origin not checked").
    #   - If everything is rejected, server has either Origin enforcement
    #     OR a bigger gating problem (e.g. unrelated handshake failure).

    if not baseline_ok and len(accepting) >= 4:
        sev, conf = "HIGH", "high"
        title = ("Origin enforcement bypassed: baseline rejected, "
                 "forged Origins accepted")
    elif baseline_ok and len(accepting) == len(EVIL_ORIGINS):
        sev, conf = "HIGH", "high"
        title = ("No Origin enforcement: every Origin (including "
                 "attacker.example, null, file://) is accepted")
    elif accepting:
        sev, conf = "MEDIUM", "medium"
        title = (f"Partial Origin enforcement: "
                 f"{len(accepting)}/{len(EVIL_ORIGINS)} forged Origins accepted")
    elif baseline_ok and not accepting:
        sev, conf = "INFO", "high"
        title = ("Server accepts no-Origin but rejects all forged Origins "
                 "(possibly Origin allowlist, possibly browser-only filter)")
    else:
        sev, conf = "INFO", "high"
        title = "Origin header is enforced (all evil Origins rejected)"

    detail = (
        f"baseline_no_origin_accepted={baseline_ok} ({baseline_info}). "
        f"{len(accepting)}/{len(EVIL_ORIGINS)} forged Origins accepted: "
        f"{', '.join(accepting) if accepting else 'none'}."
    )
    findings.append(Finding(
        check="cswsh.origin-enforcement",
        severity=sev,
        confidence=conf,
        title=title,
        detail=detail,
        evidence={"accepted": {k: {"ok": v[0], "info": v[1]}
                               for k, v in accepted.items()},
                  "baseline": {"ok": baseline_ok, "info": baseline_info}},
        references=[
            "https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking_(CSWSH)",
            "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
        ],
    ))
    return findings

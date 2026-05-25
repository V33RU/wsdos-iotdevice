"""Authentication & authorization tests for WebSocket endpoints.

Detection logic is *baseline-first*: before claiming any specific bypass,
we verify that the endpoint distinguishes between authenticated and
unauthenticated handshakes. If it accepts no-auth at the handshake
layer (common, often by design with message-level auth), specific
"forged token accepted" findings would be misleading and are suppressed.
"""

from __future__ import annotations

from contextlib import suppress

import websockets
from websockets.exceptions import InvalidHandshake, InvalidStatusCode

from ..common import (
    Finding,
    build_ssl_context,
    normalize_target,
    parse_headers,
)


async def _connect(url, ssl_ctx, headers, timeout):
    try:
        ws = await websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=list(headers.items()) if headers else None,
            open_timeout=timeout,
            close_timeout=1,
            ping_interval=None,
        )
        return ws, None
    except InvalidStatusCode as exc:
        return None, f"HTTP {exc.status_code}"
    except InvalidHandshake as exc:
        return None, f"handshake: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, f"err: {type(exc).__name__}"


async def _handshake_accepted(url, ssl_ctx, headers, timeout) -> tuple[bool, str]:
    """Return (accepted_at_handshake_layer, info)."""
    ws, err = await _connect(url, ssl_ctx, headers, timeout)
    if ws is None:
        return False, err
    with suppress(Exception):
        await ws.close()
    return True, "ok"


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    base_headers = parse_headers(args.header)
    findings: list = []

    # ----- 1. Baseline: connect with NO auth at all
    no_auth = {k: v for k, v in base_headers.items()
               if k.lower() not in ("authorization", "cookie", "x-api-key")}
    baseline_ok, baseline_info = await _handshake_accepted(
        url, ssl_ctx, no_auth, args.timeout
    )

    if baseline_ok:
        # Endpoint is open at the WS handshake layer. This is COMMON for
        # control-plane WS servers that enforce auth at the application
        # message layer (e.g. Crestron Control Subnet API, ROS rosbridge).
        # Therefore: do NOT make claims about token validity because we
        # cannot distinguish "trusted my forged JWT" from "accepts anything".
        findings.append(Finding(
            check="auth.handshake-open",
            severity="MEDIUM",
            title="WebSocket handshake accepts unauthenticated clients",
            detail=("Server completed the handshake with no Authorization / "
                    "Cookie / X-API-Key header. This is acceptable only if "
                    "the application enforces auth in the first WS message "
                    "(check vendor docs). If there is no post-handshake auth "
                    "either, this is a HIGH-severity exposure on a "
                    "control-plane endpoint. Skipping JWT-bypass sub-checks "
                    "because their results would be unreliable against an "
                    "open handshake."),
            evidence={"url": url, "headers_sent": no_auth},
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
            ],
        ))

        # Token-in-query-string is independent of handshake gating
        if any(p in url for p in ("token=", "api_key=", "auth=", "access_token=")):
            findings.append(Finding(
                check="auth.token-in-query-string",
                severity="MEDIUM",
                title="Authentication token passed via URL query string",
                detail=("Tokens in query strings get logged by HTTP proxies, "
                        "load balancers, and browser history. Move to the "
                        "Authorization header or to the first WS frame."),
                evidence={"url": url},
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc6750#section-2.3",
                ],
            ))
        return findings

    # ----- Baseline REJECTED. Handshake-layer auth IS being enforced.
    findings.append(Finding(
        check="auth.handshake-gated",
        severity="INFO",
        title="WebSocket handshake refuses unauthenticated clients (good)",
        detail=f"Baseline no-auth handshake was rejected: {baseline_info}. "
               "Now testing token-validation sub-cases against this gate.",
        evidence={"baseline_info": baseline_info},
        references=[],
    ))

    # ----- 2. JWT alg:none — meaningful only because baseline rejected no-auth
    none_jwt = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
                "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.")
    bad_headers = dict(no_auth, Authorization=f"Bearer {none_jwt}")
    accepted, info = await _handshake_accepted(
        url, ssl_ctx, bad_headers, args.timeout
    )
    if accepted:
        findings.append(Finding(
            check="auth.jwt-alg-none",
            severity="CRITICAL",
            title="Server accepted JWT with 'alg: none'",
            detail=("Handshake succeeded with a Bearer token whose JWT "
                    "header is `{\"alg\":\"none\"}` and claims "
                    "`role=admin`, even though the baseline no-auth "
                    "handshake was rejected. The server either does not "
                    "verify the signature, or treats the Authorization "
                    "header as opaque allow-listed input (CVE-2015-9235 "
                    "family)."),
            evidence={"token_used": none_jwt, "info": info},
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235",
                "https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.5",
            ],
        ))

    # ----- 3. Bearer with obvious garbage — sanity counter-test
    garbage_headers = dict(no_auth, Authorization="Bearer NOT_A_TOKEN_AT_ALL")
    accepted, info = await _handshake_accepted(
        url, ssl_ctx, garbage_headers, args.timeout
    )
    if accepted:
        findings.append(Finding(
            check="auth.bearer-anything-accepted",
            severity="HIGH",
            title=("Server accepts ANY Bearer header value, even literal "
                   "'NOT_A_TOKEN_AT_ALL'"),
            detail=("Handshake succeeded with a non-JWT, non-base64 bearer "
                    "value. The server appears to only check for the "
                    "*presence* of an Authorization header, not its "
                    "contents. The earlier `auth.jwt-alg-none` finding (if "
                    "any) is therefore also explained by this weaker bug."),
            evidence={"header_sent": "Authorization: Bearer NOT_A_TOKEN_AT_ALL"},
            references=[],
        ))

    # ----- 4. Token in query string (independent of bypass tests)
    if any(p in url for p in ("token=", "api_key=", "auth=", "access_token=")):
        findings.append(Finding(
            check="auth.token-in-query-string",
            severity="MEDIUM",
            title="Authentication token passed via URL query string",
            detail=("Tokens in query strings get logged by HTTP proxies, "
                    "load balancers, and browser history. Move to the "
                    "Authorization header or to the first WS frame."),
            evidence={"url": url},
            references=[
                "https://datatracker.ietf.org/doc/html/rfc6750#section-2.3",
            ],
        ))

    return findings

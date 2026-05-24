"""Authentication & authorization tests for WebSocket endpoints.

Common bugs:
  1. No auth at all on a control-plane endpoint
  2. Auth only enforced on the initial HTTP request, not on WS messages
  3. Token passed in query string (gets logged in proxies, history)
  4. JWT 'none' algorithm accepted
  5. Subscription/topic auth missing (you can subscribe to other users)
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


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    base_headers = parse_headers(args.header)
    findings: list = []

    # 1. Connect with NO auth at all
    no_auth = {k: v for k, v in base_headers.items()
               if k.lower() not in ("authorization", "cookie", "x-api-key")}
    ws, err = await _connect(url, ssl_ctx, no_auth, args.timeout)
    if ws is not None:
        with suppress(Exception):
            await ws.close()
        findings.append(Finding(
            check="auth.no-auth-accepted",
            severity="HIGH",
            title="Endpoint accepts connections with NO authentication",
            detail="The WebSocket server completed the handshake without any "
                   "Authorization / Cookie / X-API-Key header. If this is a "
                   "control-plane endpoint, anyone on the network can connect.",
            evidence={"url": url, "headers_sent": no_auth},
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
            ],
        ))
    else:
        findings.append(Finding(
            check="auth.no-auth-accepted",
            severity="INFO",
            title="No-auth handshake refused (good)",
            detail=f"Server rejected the unauthenticated handshake: {err}",
            evidence={"error": err},
            references=[],
        ))

    # 2. JWT 'none' algorithm
    none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
    bad_headers = dict(no_auth, Authorization=f"Bearer {none_jwt}")
    ws, err = await _connect(url, ssl_ctx, bad_headers, args.timeout)
    if ws is not None:
        with suppress(Exception):
            await ws.close()
        findings.append(Finding(
            check="auth.jwt-alg-none",
            severity="CRITICAL",
            title="Server accepted JWT with 'alg: none'",
            detail="A bearer token with header alg=none and claim role=admin "
                   "was accepted. This is a classic JWT validation flaw "
                   "(CVE-2015-9235 family).",
            evidence={"token": none_jwt},
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235",
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
            ],
        ))

    # 3. Token in query string
    if "token=" in url or "api_key=" in url or "auth=" in url:
        findings.append(Finding(
            check="auth.token-in-query-string",
            severity="MEDIUM",
            title="Authentication token passed via URL query string",
            detail="Tokens in query strings get logged by HTTP intermediaries, "
                   "proxies, and browser history. Move to Authorization header "
                   "or to the first WS frame.",
            evidence={"url": url},
            references=[
                "https://datatracker.ietf.org/doc/html/rfc6750#section-2.3",
            ],
        ))

    return findings

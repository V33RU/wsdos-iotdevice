"""TLS hygiene checks for wss:// endpoints.

Embedded devices typically ship hard-coded self-signed certs that
never rotate, weak ciphers, or expired CAs. We negotiate TLS and
report concerning properties.
"""

from __future__ import annotations

import asyncio
import datetime
import ssl
from urllib.parse import urlparse

from ..common import Finding, normalize_target


async def _peek_cert(host: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
        timeout=timeout,
    )
    sock = writer.get_extra_info("ssl_object")
    cert = sock.getpeercert(binary_form=False) if sock else None
    cert_bin = sock.getpeercert(binary_form=True) if sock else None
    cipher = sock.cipher() if sock else None
    version = sock.version() if sock else None
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    # Re-fetch with default context to test cert validity
    return cert, cert_bin, cipher, version


async def check(args) -> list:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    findings: list = []
    if not url.startswith("wss://"):
        is_loopback = (args.target.startswith("ws://127.")
                       or args.target.startswith("ws://localhost")
                       or args.target.startswith("ws://[::1]"))
        findings.append(Finding(
            check="tls.plaintext",
            severity="INFO" if is_loopback else "HIGH",
            confidence="high",
            title=("WebSocket served over loopback plaintext (local-only, OK)"
                   if is_loopback
                   else "WebSocket served over plaintext ws://"),
            detail=("All traffic (including auth tokens, sensor data, commands) "
                    "is exposed to any on-path attacker. Move to wss:// with a "
                    "valid certificate." if not is_loopback
                    else "Loopback plaintext is acceptable; no on-path threat."),
            evidence={"url": url, "loopback": is_loopback},
            references=["https://datatracker.ietf.org/doc/html/rfc6455#section-10.6"],
        ))
        return findings

    u = urlparse(url)
    host, port = u.hostname, u.port or 443
    try:
        cert, cert_bin, cipher, version = await _peek_cert(host, port, args.timeout)
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding(
            check="tls.handshake-failed",
            severity="MEDIUM",
            title="TLS handshake to wss:// endpoint failed",
            detail=f"{type(exc).__name__}: {exc}",
            evidence={"host": host, "port": port},
            references=[],
        ))
        return findings

    # TLS version
    if version and version < "TLSv1.2":
        findings.append(Finding(
            check="tls.weak-version",
            severity="HIGH",
            title=f"Server negotiated obsolete TLS version: {version}",
            detail="TLS 1.0/1.1 are deprecated (RFC 8996). Use TLS 1.2+ only.",
            evidence={"version": version},
            references=["https://datatracker.ietf.org/doc/html/rfc8996"],
        ))

    # Cipher
    if cipher:
        name = cipher[0]
        if any(weak in name for weak in ("RC4", "3DES", "MD5", "NULL", "EXPORT", "DES-CBC")):
            findings.append(Finding(
                check="tls.weak-cipher",
                severity="HIGH",
                title=f"Server uses weak cipher suite: {name}",
                detail="Cipher contains a deprecated primitive.",
                evidence={"cipher": cipher},
                references=[],
            ))

    # Cert validity (use default-context verify)
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=args.timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        findings.append(Finding(
            check="tls.cert-trusted",
            severity="INFO",
            title="Certificate verified against system trust store",
            detail="Server presents a publicly-trusted certificate.",
            evidence={"version": version, "cipher": cipher[0] if cipher else None},
            references=[],
        ))
    except ssl.SSLError as exc:
        findings.append(Finding(
            check="tls.cert-untrusted",
            severity="MEDIUM",
            title="Certificate not trusted by system CA store",
            detail=f"SSL verification failed: {exc}. Likely self-signed or "
                   "expired; fine for lab use but not for production.",
            evidence={"error": str(exc)},
            references=[],
        ))
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding(
            check="tls.cert-untrusted",
            severity="MEDIUM",
            title="Could not verify certificate",
            detail=f"{type(exc).__name__}: {exc}",
            evidence={},
            references=[],
            confidence="medium",
        ))

    return findings

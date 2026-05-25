"""Shared helpers: URL parsing, headers, metrics, signal handling."""

from __future__ import annotations

import asyncio
import json
import random
import signal
import ssl
import string
import sys
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Optional


# ----------------------------------------------------------------------
# Metrics shared across attack modes
# ----------------------------------------------------------------------


@dataclass
class Metrics:
    started_at: float = field(default_factory=time.monotonic)
    connections_attempted: int = 0
    connections_open: int = 0
    connections_peak: int = 0
    connections_failed: int = 0
    handshake_rejects: int = 0
    bytes_sent: int = 0
    frames_sent: int = 0
    errors_by_type: dict = field(default_factory=dict)
    last_error: str = ""

    def conn_opened(self) -> None:
        self.connections_open += 1
        self.connections_peak = max(self.connections_peak, self.connections_open)

    def conn_closed(self) -> None:
        self.connections_open = max(0, self.connections_open - 1)

    def record_error(self, exc: BaseException) -> None:
        name = type(exc).__name__
        self.errors_by_type[name] = self.errors_by_type.get(name, 0) + 1
        self.last_error = f"{name}: {exc}"

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def snapshot(self) -> dict:
        return {
            "elapsed_s": round(self.elapsed(), 2),
            "attempted": self.connections_attempted,
            "open_now": self.connections_open,
            "peak_open": self.connections_peak,
            "failed": self.connections_failed,
            "handshake_rejects": self.handshake_rejects,
            "bytes_sent": self.bytes_sent,
            "frames_sent": self.frames_sent,
            "errors_by_type": dict(self.errors_by_type),
        }


METRICS = Metrics()
STOPPING = asyncio.Event()


# ----------------------------------------------------------------------
# URL & target helpers
# ----------------------------------------------------------------------


def normalize_target(raw: str, port: Optional[int] = None,
                     path: str = "/", tls: bool = False) -> str:
    """Accept '1.2.3.4', '1.2.3.4:8080', or 'ws[s]://host/path' forms."""
    if raw.startswith(("ws://", "wss://")):
        return raw
    scheme = "wss" if tls else "ws"
    if ":" in raw and not raw.startswith("["):
        host = raw
    elif port:
        host = f"{raw}:{port}"
    else:
        host = raw
    return f"{scheme}://{host}{path}"


def to_http_url(ws_url: str) -> str:
    """Convert ws:// to http:// and wss:// to https://."""
    return ws_url.replace("ws://", "http://", 1).replace("wss://", "https://", 1)


def parse_headers(items) -> dict:
    out = {}
    for item in items or []:
        if ":" not in item:
            raise SystemExit(f"bad --header {item!r}, expected 'Name: value'")
        k, _, v = item.partition(":")
        out[k.strip()] = v.strip()
    return out


def build_ssl_context(insecure: bool) -> Optional[ssl.SSLContext]:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def random_ws_key() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=22)) + "=="


# ----------------------------------------------------------------------
# Signal handling
# ----------------------------------------------------------------------


def install_signal_handlers(loop) -> None:
    def _stop(*_):
        if not STOPPING.is_set():
            sys.stderr.write("\n[!] stop signal received, draining...\n")
            STOPPING.set()
    with suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGINT, _stop)
        loop.add_signal_handler(signal.SIGTERM, _stop)


# ----------------------------------------------------------------------
# Output formatting
# ----------------------------------------------------------------------


COLORS = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}


def color(text: str, c: str) -> str:
    if not sys.stderr.isatty():
        return text
    return f"{COLORS.get(c, '')}{text}{COLORS['reset']}"


SEVERITY_COLORS = {
    "INFO": "blue", "LOW": "cyan", "MEDIUM": "yellow",
    "HIGH": "magenta", "CRITICAL": "red",
}


def severity_label(sev: str) -> str:
    return color(f"[{sev}]", SEVERITY_COLORS.get(sev, "reset"))


# ----------------------------------------------------------------------
# Findings container (used by all vuln modules)
# ----------------------------------------------------------------------


@dataclass
class Finding:
    check: str                      # short id, e.g., 'cswsh.origin-bypass'
    severity: str                   # INFO / LOW / MEDIUM / HIGH / CRITICAL
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)
    references: list = field(default_factory=list)
    confidence: str = "medium"      # low / medium / high — how sure are we?

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "references": self.references,
        }

    def pretty(self) -> str:
        conf = color(f"({self.confidence})", "dim")
        head = (f"{severity_label(self.severity)} {conf} "
                f"{color(self.check, 'bold')} {self.title}")
        body = f"      {color(self.detail, 'dim')}"
        return head + "\n" + body


# ----------------------------------------------------------------------
# Rate-limit aware pacing (shared by the scan dispatcher)
# ----------------------------------------------------------------------


class Pacer:
    """Tracks recent connection refusals and inserts adaptive backoff.

    The scan dispatcher calls .wait() between checks. If recent checks
    saw ConnectionRefused / ConnectionResetError errors, the wait grows
    exponentially (capped). Otherwise, the wait stays at .base_delay.
    """

    def __init__(self, base_delay: float = 0.5, max_delay: float = 8.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.consecutive_refusals = 0

    def note_check_result(self, findings_or_error) -> None:
        """Inspect findings (or an error string) from the last check;
        bump the refusal counter if there's evidence the device is throttling."""
        text = str(findings_or_error).lower()
        if "connectionrefused" in text or "connection refused" in text \
                or "connectionreset" in text or "connection reset" in text:
            self.consecutive_refusals += 1
        else:
            self.consecutive_refusals = max(0, self.consecutive_refusals - 1)

    async def wait(self) -> float:
        delay = min(
            self.base_delay * (2 ** self.consecutive_refusals),
            self.max_delay,
        )
        await asyncio.sleep(delay)
        return delay

    def is_throttled(self) -> bool:
        return self.consecutive_refusals >= 2

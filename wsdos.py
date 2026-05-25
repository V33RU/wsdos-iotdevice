#!/usr/bin/env python3
"""
wsdos: WebSocket security testing framework for IoT, automotive, and
connected devices.

Authorized testing only. Active attack modes require --i-have-authorization.
See README for usage. License: MIT.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from contextlib import suppress

try:
    import websockets  # noqa: F401
except ImportError:
    sys.stderr.write(
        "error: the 'websockets' package is required.\n"
        "       install with: pip install -r requirements.txt\n"
    )
    sys.exit(2)

from wsdoscore import __version__
from wsdoscore.common import (
    METRICS,
    STOPPING,
    Finding,
    Pacer,
    color,
    install_signal_handlers,
    severity_label,
)
from wsdoscore import recon, stress, presets, report
from wsdoscore.vuln import CHECK_REGISTRY


BANNER = rf"""
 __      _____  ___   ___  ___
 \ \    / / __||   \ / _ \/ __|
  \ \/\/ /\__ \| |) | (_) \__ \
   \_/\_/ |___/|___/ \___/|___/  v{__version__}
 WebSocket security framework for IoT / automotive / connected devices
 github.com/V33RU/wsdos-iotdevice
"""

LEGAL = (
    "Authorized testing only. By using this tool you confirm you have "
    "explicit permission to test the target. Misuse is your responsibility."
)


# ----------------------------------------------------------------------
# Argparse plumbing
# ----------------------------------------------------------------------


def add_common_target_args(sp):
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


def add_stress_args(sp):
    add_common_target_args(sp)
    sp.add_argument("-d", "--duration", type=float, default=0,
                    help="Stop after N seconds (0 = until Ctrl+C)")
    sp.add_argument("--report-every", type=float, default=1.0,
                    help="Live-metrics interval (s)")
    sp.add_argument("--json", action="store_true",
                    help="Emit metrics as JSON lines (stdout)")
    sp.add_argument("--i-have-authorization", action="store_true",
                    help="REQUIRED to actually run an attack mode")


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wsdos",
        description="WebSocket security framework (authorized testing).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=LEGAL,
    )
    p.add_argument("--version", action="version",
                   version=f"wsdos {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="CMD")

    # ---- recon ----
    sp = sub.add_parser("probe", help="Recon a target (single handshake).")
    add_common_target_args(sp)
    sp.set_defaults(func=cmd_probe)

    # ---- vuln scan (passive/safe) ----
    sp = sub.add_parser("scan", help="Run all non-destructive vuln checks.")
    add_common_target_args(sp)
    sp.add_argument("--only", action="append",
                    help=f"Run only listed checks ({', '.join(CHECK_REGISTRY)})")
    sp.add_argument("--skip", action="append", help="Skip listed checks")
    sp.add_argument("--check-delay", type=float, default=0.5,
                    help="Base delay (s) between checks; doubles on each "
                         "consecutive ConnectionRefused, capped at 8s")
    sp.add_argument("--format", choices=("pretty", "json", "markdown"),
                    default="pretty", help="Report format")
    sp.add_argument("-o", "--output", help="Write report to file")
    sp.set_defaults(func=cmd_scan)

    # ---- individual vuln checks (vuln <name>) ----
    sp_vuln = sub.add_parser("vuln", help="Run a single vuln check.")
    sub_vuln = sp_vuln.add_subparsers(dest="vuln_name", required=True)
    for name in CHECK_REGISTRY:
        v = sub_vuln.add_parser(name, help=f"Run only the {name} check.")
        add_common_target_args(v)
        v.add_argument("--format", choices=("pretty", "json", "markdown"),
                       default="pretty")
        v.set_defaults(func=cmd_single_vuln, vuln_name=name)

    # ---- presets ----
    sp_pre = sub.add_parser("preset", help="Vendor/category presets.")
    sub_pre = sp_pre.add_subparsers(dest="preset_action", required=True)
    sub_pre.add_parser("list", help="List all known presets.").set_defaults(func=cmd_preset_list)
    pr = sub_pre.add_parser("show", help="Show preset details.")
    pr.add_argument("name")
    pr.set_defaults(func=cmd_preset_show)
    pr = sub_pre.add_parser("scan", help="Run scan against a preset target.")
    pr.add_argument("name", help="Preset name")
    pr.add_argument("host", help="Target host or IP")
    pr.add_argument("--format", choices=("pretty", "json", "markdown"), default="pretty")
    pr.add_argument("-o", "--output")
    pr.set_defaults(func=cmd_preset_scan)

    # ---- stress modes ----
    sp_flood = sub.add_parser("flood", help="Open many concurrent connections.")
    add_stress_args(sp_flood)
    sp_flood.add_argument("-n", "--count", type=int, default=1000)
    sp_flood.add_argument("-c", "--concurrency", type=int, default=200)
    sp_flood.set_defaults(func=cmd_stress, handler=stress.mode_flood)

    sp_slow = sub.add_parser("slowloris", help="Hold connections with tiny frames.")
    add_stress_args(sp_slow)
    sp_slow.add_argument("-n", "--count", type=int, default=500)
    sp_slow.add_argument("-i", "--interval", type=float, default=15.0)
    sp_slow.set_defaults(func=cmd_stress, handler=stress.mode_slowloris)

    sp_frame = sub.add_parser("frame-flood", help="Hammer with rapid frames.")
    add_stress_args(sp_frame)
    sp_frame.add_argument("-w", "--workers", type=int, default=10)
    sp_frame.add_argument("--payload-size", type=int, default=64)
    sp_frame.set_defaults(func=cmd_stress, handler=stress.mode_frame_flood)

    sp_pay = sub.add_parser("payload", help="Send oversized frames.")
    add_stress_args(sp_pay)
    sp_pay.add_argument("-w", "--workers", type=int, default=5)
    sp_pay.add_argument("--payload-size", type=int, default=1_048_576)
    sp_pay.add_argument("--frames", type=int, default=0)
    sp_pay.add_argument("-i", "--interval", type=float, default=0)
    sp_pay.set_defaults(func=cmd_stress, handler=stress.mode_payload)

    sp_zip = sub.add_parser("compression",
                            help="permessage-deflate amplification (attack mode).")
    add_stress_args(sp_zip)
    sp_zip.add_argument("-w", "--workers", type=int, default=5)
    sp_zip.add_argument("--payload-size", type=int, default=10 * 1024 * 1024)
    sp_zip.set_defaults(func=cmd_stress, handler=stress.mode_compression)

    return p


# ----------------------------------------------------------------------
# Command handlers
# ----------------------------------------------------------------------


async def cmd_probe(args):
    info = await recon.run(args)
    print(json.dumps(info, indent=2))


async def _run_checks(args, names):
    findings = []
    pacer = Pacer(base_delay=getattr(args, "check_delay", 0.5))
    for i, name in enumerate(names):
        mod = CHECK_REGISTRY[name]
        if i > 0:
            delay = await pacer.wait()
            if pacer.is_throttled():
                sys.stderr.write(color(
                    f"\n[!] device appears throttled (waited {delay:.1f}s)\n",
                    "yellow"))
        sys.stderr.write(color(f"\n[*] running check: {name}\n", "cyan"))
        try:
            sub = await mod.check(args)
            findings.extend(sub)
            pacer.note_check_result(sub)
        except Exception as exc:  # noqa: BLE001
            err_msg = f"{type(exc).__name__}: {exc}"
            findings.append(Finding(
                check=f"{name}.error",
                severity="INFO",
                title=f"Check {name} crashed",
                detail=err_msg,
                confidence="high",
            ))
            pacer.note_check_result(err_msg)
    if pacer.consecutive_refusals >= 3:
        # Distinguish "target down" from "target rate-limited mid-scan":
        # count refusal-containing findings across the whole run. If most
        # of them refused, target is unreachable. Otherwise rate-limited
        # (some early checks worked, later ones failed).
        refused_count = sum(
            1 for f in findings
            if ("connectionrefused" in str(f.evidence).lower()
                or "connection refused" in (f.detail or "").lower()
                or "connect call failed" in (f.detail or "").lower()
                or "handshake_failures" in str(f.evidence).lower())
        )
        all_refused = refused_count >= max(3, len(names) - 2)
        if all_refused:
            findings.append(Finding(
                check="scan.target-unreachable",
                severity="INFO",
                confidence="high",
                title="Target appears unreachable",
                detail=("Every check failed to connect. Verify the target "
                        "host:port is correct, that the device is up, and "
                        "that no firewall is blocking the scanner's source IP."),
                evidence={"checks_attempted": len(names)},
            ))
        else:
            findings.append(Finding(
                check="scan.rate-limited",
                severity="INFO",
                confidence="medium",
                title="Device rate-limited the scanner during this run",
                detail=("Earlier checks succeeded but later checks could "
                        "not connect. The device has a connection cap or "
                        "per-IP rate limiter (often a good defensive "
                        "behavior). Findings near the end of the scan may "
                        "be incomplete; rerun with a higher --check-delay."),
                evidence={"consecutive_refusals_at_end":
                          pacer.consecutive_refusals},
            ))
    return findings


async def cmd_scan(args):
    names = list(CHECK_REGISTRY.keys())
    if args.only:
        wanted = set()
        for item in args.only:
            wanted.update(s.strip() for s in item.split(","))
        names = [n for n in names if n in wanted]
    if args.skip:
        skip = set()
        for item in args.skip:
            skip.update(s.strip() for s in item.split(","))
        names = [n for n in names if n not in skip]

    sys.stderr.write(BANNER + "\n" + LEGAL + "\n\n")
    findings = await _run_checks(args, names)
    from wsdoscore.common import normalize_target
    target = normalize_target(args.target, args.port, args.path, args.tls)
    out = report.emit(findings, args.format, target)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out)
        sys.stderr.write(color(f"\n[+] wrote {args.output}\n", "green"))
    else:
        print(out)


async def cmd_single_vuln(args):
    findings = await _run_checks(args, [args.vuln_name])
    from wsdoscore.common import normalize_target
    target = normalize_target(args.target, args.port, args.path, args.tls)
    print(report.emit(findings, args.format, target))


def cmd_preset_list(args):
    cats = presets.list_categories()
    print(color("\nKnown presets:", "bold"))
    for cat, items in sorted(cats.items()):
        print(color(f"\n[{cat}]", "cyan"))
        for name, desc in items:
            print(f"  {color(name, 'green'):<35} {desc}")
    print()


def cmd_preset_show(args):
    p = presets.get(args.name)
    print(json.dumps({"name": args.name, **p}, indent=2))


async def cmd_preset_scan(args):
    p = presets.get(args.name)
    # Construct a synthetic args namespace for scan
    class A:
        pass
    a = A()
    a.target = args.host
    a.port = p["default_port"]
    a.path = p["default_path"]
    a.tls = p["scheme"] == "wss"
    a.insecure = True            # most embedded boxes ship self-signed certs
    a.header = []
    a.timeout = 10.0
    a.only = None
    a.skip = None
    a.format = args.format
    a.output = args.output
    sys.stderr.write(color(f"\n[+] preset: {args.name} ({p['description']})\n", "green"))
    await cmd_scan(a)


async def metrics_printer(interval: float, json_out: bool) -> None:
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


async def cmd_stress(args):
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
        await args.handler(args)
    finally:
        STOPPING.set()
        printer.cancel()
        with suppress(asyncio.CancelledError):
            await printer
        sys.stderr.write("\n")
        print(json.dumps({"final": METRICS.snapshot()}, indent=2))


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------


def main(argv=None) -> None:
    parser = make_parser()
    args = parser.parse_args(argv)
    func = args.func
    try:
        if asyncio.iscoroutinefunction(func):
            asyncio.run(func(args))
        else:
            func(args)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

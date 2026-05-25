# Changelog

## v3.1.0 - 2026-05-25

Detection-logic hardening. Removes fabricated content that snuck into v3.0,
makes every finding falsifiable, and adds adaptive rate-limit handling.

### Changed
- **CVE registry trimmed from 10 to 4 verified entries.** Removed:
  CVE-2024-23341 (was claimed aiohttp WS compression DoS; actually a Taiwanese
  text package HTML injection), CVE-2023-49081 (real aiohttp CVE but not
  WebSocket-specific), CVE-2021-22150 (claimed Kibana WS auth bypass; actually
  JS-YAML deserialization), CVE-2018-15598 (claimed SignalR cross-origin;
  actually Traefik API exposure), CVE-2022-21680 (real marked ReDoS but not
  WebSocket-specific), CVE-2022-32287 (claimed Mongoose WS frame OOB; actually
  Apache UIMA path traversal). Kept the 4 confirmed-real ones: CVE-2020-7662,
  CVE-2021-32640, CVE-2024-37890, CVE-2023-32695.
- **Preset registry trimmed from 18 to 8 verified entries.** Removed entries
  I could not verify against vendor docs (`tuya-local`, `hikvision-isapi`,
  `dahua-snap`, `obd-ws-bridge`, `tesla-firehose`, `open-vehicle-monitoring`,
  `niagara-n4-bajaws`, `bacnet-ws-gateway`, `modbus-ws-gateway`, `opcua-ws`).
  Every remaining preset cites its source URL.
- **Check execution order is now cheap-first**: tls -> cves -> cswsh -> auth
  -> compression -> smuggling -> frames. Aggressive raw-socket fuzzing runs
  last so it cannot starve earlier checks when the target rate-limits.
- **`auth` check no longer fires false `JWT alg:none` finding** when the
  baseline no-auth handshake was already accepted. Now establishes baseline
  first and only reports JWT-bypass when baseline was rejected (so the
  forged-token acceptance is genuinely a new behavior). Also added a
  counter-test `auth.bearer-anything-accepted` that catches the weaker case
  of "any Bearer value accepted" so JWT findings can be properly contextualized.
- **`cswsh` check now reports baseline disposition** and uses a 4-bucket
  classification: bypass-confirmed / no-enforcement / partial / good.
- **`tls.plaintext` finding downgraded to INFO for loopback targets** instead
  of HIGH (`ws://127.x`, `ws://localhost`, `ws://[::1]`).
- **`frames` check no longer reports HIGH "Server tolerates 5/5 malformed
  frames"** when the handshake itself failed (no data to interpret).

### Added
- **`Finding.confidence` field** (low/medium/high). Surfaced in pretty
  output and JSON. Every existing check assigns confidence based on whether
  there's a baseline comparison and how strong the evidence is.
- **`Pacer` class in `common.py`**: tracks consecutive `ConnectionRefused`
  errors and inserts exponential backoff between checks (capped at 8s).
- **`--check-delay` flag on `scan`** (default 0.5s): base inter-check delay.
- **New `scan.rate-limited` and `scan.target-unreachable` summary findings**:
  the scanner now distinguishes "device rate-limited me mid-scan" (some
  checks worked, later ones refused) from "target was never up" (every
  check refused).

### Why this matters
The v3.0 Crestron MC4-R audit surfaced three classes of false positives
caused by detection logic that didn't establish a baseline:
- `auth.jwt-alg-none` CRITICAL fired even though the server was simply
  accepting any unauthenticated handshake.
- `frames.rfc6455-compliance` HIGH fired against an unreachable target.
- `tls.handshake-failed`, `smuggling.error`, `cves.fingerprint-failed`
  all fired with no real data because the rate-limiter starved them.

v3.1 fixes all three classes.

## v3.0.0 - 2026-05-25

Framework restructure: passive vuln scanning + known-CVE fingerprinting + vendor presets.

### Added
- **`wsdoscore/` Python package** with clear module split (recon, stress, vuln, presets, report).
- **`scan` command**: run all non-destructive vuln checks against a target, output pretty / JSON / Markdown.
- **`vuln <name>` command**: run a single check (`cswsh`, `auth`, `compression`, `frames`, `smuggling`, `tls`, `cves`).
- **`preset <list|show|scan>` command**: 18 vendor presets across 7 categories:
  - `iot-smart-home`: shelly, tasmota, esphome, home-assistant, tuya-local
  - `iot-camera`: hikvision-isapi, dahua-snap
  - `iot-3dprinter`: octoprint
  - `robotics`: ros1-rosbridge, ros2-rosbridge, foxglove-bridge
  - `automotive`: obd-ws-bridge, tesla-firehose, open-vehicle-monitoring
  - `industrial-bms`: niagara-n4-bajaws, bacnet-ws-gateway
  - `industrial-scada`: modbus-ws-gateway, opcua-ws
- **7 vulnerability check modules**:
  - `cswsh`: Origin-enforcement bypass (CSWSH detection)
  - `auth`: no-auth, JWT alg:none, query-string tokens
  - `compression`: permessage-deflate amplification ratio measurement
  - `frames`: raw-socket RFC 6455 fuzzing (unmasked client, RSV bits, reserved opcodes, oversize length, dangling continuations)
  - `smuggling`: HTTP request smuggling via WS Upgrade boundary
  - `tls`: plaintext / weak version / weak cipher / cert validation
  - `cves`: fingerprint match against 10 documented WebSocket CVEs
- **Reporting**: pretty (terminal), JSON, Markdown.
- **`--only` / `--skip`** to filter which checks run.

### Known CVEs in fingerprint registry
CVE-2020-7662, CVE-2024-37890, CVE-2021-32640 (ws npm); CVE-2024-23341, CVE-2023-49081 (aiohttp); CVE-2021-22150 (Kibana); CVE-2018-15598 (SignalR); CVE-2023-32695 (socket.io-parser); CVE-2022-21680 (marked); CVE-2022-32287 (Mongoose).

### Changed
- Single-file `wsdos.py` slimmed to a CLI dispatcher; logic moved into `wsdoscore/`.
- Help text grouped: `probe`, `scan`, `vuln`, `preset`, plus the 5 attack modes.

### Backward compatibility
- All v2.0 attack-mode CLIs preserved (`flood`, `slowloris`, `frame-flood`, `payload`, `compression`).
- v2.0 `probe` preserved with same JSON output shape.

## v2.0.0 — 2026-05-25

Major rewrite.

### Added
- Async core using `websockets` library; tens of thousands of concurrent connections from a single host.
- Five attack modes: `flood`, `slowloris`, `frame-flood`, `payload`, `compression`.
- `probe` recon mode for safe single-handshake target inspection.
- Live metrics (stderr or JSON-lines stdout).
- TLS support (`wss://`) with optional cert-verification skip.
- Custom headers, paths, subprotocols.
- Safety gate: `--i-have-authorization` required for all attack modes.
- Graceful shutdown on SIGINT/SIGTERM with final JSON report.
- `requirements.txt`, `LICENSE` (MIT), structured `README.md`.

### Changed
- Switched from `websocket-client` (sync, sequential) to `websockets` (asyncio).
- CLI redesigned with argparse subcommands.

### Backward compatibility
- The original `wsdos.py <ip> <count>` call signature is replaced. Closest equivalent:
  `python3 wsdos.py flood <ip> -n <count> --i-have-authorization`

## v1.0 — 2019-10-29

Initial release: sequential WebSocket connection-flood PoC against IoT devices.

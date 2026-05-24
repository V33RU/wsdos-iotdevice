# Changelog

## v3.0.0 — 2026-05-25

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

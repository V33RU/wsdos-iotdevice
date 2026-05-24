# Changelog

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

<h1 align="center">wsdos</h1>
<p align="center">WebSocket stress-test framework for IoT devices.</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/asyncio-native-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/use-authorized_only-red?style=flat-square"/>
</p>

> ⚠️ **Authorized testing only.** This tool is built for IoT security research, red-team engagements, and stress-testing your own embedded devices. Running it against systems you do not own or have explicit written permission to test is illegal in most jurisdictions and unethical everywhere. The author accepts no responsibility for misuse.

Many IoT devices (cameras, smart plugs, hubs, industrial gateways, vacuum robots, kiosks) expose WebSocket control planes. Their embedded WebSocket servers are frequently single-threaded, have no per-IP connection caps, and choke long before a real DoS rate is reached. `wsdos` is a research tool that lets you measure how those endpoints behave under five common pressure patterns.

## Features

- **Async core** built on [`websockets`](https://github.com/python-websockets/websockets). Tens of thousands of concurrent connections from a single host.
- **Five attack modes** mapped to common bug classes:
  - `flood`: maximize concurrent open connections (classic file-descriptor / accept-loop exhaustion).
  - `slowloris`: hold many sockets open with periodic 1-byte frames (timeout-budget exhaustion).
  - `frame-flood`: blast rapid small frames over few connections (event-loop / parser CPU pressure).
  - `payload`: send oversized frames (framing buffer / message-size handling).
  - `compression`: ship highly-compressible payloads when the server speaks `permessage-deflate` (decompression amplification, CVE-2020-7662 family).
- **Recon mode (`probe`)** that does a single safe handshake and reports server, subprotocol, headers, and RTT.
- **Live metrics** to stderr (or JSON-lines to stdout for piping into Grafana / jq).
- **TLS support** (`wss://`) with optional cert-verification skip for self-signed embedded devices.
- **Custom headers** for `Origin`, `Cookie`, `Authorization`, `Sec-WebSocket-Protocol` negotiation.
- **Safety gate**: attack modes refuse to run without an explicit `--i-have-authorization` flag.
- **Graceful shutdown** on Ctrl+C; reports final stats.

## Install

```bash
git clone https://github.com/V33RU/wsdos-iotdevice.git
cd wsdos-iotdevice
pip install -r requirements.txt
```

Python 3.8 or newer.

## Usage

### Recon first (no flooding, single handshake)

```bash
python3 wsdos.py probe ws://192.168.1.42:8080/
```

```json
{
  "url": "ws://192.168.1.42:8080/",
  "ok": true,
  "rtt_ms": 4.13,
  "subprotocol": null,
  "headers_seen": {
    "Server": "Mongoose/6.18",
    "Sec-WebSocket-Extensions": "permessage-deflate"
  },
  "error": null
}
```

### Connection flood (the classic original behaviour, but async)

```bash
python3 wsdos.py flood 192.168.1.42 \
  --port 8080 \
  --count 5000 \
  --concurrency 500 \
  --duration 60 \
  --i-have-authorization
```

### Slowloris (hold connections cheaply)

```bash
python3 wsdos.py slowloris ws://192.168.1.42:8080/ \
  --count 800 \
  --interval 20 \
  --i-have-authorization
```

### Frame flood (CPU pressure on the parser)

```bash
python3 wsdos.py frame-flood ws://192.168.1.42:8080/api \
  --workers 20 \
  --payload-size 256 \
  --duration 30 \
  --i-have-authorization
```

### Oversized payload (memory pressure)

```bash
python3 wsdos.py payload ws://192.168.1.42:8080/ \
  --workers 5 \
  --payload-size 8388608 \
  --frames 50 \
  --i-have-authorization
```

### Compression amplification (decoder CPU/RAM)

```bash
python3 wsdos.py compression wss://device.lan/ws \
  --insecure \
  --workers 4 \
  --payload-size 10485760 \
  --duration 30 \
  --i-have-authorization
```

### Common flags (all modes)

| Flag | Meaning |
|---|---|
| `-p, --port` | Port when target is a bare host |
| `--path` | WebSocket path (default `/`) |
| `-s, --tls` | Use `wss://` even for bare hostnames |
| `-k, --insecure` | Skip TLS cert verification |
| `-H, --header` | Extra header `'Name: value'` (repeatable) |
| `-t, --timeout` | Per-connection handshake timeout (s) |
| `-d, --duration` | Stop after N seconds (0 = until Ctrl+C) |
| `--report-every` | Live-metrics interval (s) |
| `--json` | Emit metrics as JSON lines on stdout |
| `--i-have-authorization` | **Required** for any attack mode |

## Sample output

```
[  12.4s] open= 4823 peak= 4823 attempted=  5000 failed=  177 reject=   0 frames=     0 bytes=        0
```

Final report (JSON):

```json
{
  "final": {
    "elapsed_s": 60.04,
    "attempted": 5000,
    "open_now": 0,
    "peak_open": 4823,
    "failed": 177,
    "handshake_rejects": 0,
    "bytes_sent": 0,
    "frames_sent": 0,
    "errors_by_type": {
      "TimeoutError": 173,
      "ConnectionResetError": 4
    }
  }
}
```

## What to look for during a test

| Symptom | Likely root cause |
|---|---|
| Connections cap out at ~1020 | `ulimit -n` on a per-process fd limit |
| Server stops accepting new connections after N seconds | Per-IP connection cap, or accept-queue exhaustion |
| CPU pegged but accept still works | Single-threaded WebSocket handler |
| `handshake_rejects` jumps to non-zero | Server-side rate-limiting kicked in (good!) |
| Web UI becomes unreachable during flood | No separation between control-plane and data-plane |
| Device reboots / freezes | Watchdog or OOM kill |

## Limitations

- Single-source only. For distributed tests use a fleet (Locust, k6, or just N hosts via SSH).
- No HTTP/2 or QUIC transport (real WebSocket, RFC 6455).
- No automatic exploit generation. This is a stress-test, not an exploit framework.

## Demo (legacy)

The 2019 PoC video is still in the repo for context:

![](wsdos.jpg)

Original demo: <https://www.youtube.com/watch?v=GhhDNFVsQBc>

## License

MIT, see [LICENSE](LICENSE).

## Author

[@V33RU](https://github.com/V33RU) / [IOTSRG](https://iotsrg.org/) (`#iot-security #embedded #pentesting`)

> If you find weird behaviour on a real device, please follow coordinated disclosure with the vendor and consider submitting to the [Robot Vulnerability Database](https://github.com/aliasrobotics/RVD) or your local CERT.

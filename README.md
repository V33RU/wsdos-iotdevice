<h1 align="center">wsdos</h1>
<p align="center">WebSocket security testing framework for IoT, automotive, and connected devices.</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/asyncio-native-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/version-3.0.0-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/use-authorized_only-red?style=flat-square"/>
</p>

> ⚠️ **Authorized testing only.** This tool is built for IoT security research, red-team engagements, and stress-testing your own embedded devices. Running it against systems you do not own or have explicit written permission to test is illegal in most jurisdictions and unethical everywhere. The author accepts no responsibility for misuse.

`wsdos` started as a 35-line WebSocket connection-flood PoC in 2019. v3.0 turns it into a real framework: passive vulnerability scanning, known-CVE fingerprinting, frame-level fuzzing, vendor presets for the most common IoT / robot / automotive WebSocket endpoints, and the original DoS modes (now async).

## What's included

### 7 vulnerability checks (passive, non-destructive)
| Check | Detects |
|---|---|
| **`cswsh`** | Missing or weak `Origin` enforcement → Cross-Site WebSocket Hijacking |
| **`auth`** | Endpoints accepting no auth at all, JWT `alg:none`, tokens in query strings |
| **`compression`** | `permessage-deflate` amplification (CVE-2020-7662 / CVE-2024-23341 family) |
| **`frames`** | RFC 6455 violations: unmasked client frames, bad RSV bits, reserved opcodes, oversize length, dangling continuations |
| **`smuggling`** | HTTP request smuggling at the Upgrade boundary |
| **`tls`** | Plaintext `ws://`, obsolete TLS versions, weak ciphers, untrusted certs |
| **`cves`** | Fingerprint matching against 10+ documented WebSocket CVEs (ws npm, aiohttp, Mongoose, Kibana, SignalR, socket.io, marked) |

### 5 attack modes (require `--i-have-authorization`)
| Mode | Pressure pattern |
|---|---|
| **`flood`** | Maximize concurrent open connections (fd / accept-loop exhaustion) |
| **`slowloris`** | Hold many sockets open with periodic 1-byte frames (timeout-budget) |
| **`frame-flood`** | Blast rapid small frames over few connections (parser CPU) |
| **`payload`** | Send oversized frames (memory pressure) |
| **`compression`** | Ship highly-compressible payloads (decoder DoS) |

### 8 vendor presets across 3 categories (verified against vendor docs)
| Category | Presets |
|---|---|
| `robotics` | `ros1-rosbridge`, `ros2-rosbridge`, `foxglove-bridge` |
| `iot-smart-home` | `home-assistant`, `esphome-dashboard`, `shelly-gen2-rpc`, `tasmota-console` |
| `iot-3dprinter` | `octoprint` |

Every preset cites its primary source URL in `wsdoscore/presets.py`. Earlier
versions of this README listed ~18 presets across 7 categories; that table
contained guesses for vendors whose protocols I had not verified. v3.1.0
removed the unverified entries. PRs adding new verified presets (with a
primary source cite) are welcome.

## Install

```bash
git clone https://github.com/V33RU/wsdos-iotdevice.git
cd wsdos-iotdevice
pip install -r requirements.txt
```

Python 3.8+.

## Quick start

### Recon a target (single safe handshake)

```bash
python3 wsdos.py probe ws://192.168.1.42:8080/
```

### Full vuln scan (all 7 checks, no attack)

```bash
python3 wsdos.py scan ws://192.168.1.42:8080/ --format pretty
```

Output (pretty):

```
=== wsdos scan report ===
Target: ws://192.168.1.42:8080/
Findings: 9

Summary: [CRITICAL] 1  [HIGH] 2  [MEDIUM] 1  [INFO] 5

[CRITICAL] auth.jwt-alg-none Server accepted JWT with 'alg: none'
      A bearer token with header alg=none and claim role=admin was accepted.
      → https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235

[HIGH] cswsh.origin-enforcement No Origin enforcement (likely CSWSH-vulnerable)
      baseline (no Origin) accepted=True. 6/6 forged Origins accepted: ...

...
```

### Single vuln check

```bash
python3 wsdos.py vuln cswsh ws://192.168.1.42:8080/
python3 wsdos.py vuln cves ws://target/
python3 wsdos.py vuln tls wss://device.lan/ws -k
```

### Use a vendor preset

```bash
# list everything we know
python3 wsdos.py preset list

# show details
python3 wsdos.py preset show ros2-rosbridge

# scan with the preset's defaults (right port, path, scheme)
python3 wsdos.py preset scan shelly 192.168.1.50
python3 wsdos.py preset scan ros2-rosbridge 10.0.0.7
python3 wsdos.py preset scan tesla-firehose owner-api.teslamotors.com --format markdown -o tesla.md
```

### Reports

```bash
# pretty (default)
python3 wsdos.py scan <target>

# JSON for piping
python3 wsdos.py scan <target> --format json > report.json

# Markdown for tickets / engagement reports
python3 wsdos.py scan <target> --format markdown -o report.md
```

### Filter checks

```bash
python3 wsdos.py scan <target> --only cswsh,auth,tls
python3 wsdos.py scan <target> --skip frames,smuggling
```

### Attack modes (require explicit consent flag)

```bash
python3 wsdos.py flood ws://192.168.1.42:8080/ -n 5000 -c 500 -d 60 \
  --i-have-authorization

python3 wsdos.py slowloris ws://192.168.1.42:8080/ -n 800 -i 20 \
  --i-have-authorization

python3 wsdos.py frame-flood ws://192.168.1.42:8080/api -w 20 --payload-size 256 -d 30 \
  --i-have-authorization

python3 wsdos.py payload ws://192.168.1.42:8080/ -w 5 --payload-size 8388608 --frames 50 \
  --i-have-authorization

python3 wsdos.py compression wss://device.lan/ws -k -w 4 --payload-size 10485760 -d 30 \
  --i-have-authorization
```

## Known CVEs covered by the `cves` check

Every entry has been verified against NVD. Earlier versions of this README
listed 10 CVEs; on verification, six of them either pointed to unrelated
products (Apache UIMA, Traefik, Taiwanese-language packages) or were real
CVEs but not WebSocket-specific. v3.1.0 trimmed the registry to the four
that are both real and WebSocket-specific:

| CVE | Stack | Severity |
|---|---|---|
| [CVE-2020-7662](https://nvd.nist.gov/vuln/detail/CVE-2020-7662) | `websocket-extensions` (Node.js) < 0.1.4 , ReDoS via `Sec-WebSocket-Extensions` header | HIGH (7.5) |
| [CVE-2021-32640](https://nvd.nist.gov/vuln/detail/CVE-2021-32640) | `ws` (npm) 5.0.0-6.2.1, 7.0.0-7.4.5 , ReDoS via `Sec-WebSocket-Protocol` header | MEDIUM (5.3) |
| [CVE-2024-37890](https://nvd.nist.gov/vuln/detail/CVE-2024-37890) | `ws` (npm) < 8.17.1 , DoS via requests exceeding `server.maxHeadersCount` | HIGH (7.5) |
| [CVE-2023-32695](https://nvd.nist.gov/vuln/detail/CVE-2023-32695) | `socket.io-parser` 3.4.0-3.4.2, 4.0.4-4.2.2 , DoS via crafted packet (uncaught exception) | HIGH (7.5) |

The check is a *fingerprint* match against `Server`/`X-Powered-By` response
headers, not active exploitation. A match is a hint, not proof , always
verify the installed version against the affected range before reporting.
PRs adding more verified WebSocket CVEs (with NVD link + primary advisory)
are welcome.

## Where the WebSocket lives, by device class

| Device class | Typical paths / ports | What to test |
|---|---|---|
| Smart plugs / relays (Shelly, Tasmota) | `/rpc`, `/ws` on :80 | `auth`, `cswsh` (often no auth at all on LAN) |
| Home Assistant | `/api/websocket` on :8123 | `auth` (token bypass), `cves` |
| IP cameras (Hikvision, Dahua) | `/RPC2_Loginws` on :80, `/` on :7681 | `cswsh`, `frames`, `cves` (firmware-specific) |
| ROS rosbridge | `/` on :9090 | `auth` (default = NONE), `frames`, see [iotsrg/awesome-ros-security](https://github.com/iotsrg/awesome-ros-security) |
| Foxglove bridge | `/` on :8765 | `auth`, `compression` |
| OctoPrint | `/sockjs/websocket` on :5000 | `cswsh`, `auth` |
| OBD-WiFi dongles | `/` on :35000 | `tls.plaintext` (always plain), `auth` (always none) |
| Tesla mobile firehose | `wss://owner-api.teslamotors.com/streaming/` | `tls`, `auth` (OAuth bearer) |
| Niagara N4 / BMS | `/baja/ws` on :1911 | `tls` (self-signed default), `cves`, `auth` |
| OPC UA over WS | `/` on :4843 wss | `tls`, `frames` |
| Modbus-WS gateways | `/modbus` on :8000 | `auth` (often none), `frames` (binary PDU fuzzing) |

## Architecture

```
wsdos.py                # CLI dispatcher
wsdoscore/
├── __init__.py
├── common.py           # Metrics, URL helpers, Finding dataclass
├── recon.py            # probe command
├── stress.py           # 5 attack modes
├── presets.py          # 8 vendor presets (each with source citation)
├── report.py           # JSON / pretty / Markdown emitters
└── vuln/
    ├── __init__.py     # CHECK_REGISTRY
    ├── cswsh.py        # Cross-Site WebSocket Hijacking
    ├── auth.py         # no-auth, JWT alg:none, query-string tokens
    ├── compression.py  # permessage-deflate amplification
    ├── frames.py       # raw-socket RFC 6455 fuzzing
    ├── smuggling.py    # HTTP/WS upgrade-boundary smuggling
    ├── tls.py          # plaintext, weak versions, weak ciphers, untrusted certs
    └── cves.py         # known-CVE fingerprint registry
```

Adding a new vuln check:
1. Create `wsdoscore/vuln/<name>.py` exporting `async def check(args) -> list[Finding]`
2. Register in `wsdoscore/vuln/__init__.py`
3. `wsdos vuln <name>` and `wsdos scan` pick it up automatically.

## What to look for during a live engagement

| Symptom | Likely root cause |
|---|---|
| Connections cap out at ~1020 | `ulimit -n` on a per-process fd limit |
| Server stops accepting after N seconds | Per-IP connection cap or accept-queue exhaustion |
| CPU pegged but accept still works | Single-threaded WebSocket handler |
| `handshake_rejects` jumps to non-zero | Server-side rate-limiting kicked in (good!) |
| Web UI unreachable during flood | No separation between control-plane and data-plane |
| Device reboots / freezes | Watchdog or OOM kill |
| `cswsh` reports HIGH | Browser-based attack chain becomes available |
| `auth.no-auth-accepted` HIGH | Anyone on the LAN can drive the device |
| `frames.rfc6455-compliance` HIGH | Custom parser; consider deeper fuzzing |
| `tls.plaintext` HIGH | All traffic visible to on-path attackers |

## Reporting bugs you find on real devices

Please follow coordinated disclosure with the vendor.

- For robots / ROS: also consider submitting to the [Robot Vulnerability Database](https://github.com/aliasrobotics/RVD).
- For ICS / OT: ICS-CERT / CISA via [cisa.gov/report](https://www.cisa.gov/forms/report).
- For consumer IoT: vendor PSIRT, then [CVE Numbering Authority](https://www.cve.org/) if no response within 90 days.

## Demo (legacy)

The original 2019 PoC video is still in the repo:

![](wsdos.jpg)

Original demo: <https://www.youtube.com/watch?v=GhhDNFVsQBc>

## License

MIT, see [LICENSE](LICENSE).

## Author

[@V33RU](https://github.com/V33RU) / [IOTSRG](https://iotsrg.org/)

See also:
- [iotsrg/awesome-ros-security](https://github.com/iotsrg/awesome-ros-security) — full robotics/ROS security curation
- [V33RU/awesome-connected-things-sec](https://github.com/V33RU/awesome-connected-things-sec) — IoT / embedded / automotive / ICS resources

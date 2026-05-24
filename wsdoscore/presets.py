"""Vendor / category presets: known endpoints, default paths, subprotocols.

Each preset has:
  - name, category, description
  - default_port, default_path, scheme (ws/wss)
  - common headers / subprotocols
  - notes (where to look for the WS endpoint on the device)

This is a research aid, not an exploit list. The endpoints below are
documented in vendor docs, FCC filings, firmware dumps, or public CVE
reports.
"""

from __future__ import annotations


PRESETS = {
    # ---------------- IoT (smart home / consumer) ----------------
    "shelly": {
        "category": "iot-smart-home",
        "description": "Shelly Gen2/Gen3 WiFi relays, plugs, dimmers (Allterco).",
        "default_port": 80,
        "default_path": "/rpc",
        "scheme": "ws",
        "subprotocols": ["jsonrpc"],
        "notes": "RPC over WS. Try ws://<ip>/rpc and send {\"id\":1,\"method\":\"Shelly.GetDeviceInfo\"}",
    },
    "tasmota": {
        "category": "iot-smart-home",
        "description": "Tasmota firmware (ESP8266/ESP32) — Web UI uses WS.",
        "default_port": 80,
        "default_path": "/ws",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Tasmota's web console pushes log frames over /ws.",
    },
    "esphome": {
        "category": "iot-smart-home",
        "description": "ESPHome device dashboards (Home Assistant ecosystem).",
        "default_port": 6052,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "ESPHome dashboard runs the API on TCP/6053 and a separate WS log on 6052.",
    },
    "home-assistant": {
        "category": "iot-smart-home",
        "description": "Home Assistant Core WebSocket API.",
        "default_port": 8123,
        "default_path": "/api/websocket",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Auth required after open. Send {\"type\": \"auth\", \"access_token\": \"...\"}",
    },
    "tuya-local": {
        "category": "iot-smart-home",
        "description": "Tuya cloud bridge / local-tuya devices.",
        "default_port": 6668,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Tuya uses MQTT primarily, but the cloud bridge exposes WS.",
    },
    # ---------------- IP cameras / NVR ----------------
    "hikvision-isapi": {
        "category": "iot-camera",
        "description": "Hikvision ISAPI live preview over WS (RTSP-over-WS bridge).",
        "default_port": 7681,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "WSS variant on 7682. Many older firmwares lack Origin checks.",
    },
    "dahua-snap": {
        "category": "iot-camera",
        "description": "Dahua web client uses WS for live video.",
        "default_port": 80,
        "default_path": "/RPC2_Loginws",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "RPC2 over WS, JSON envelope. Auth via session cookie.",
    },
    # ---------------- Robotics / industrial ----------------
    "ros1-rosbridge": {
        "category": "robotics",
        "description": "ROS 1 rosbridge_suite (JSON over WS).",
        "default_port": 9090,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Defaults to NO auth. Send {\"op\":\"subscribe\",\"topic\":\"/cmd_vel\"} after connect.",
    },
    "ros2-rosbridge": {
        "category": "robotics",
        "description": "ROS 2 rosbridge_suite (same protocol as ROS1).",
        "default_port": 9090,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "See https://github.com/RobotWebTools/rosbridge_suite. Often exposed without auth.",
    },
    "foxglove-bridge": {
        "category": "robotics",
        "description": "Foxglove WebSocket bridge (ROS, Pose, etc.)",
        "default_port": 8765,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": ["foxglove.websocket.v1"],
        "notes": "Increasingly common alternative to rosbridge.",
    },
    "octoprint": {
        "category": "iot-3dprinter",
        "description": "OctoPrint server (3D printer control plane).",
        "default_port": 5000,
        "default_path": "/sockjs/websocket",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "SockJS layer; auth via API key in Cookie.",
    },
    # ---------------- Automotive / connected vehicle ----------------
    "obd-ws-bridge": {
        "category": "automotive",
        "description": "OBD-II WiFi dongles that bridge to WS (common cheap dongles).",
        "default_port": 35000,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Many dongles expose ELM327 AT commands over a raw WS endpoint.",
    },
    "tesla-firehose": {
        "category": "automotive",
        "description": "Tesla mobile app WS firehose (telemetry stream).",
        "default_port": 443,
        "default_path": "/streaming/",
        "scheme": "wss",
        "subprotocols": [],
        "notes": "Mobile app endpoint. Auth via OAuth bearer.",
    },
    "open-vehicle-monitoring": {
        "category": "automotive",
        "description": "Open Vehicle Monitoring System (OVMS) live data feed.",
        "default_port": 6868,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Used for Renault, Twizy, Roadster, Kia/Hyundai EVs.",
    },
    # ---------------- Industrial / building ----------------
    "niagara-n4-bajaws": {
        "category": "industrial-bms",
        "description": "Tridium Niagara N4 BAJA WS (building management).",
        "default_port": 1911,
        "default_path": "/baja/ws",
        "scheme": "wss",
        "subprotocols": [],
        "notes": "Niagara N4 modules expose WS for live point updates. Self-signed certs common.",
    },
    "bacnet-ws-gateway": {
        "category": "industrial-bms",
        "description": "BACnet-over-WS gateways (Siemens, Honeywell).",
        "default_port": 47808,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Modern building gateways tunnel BACnet/IP over WS.",
    },
    "modbus-ws-gateway": {
        "category": "industrial-scada",
        "description": "Modbus-TCP-to-WebSocket bridges (eWON, Moxa, generic).",
        "default_port": 8000,
        "default_path": "/modbus",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Test by sending hex-encoded Modbus PDUs as binary frames.",
    },
    "opcua-ws": {
        "category": "industrial-scada",
        "description": "OPC UA over WebSocket (opc.wss://) — IEC 62541-6.",
        "default_port": 4843,
        "default_path": "/",
        "scheme": "wss",
        "subprotocols": ["opcua+uacp"],
        "notes": "OPC UA Part 6 binary mapping over WSS.",
    },
}


def get(name: str) -> dict:
    if name not in PRESETS:
        raise SystemExit(f"unknown preset {name!r}. See: wsdos preset list")
    return PRESETS[name]


def list_categories() -> dict:
    """Return presets grouped by category."""
    out: dict = {}
    for name, p in PRESETS.items():
        out.setdefault(p["category"], []).append((name, p["description"]))
    return out

"""Vendor / category presets: WebSocket endpoint defaults.

Every preset below was verified against the vendor's official documentation
at the time of writing. The link in `source` is the page where the
default port/path is stated. If you find a vendor's defaults have
changed, please open a PR.

We deliberately keep this list small and accurate. Fabricated guesses
do not help researchers; they waste their time and erode trust.

Adding a new preset?
  - Cite a primary source (vendor docs, RFC, open-source project README).
  - Verify the port/path is the *default* — not just one of many.
  - Note any non-default behaviour (auth required, subprotocol, etc.).
"""

from __future__ import annotations


PRESETS = {
    # ---------------- ROS / Robotics ----------------
    "ros1-rosbridge": {
        "category": "robotics",
        "description": "ROS 1 rosbridge_suite (JSON over WebSocket).",
        "default_port": 9090,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": ("rosbridge has no authentication by default. "
                  "Send `{\"op\":\"subscribe\",\"topic\":\"/cmd_vel\"}` after "
                  "connect to test."),
        "source": "https://github.com/RobotWebTools/rosbridge_suite",
    },
    "ros2-rosbridge": {
        "category": "robotics",
        "description": "ROS 2 rosbridge_suite (same protocol as ROS1).",
        "default_port": 9090,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Defaults to NO auth. Same wire protocol as ROS 1 rosbridge.",
        "source": "https://github.com/RobotWebTools/rosbridge_suite",
    },
    "foxglove-bridge": {
        "category": "robotics",
        "description": "Foxglove WebSocket bridge (alternative to rosbridge).",
        "default_port": 8765,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": ["foxglove.websocket.v1"],
        "notes": ("Auth optional. See foxglove/ws-protocol for the binary "
                  "subprotocol details."),
        "source": "https://github.com/foxglove/ws-protocol",
    },

    # ---------------- Smart home / IoT ----------------
    "home-assistant": {
        "category": "iot-smart-home",
        "description": "Home Assistant Core WebSocket API.",
        "default_port": 8123,
        "default_path": "/api/websocket",
        "scheme": "ws",
        "subprotocols": [],
        "notes": ("Auth required after open. Send "
                  "`{\"type\":\"auth\",\"access_token\":\"<long-lived token>\"}` "
                  "as the first message."),
        "source": "https://developers.home-assistant.io/docs/api/websocket/",
    },
    "esphome-dashboard": {
        "category": "iot-smart-home",
        "description": "ESPHome web dashboard (Home Assistant ecosystem).",
        "default_port": 6052,
        "default_path": "/",
        "scheme": "ws",
        "subprotocols": [],
        "notes": ("Dashboard runs on 6052 by default. The ESPHome native "
                  "API is on TCP/6053 and uses a different protocol."),
        "source": "https://esphome.io/guides/getting_started_hassio",
    },
    "shelly-gen2-rpc": {
        "category": "iot-smart-home",
        "description": "Shelly Gen2/Gen3 devices (Allterco) JSON-RPC over WS.",
        "default_port": 80,
        "default_path": "/rpc",
        "scheme": "ws",
        "subprotocols": [],
        "notes": ("Send `{\"id\":1,\"method\":\"Shelly.GetDeviceInfo\"}` after "
                  "connect. Auth optional unless explicitly enabled."),
        "source": "https://shelly-api-docs.shelly.cloud/gen2/General/RPCProtocol",
    },
    "tasmota-console": {
        "category": "iot-smart-home",
        "description": "Tasmota firmware web console (ESP8266/ESP32).",
        "default_port": 80,
        "default_path": "/ws",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "Web UI streams log lines over /ws. Same HTTP auth as the UI.",
        "source": "https://tasmota.github.io/docs/Commands/",
    },

    # ---------------- Maker / 3D print ----------------
    "octoprint": {
        "category": "iot-3dprinter",
        "description": "OctoPrint server (3D printer control plane).",
        "default_port": 5000,
        "default_path": "/sockjs/websocket",
        "scheme": "ws",
        "subprotocols": [],
        "notes": "SockJS layer. Auth via API key in Cookie or X-Api-Key header.",
        "source": "https://docs.octoprint.org/en/master/api/push.html",
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

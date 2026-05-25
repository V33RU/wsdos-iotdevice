"""Vulnerability-check modules. Each exports an async check(args) -> list[Finding].

The order of CHECK_REGISTRY matters: cheap, single-connection checks run
first so an aggressive later check that trips the device's rate-limiter
cannot starve the earlier ones. Order is cheap-first / least-aggressive
first:

  1. tls         : 1 TLS handshake, no WS frames sent
  2. cves        : 1 WS handshake, capture server headers, no frames
  3. cswsh       : ~6 handshakes (one per forged Origin)
  4. auth        : 1-3 handshakes
  5. compression : 1 handshake + 4 frames
  6. smuggling   : 4 raw socket handshakes
  7. frames      : 5 raw socket handshakes + malformed frames (most aggressive)
"""

from . import tls, cves, cswsh, auth, compression, smuggling, frames

CHECK_REGISTRY = {
    "tls": tls,
    "cves": cves,
    "cswsh": cswsh,
    "auth": auth,
    "compression": compression,
    "smuggling": smuggling,
    "frames": frames,
}

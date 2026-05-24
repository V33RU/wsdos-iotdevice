"""Vulnerability-check modules. Each exports an async check(args) -> list[Finding]."""

from . import cswsh, auth, compression, frames, smuggling, tls, cves

CHECK_REGISTRY = {
    "cswsh": cswsh,
    "auth": auth,
    "compression": compression,
    "frames": frames,
    "smuggling": smuggling,
    "tls": tls,
    "cves": cves,
}

"""Load Scapy once, and only with the protocol layers the monitor reads.

Scapy imports every protocol it knows by default, which takes over a second and puts a lot of
parsing code in front of hostile packets. The monitor only needs Ethernet and VLAN framing, IPv4,
IPv6 (with its extension headers), TCP, UDP, ICMP and SCTP, so the upper-layer payloads (DNS, HTTP,
TLS ...) stay raw bytes. Nothing in the monitor reads them.
"""

from functools import lru_cache
from types import ModuleType

_LAYERS = ["l2", "inet", "inet6", "sctp"]


class CaptureLibraryMissingError(Exception):
    """Scapy is not installed in this environment."""


@lru_cache(maxsize=1)
def load_scapy() -> ModuleType:
    """The ``scapy.all`` module, imported on first use. Raises if Scapy is not installed."""
    try:
        from scapy.config import conf

        conf.load_layers = list(_LAYERS)
        import scapy.all as scapy_all
    except ImportError as exc:
        raise CaptureLibraryMissingError("Scapy is not installed.") from exc
    return scapy_all

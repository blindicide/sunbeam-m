"""
Protocol masquerading layer - makes VPN traffic look like other protocols.
"""

from sunbeam_m.masquerade.base import MasqueradeProtocol, ProtocolState
from sunbeam_m.masquerade.soup import ProtocolSoup

__all__ = [
    "MasqueradeProtocol",
    "ProtocolState",
    "ProtocolSoup",
]

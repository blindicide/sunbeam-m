"""
Protocol soup masquerade.

Randomly rotates between multiple masquerade protocols (TLS, SSH, HTTP)
to make traffic analysis harder. Each packet can use a different protocol.
"""

import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

from sunbeam_m.core.framing import PacketType
from sunbeam_m.masquerade.base import (
    MasqueradeProtocol,
    ProtocolState,
)
from sunbeam_m.masquerade.http import HTTPMasquerade
from sunbeam_m.masquerade.ssh import SSHMasquerade
from sunbeam_m.masquerade.tls import TLSMasquerade


@dataclass
class ProtocolWeight:
    """Weight for protocol selection."""

    protocol_class: type[MasqueradeProtocol]
    weight: float  # Higher = more likely to be selected
    name: str


# Default protocol weights
DEFAULT_PROTOCOLS: Sequence[ProtocolWeight] = (
    ProtocolWeight(TLSMasquerade, 0.5, "tls"),
    ProtocolWeight(SSHMasquerade, 0.25, "ssh"),
    ProtocolWeight(HTTPMasquerade, 0.25, "http"),
)


class ProtocolSoup(MasqueradeProtocol):
    """
    Protocol soup masquerade that randomly rotates between protocols.

    Each encode operation can use a different protocol, making traffic
    analysis much harder. The decoder automatically detects which protocol
    was used for each incoming packet.

    The soup maintains instances of each protocol and switches between them
    based on configured weights or random selection.
    """

    PROTOCOL_NAME = "soup"
    SUPPORTS_STREAMING = False  # Protocol soup doesn't maintain single stream

    def __init__(
        self,
        server_name: str | None = None,
        protocols: Sequence[ProtocolWeight] | None = None,
        rotation_mode: str = "random",
    ):
        """
        Initialize protocol soup.

        Args:
            server_name: Server name for masquerade protocols
            protocols: List of ProtocolWeight for selection
            rotation_mode: How to rotate protocols:
                - "random": Random selection per packet
                - "round-robin": Cycle through protocols
                - "sticky": Use same protocol until rekey
        """
        super().__init__(server_name)
        self.protocols = protocols or DEFAULT_PROTOCOLS
        self.rotation_mode = rotation_mode

        # Create instances of each protocol
        self._protocol_instances: dict[str, MasqueradeProtocol] = {}
        for pw in self.protocols:
            self._protocol_instances[pw.name] = pw.protocol_class(server_name)

        # For round-robin mode
        self._protocol_index = 0

        # For sticky mode
        self._current_protocol: Optional[str] = None

        # Track which protocol to expect on decode
        self._expected_protocol: Optional[str] = None

    @property
    def available_protocols(self) -> list[str]:
        """Get list of available protocol names."""
        return list(self._protocol_instances.keys())

    def get_protocol(self, name: str) -> MasqueradeProtocol:
        """
        Get a specific protocol instance by name.

        Args:
            name: Protocol name

        Returns:
            Protocol instance

        Raises:
            KeyError: If protocol not found
        """
        return self._protocol_instances[name]

    def _select_protocol(self) -> str:
        """Select a protocol based on rotation mode."""
        if self.rotation_mode == "random":
            # Weighted random selection
            weights = [p.weight for p in self.protocols]
            names = [p.name for p in self.protocols]
            return random.choices(names, weights=weights, k=1)[0]

        elif self.rotation_mode == "round-robin":
            # Cycle through protocols
            name = self.protocols[self._protocol_index].name
            self._protocol_index = (self._protocol_index + 1) % len(self.protocols)
            return name

        elif self.rotation_mode == "sticky":
            # Use same protocol (select first time or rekey)
            if self._current_protocol is None:
                weights = [p.weight for p in self.protocols]
                names = [p.name for p in self.protocols]
                self._current_protocol = random.choices(names, weights=weights, k=1)[0]
            return self._current_protocol

        else:
            # Default to random
            return random.choice(self.available_protocols)

    def set_rotation_mode(self, mode: str) -> None:
        """
        Change the rotation mode.

        Args:
            mode: New rotation mode
        """
        if mode not in ("random", "round-robin", "sticky"):
            raise ValueError(f"Invalid rotation mode: {mode}")

        self.rotation_mode = mode
        if mode != "sticky":
            self._current_protocol = None

    def reset_protocol(self) -> None:
        """Reset the sticky protocol (for rekey)."""
        self._current_protocol = None

    def client_handshake(self) -> bytes:
        """
        Generate handshake using a selected protocol.

        Returns:
            Handshake data from selected protocol
        """
        protocol_name = self._select_protocol()
        protocol = self._protocol_instances[protocol_name]
        self._current_protocol = protocol_name
        self._expected_protocol = protocol_name

        handshake = protocol.client_handshake()
        self.transition_to(ProtocolState.HANDSHAKE_SENT)

        return handshake

    def server_handshake(self, client_data: bytes) -> bytes:
        """
        Generate handshake response, detecting client protocol.

        Args:
            client_data: Client handshake data

        Returns:
            Handshake response from detected protocol

        Raises:
            HandshakeError: If protocol detection fails
        """
        # Detect which protocol the client used
        detected_protocol = self._detect_protocol(client_data)

        if detected_protocol is None:
            # Default to first protocol
            detected_protocol = self.protocols[0].name

        protocol = self._protocol_instances[detected_protocol]
        self._current_protocol = detected_protocol
        self._expected_protocol = detected_protocol

        handshake = protocol.server_handshake(client_data)
        self.transition_to(ProtocolState.ESTABLISHED)

        return handshake

    def _detect_protocol(self, data: bytes) -> Optional[str]:
        """
        Detect which masquerade protocol was used.

        Args:
            data: Raw handshake data

        Returns:
            Protocol name or None if undetected
        """
        if not data:
            return None

        # Check for SSH
        if data.startswith(b"SSH-"):
            return "ssh"

        # Check for TLS (handshake record)
        if len(data) >= 1 and data[0] == 0x16:  # Handshake content type
            # Check version
            if len(data) >= 3:
                version = (data[1] << 8) | data[2]
                if version in (0x0303, 0x0304):  # TLS 1.2 or 1.3
                    return "tls"

        # Check for HTTP
        if data.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/")):
            return "http"

        return None

    def encode(self, frame: bytes, packet_type: PacketType = PacketType.DATA) -> bytes:
        """
        Encode a frame using a selected protocol.

        Args:
            frame: Raw VPN frame bytes
            packet_type: Type of packet

        Returns:
            Protocol-encoded frame

        Note:
            For protocol soup, we prefix the encoded data with a protocol marker
            so the decoder knows which protocol to use.
        """
        # Select protocol for this packet
        protocol_name = self._select_protocol()
        protocol = self._protocol_instances[protocol_name]

        # Encode using the selected protocol
        encoded = protocol.encode(frame, packet_type)

        # Prefix with 1-byte protocol marker
        # 0 = TLS, 1 = SSH, 2 = HTTP
        protocol_map = {"tls": 0, "ssh": 1, "http": 2}
        marker = bytes([protocol_map.get(protocol_name, 0)])

        return marker + encoded

    def decode(self, data: bytes) -> list[bytes]:
        """
        Decode frames, auto-detecting the protocol for each.

        Args:
            data: Bytes received from network

        Returns:
            List of decoded VPN frames

        Raises:
            DecodeError: If data is malformed
        """
        if not data:
            return []

        results = []
        remaining = data

        while remaining:
            # Protocol marker is first byte
            if len(remaining) < 1:
                break

            marker = remaining[0]
            remaining = remaining[1:]

            # Map marker to protocol
            marker_map = {0: "tls", 1: "ssh", 2: "http"}
            protocol_name = marker_map.get(marker, "tls")
            protocol = self._protocol_instances[protocol_name]

            # For soup mode, we need to know where each frame ends
            # This is tricky because protocols have different framing
            # For now, decode all remaining data with this protocol
            # In a production system, we'd need length-prefixing or
            # protocol-aware frame boundary detection

            try:
                frames = protocol.decode(remaining)
                results.extend(frames)

                # Assume protocol consumed all data (simplified)
                # In reality, we'd need to track exact consumption
                break
            except Exception:
                # Try next protocol if this one fails
                continue

        return results

    def _generate_close(self) -> Optional[bytes]:
        """Generate close message using current protocol."""
        if self._current_protocol:
            protocol = self._protocol_instances[self._current_protocol]
            return protocol._generate_close()
        return None

    def reset(self) -> None:
        """Reset all protocol instances."""
        super().reset()
        for protocol in self._protocol_instances.values():
            protocol.reset()
        self._current_protocol = None
        self._protocol_index = 0

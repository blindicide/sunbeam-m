"""
Base masquerade protocol interface.

All masquerade protocols (TLS, SSH, HTTP, etc.) inherit from MasqueradeProtocol.
This defines the contract for encoding/decoding VPN frames as other protocols.
"""

import time
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Optional

from sunbeam_m.core.framing import PacketType


class ProtocolState(IntEnum):
    """State machine for masquerade protocol connection."""

    DISCONNECTED = 0
    HANDSHAKE_INIT = 1
    HANDSHAKE_SENT = 2
    HANDSHAKE_RECV = 3
    ESTABLISHED = 4
    CLOSING = 5
    CLOSED = 6


class MasqueradeProtocol(ABC):
    """
    Abstract base class for protocol masquerading.

    Each masquerade protocol must implement:
    - handshake(): Generate initial handshake data
    - encode(): Wrap VPN frame in masquerade protocol
    - decode(): Extract VPN frame from masquerade protocol
    - can_transition(): Validate state transitions

    The goal is to make VPN traffic indistinguishable from the target protocol.
    """

    # Protocol identification (for internal use, not sent on wire)
    PROTOCOL_NAME: str = "base"

    # Does this protocol support bidirectional streaming?
    SUPPORTS_STREAMING: bool = True

    # Default server name for SNI/Host headers
    DEFAULT_SERVER_NAME: str = "www.example.com"

    def __init__(self, server_name: str | None = None):
        """
        Initialize the masquerade protocol.

        Args:
            server_name: Server name for SNI/Host headers
        """
        self.server_name = server_name or self.DEFAULT_SERVER_NAME
        self.state = ProtocolState.DISCONNECTED
        self._handshake_sent = False
        self._handshake_received = False
        self._last_activity = time.time()

    @property
    def is_established(self) -> bool:
        """Check if the protocol handshake is complete."""
        return self.state == ProtocolState.ESTABLISHED

    @property
    def can_send(self) -> bool:
        """Check if we can send data in current state."""
        return self.state in (
            ProtocolState.HANDSHAKE_SENT,
            ProtocolState.ESTABLISHED,
        )

    @property
    def can_recv(self) -> bool:
        """Check if we can receive data in current state."""
        return self.state in (
            ProtocolState.HANDSHAKE_RECV,
            ProtocolState.ESTABLISHED,
        )

    @abstractmethod
    def client_handshake(self) -> bytes:
        """
        Generate client-side handshake data.

        Returns:
            Bytes to send to initiate the masquerade protocol

        Raises:
            RuntimeError: If handshake already sent or in invalid state
        """

    @abstractmethod
    def server_handshake(self, client_data: bytes) -> bytes:
        """
        Generate server-side handshake response.

        Args:
            client_data: Client handshake data received

        Returns:
            Bytes to send as handshake response

        Raises:
            RuntimeError: If in invalid state
            ValueError: If client data is invalid
        """

    @abstractmethod
    def encode(self, frame: bytes, packet_type: PacketType = PacketType.DATA) -> bytes:
        """
        Encode a VPN frame as the masquerade protocol.

        Args:
            frame: Raw VPN frame bytes (already encrypted/framed)
            packet_type: Type of packet (may affect encoding)

        Returns:
            Protocol-encoded bytes ready to send
        """

    @abstractmethod
    def decode(self, data: bytes) -> list[bytes]:
        """
        Decode received protocol data into VPN frames.

        Args:
            data: Bytes received from network

        Returns:
            List of decoded VPN frames

        Raises:
            ValueError: If data is malformed or invalid
        """

    def transition_to(self, new_state: ProtocolState) -> None:
        """
        Transition to a new state with validation.

        Args:
            new_state: Target state

        Raises:
            ValueError: If transition is invalid
        """
        if not self._can_transition(new_state):
            raise ValueError(
                f"Invalid state transition: {self.state.name} -> {new_state.name}"
            )

        self.state = new_state
        self._last_activity = time.time()

    def _can_transition(self, new_state: ProtocolState) -> bool:
        """
        Validate if a state transition is allowed.

        Args:
            new_state: Target state

        Returns:
            True if transition is valid
        """
        # Define valid transitions
        valid_transitions = {
            ProtocolState.DISCONNECTED: [
                ProtocolState.HANDSHAKE_INIT,
                ProtocolState.ESTABLISHED,  # For single-step masquerade handshakes
            ],
            ProtocolState.HANDSHAKE_INIT: [
                ProtocolState.HANDSHAKE_SENT,
                ProtocolState.HANDSHAKE_RECV,
                ProtocolState.ESTABLISHED,  # For protocols without handshake
            ],
            ProtocolState.HANDSHAKE_SENT: [
                ProtocolState.HANDSHAKE_RECV,
                ProtocolState.ESTABLISHED,
            ],
            ProtocolState.HANDSHAKE_RECV: [
                ProtocolState.ESTABLISHED,
            ],
            ProtocolState.ESTABLISHED: [
                ProtocolState.CLOSING,
            ],
            ProtocolState.CLOSING: [
                ProtocolState.CLOSED,
            ],
            ProtocolState.CLOSED: [
                ProtocolState.DISCONNECTED,
            ],
        }

        return new_state in valid_transitions.get(self.state, [])

    def reset(self) -> None:
        """Reset the protocol state machine."""
        self.state = ProtocolState.DISCONNECTED
        self._handshake_sent = False
        self._handshake_received = False
        self._last_activity = time.time()

    def close(self) -> Optional[bytes]:
        """
        Generate protocol-specific close message.

        Returns:
            Bytes to send for graceful close, or None
        """
        if self.state == ProtocolState.ESTABLISHED:
            self.transition_to(ProtocolState.CLOSING)
            return self._generate_close()
        return None

    @abstractmethod
    def _generate_close(self) -> Optional[bytes]:
        """
        Generate protocol-specific close message.

        Returns:
            Bytes to send, or None if no close message needed
        """

    def idle_time(self) -> float:
        """
        Get time since last activity.

        Returns:
            Seconds since last packet sent or received
        """
        return time.time() - self._last_activity

    def update_activity(self) -> None:
        """Update the last activity timestamp."""
        self._last_activity = time.time()


class StreamBuffer:
    """
    Buffer for streaming protocols that may frame data arbitrarily.

    Some protocols (TLS, SSH) have their own framing that may split
    or combine our VPN frames. This buffer handles reassembly.
    """

    def __init__(self):
        """Initialize an empty stream buffer."""
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        """Add data to the buffer."""
        self._buffer.extend(data)

    def consume(self, n: int) -> bytes:
        """
        Consume n bytes from the buffer.

        Args:
            n: Number of bytes to consume

        Returns:
            Consumed bytes

        Raises:
            ValueError: If not enough bytes available
        """
        if n > len(self._buffer):
            raise ValueError(f"Not enough bytes: need {n}, have {len(self._buffer)}")

        result = bytes(self._buffer[:n])
        del self._buffer[:n]
        return result

    def peek(self, n: int) -> bytes:
        """
        Peek at n bytes without consuming.

        Args:
            n: Number of bytes to peek

        Returns:
            Bytes without consuming them

        Raises:
            ValueError: If not enough bytes available
        """
        if n > len(self._buffer):
            raise ValueError(f"Not enough bytes: need {n}, have {len(self._buffer)}")

        return bytes(self._buffer[:n])

    def available(self) -> int:
        """Get number of bytes available in buffer."""
        return len(self._buffer)

    def clear(self) -> None:
        """Clear the buffer."""
        self._buffer.clear()

    def drain(self) -> bytes:
        """Drain all bytes from the buffer."""
        result = bytes(self._buffer)
        self._buffer.clear()
        return result


class ProtocolException(Exception):
    """Base exception for masquerade protocol errors."""

    pass


class HandshakeError(ProtocolException):
    """Raised when handshake fails."""

    pass


class DecodeError(ProtocolException):
    """Raised when decoding fails."""

    pass

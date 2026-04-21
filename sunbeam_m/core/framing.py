"""
Packet framing for Sunbeam-M VPN.

Defines the binary wire format for VPN packets:
- Length prefix (2 bytes)
- Nonce (12 bytes, from crypto layer)
- Ciphertext + tag (variable)
- Padding to obscure payload size

Also supports:
- Variable packet sizes to mimic real traffic
- Random padding for traffic analysis resistance
- Packet type flags (control, data, ping)
"""

import os
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from sunbeam_m.core.crypto import CipherSuite, NONCE_SIZE, TAG_SIZE

# Constants
MIN_FRAME_SIZE = 64  # Minimum frame size in bytes
MAX_FRAME_SIZE = 1500  # Maximum frame size (MTU-safe)
MAX_PADDING = 256  # Maximum padding bytes
LENGTH_FIELD_SIZE = 2
FLAG_FIELD_SIZE = 1


class PacketType(IntEnum):
    """Packet type flags."""

    DATA = 0x00  # Regular VPN data
    CONTROL = 0x01  # Control message
    PING = 0x02  # Keepalive ping
    PONG = 0x03  # Keepalive pong
    HANDSHAKE = 0x04  # Key exchange
    REKEY = 0x05  # Rekey request
    CLOSE = 0x06  # Connection close


@dataclass
class VPNFrame:
    """
    A VPN frame containing encrypted packet data.

    Wire format:
    ```
    +-----+-----+--------+----------------+----------+
    | Len | Flags | Nonce | Ciphertext+Tag | Padding |
    | 2B  |  1B   |  12B   |    Variable    | Variable |
    +-----+-------+--------+----------------+----------+
    ```

    The length field includes everything after the length field itself.
    """

    packet_type: PacketType
    nonce: bytes
    ciphertext: bytes
    padding: bytes = b""

    @property
    def total_size(self) -> int:
        """Total size of this frame including length prefix."""
        payload_size = (
            FLAG_FIELD_SIZE
            + NONCE_SIZE
            + len(self.ciphertext)
            + len(self.padding)
        )
        return LENGTH_FIELD_SIZE + payload_size


class FrameEncoder:
    """
    Encodes VPN packets into frames for transmission.

    Features:
    - Length-prefixed binary format
    - Random padding for size obfuscation
    - Variable sizing to mimic real traffic patterns
    """

    def __init__(
        self,
        cipher: CipherSuite,
        min_size: int = MIN_FRAME_SIZE,
        max_size: int = MAX_FRAME_SIZE,
    ):
        """
        Initialize the frame encoder.

        Args:
            cipher: CipherSuite for encryption
            min_size: Minimum frame size (for padding)
            max_size: Maximum frame size
        """
        self.cipher = cipher
        self.min_size = min_size
        self.max_size = max_size

    def encode(
        self,
        data: bytes,
        packet_type: PacketType = PacketType.DATA,
        pad_to_min: bool = True,
        random_padding: bool = True,
    ) -> bytes:
        """
        Encode a packet into a frame.

        Args:
            data: Plaintext data to encrypt and frame
            packet_type: Type of packet
            pad_to_min: Ensure minimum frame size with padding
            random_padding: Add random padding up to max_size

        Returns:
            Complete frame ready for transmission

        Raises:
            ValueError: If data is too large
        """
        if len(data) > self.max_size - FLAG_FIELD_SIZE - NONCE_SIZE - TAG_SIZE:
            raise ValueError(
                f"Data too large: {len(data)} bytes "
                f"(max {self.max_size - FLAG_FIELD_SIZE - NONCE_SIZE - TAG_SIZE})"
            )

        # Encrypt the data
        nonce, ciphertext = self.cipher.encrypt(data)

        # Calculate padding needed
        payload_size = FLAG_FIELD_SIZE + NONCE_SIZE + len(ciphertext)
        padding_len = 0

        if pad_to_min and payload_size < self.min_size:
            padding_len = self.min_size - payload_size
        elif random_padding:
            # Add random padding up to MAX_PADDING
            padding_len = os.urandom(1)[0] % MAX_PADDING

        # Ensure we don't exceed max_size
        if payload_size + padding_len > self.max_size:
            padding_len = max(0, self.max_size - payload_size)

        padding = os.urandom(padding_len) if padding_len > 0 else b""

        # Build frame: [length][flags][nonce][ciphertext][padding]
        flags = packet_type.value
        payload = struct.pack("!B", flags) + nonce + ciphertext + padding
        length = struct.pack("!H", len(payload))

        return length + payload

    def encode_control(self, message: str) -> bytes:
        """Encode a control message."""
        return self.encode(
            message.encode(),
            packet_type=PacketType.CONTROL,
        )

    def encode_ping(self, ping_id: int) -> bytes:
        """Encode a ping packet."""
        return self.encode(
            struct.pack("!Q", ping_id),
            packet_type=PacketType.PING,
        )

    def encode_pong(self, ping_id: int) -> bytes:
        """Encode a pong packet."""
        return self.encode(
            struct.pack("!Q", ping_id),
            packet_type=PacketType.PONG,
        )

    def encode_handshake(self, public_key: bytes) -> bytes:
        """Encode a handshake packet with public key."""
        return self.encode(
            public_key,
            packet_type=PacketType.HANDSHAKE,
        )


class FrameDecoder:
    """
    Decodes received frames back into VPN packets.

    Handles:
    - Length-prefixed binary format parsing
    - Validation of frame structure
    - Decryption of ciphertext
    """

    def __init__(self, cipher: CipherSuite):
        """
        Initialize the frame decoder.

        Args:
            cipher: CipherSuite for decryption
        """
        self.cipher = cipher
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        """
        Feed received data to the buffer.

        Args:
            data: Raw bytes received from network
        """
        self._buffer.extend(data)

    def decode(self) -> Optional[VPNFrame]:
        """
        Try to decode a complete frame from the buffer.

        Returns:
            VPNFrame if a complete frame is available, None otherwise

        Raises:
            ValueError: If frame format is invalid
        """
        # Need at least length field
        if len(self._buffer) < LENGTH_FIELD_SIZE:
            return None

        # Read length
        length = struct.unpack("!H", self._buffer[:LENGTH_FIELD_SIZE])[0]

        # Validate length
        if length < FLAG_FIELD_SIZE + NONCE_SIZE + TAG_SIZE:
            raise ValueError(f"Invalid frame length: {length}")
        if length > MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {length}")

        # Check if we have the full frame
        if len(self._buffer) < LENGTH_FIELD_SIZE + length:
            return None

        # Extract the payload
        start = LENGTH_FIELD_SIZE
        end = start + length
        payload = bytes(self._buffer[start:end])

        # Remove from buffer
        del self._buffer[: LENGTH_FIELD_SIZE + length]

        # Parse payload: [flags][nonce][ciphertext][padding]
        flags = payload[0]
        nonce = payload[1 : 1 + NONCE_SIZE]
        ciphertext = payload[1 + NONCE_SIZE :]

        # Remove padding (we don't know exact padding length,
        # but decryption will fail if it's wrong)
        # For now, include everything in ciphertext

        packet_type = PacketType(flags)

        return VPNFrame(
            packet_type=packet_type,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decode_frame(self, frame: VPNFrame) -> bytes:
        """
        Decrypt a VPNFrame's ciphertext.

        Args:
            frame: VPNFrame with encrypted data

        Returns:
            Decrypted plaintext

        Raises:
            InvalidTag: If authentication fails
        """
        return self.cipher.decrypt(frame.nonce, frame.ciphertext)

    def decode_all(self) -> list[bytes]:
        """
        Decode all available frames from the buffer.

        Returns:
            List of decrypted plaintext packets

        Raises:
            ValueError: If frame format is invalid
            InvalidTag: If authentication fails
        """
        results = []
        while True:
            frame = self.decode()
            if frame is None:
                break
            results.append(self.decode_frame(frame))
        return results

    def clear(self) -> None:
        """Clear the receive buffer."""
        self._buffer.clear()

    @property
    def buffer_size(self) -> int:
        """Current buffer size in bytes."""
        return len(self._buffer)


class FramingSession:
    """
    Complete framing session with encoder and decoder.

    Combines FrameEncoder and FrameDecoder for bidirectional communication.
    """

    def __init__(
        self,
        tx_cipher: CipherSuite,
        rx_cipher: CipherSuite,
        min_frame_size: int = MIN_FRAME_SIZE,
        max_frame_size: int = MAX_FRAME_SIZE,
    ):
        """
        Initialize a framing session.

        Args:
            tx_cipher: Cipher for transmitting
            rx_cipher: Cipher for receiving
            min_frame_size: Minimum frame size
            max_frame_size: Maximum frame size
        """
        self.encoder = FrameEncoder(tx_cipher, min_frame_size, max_frame_size)
        self.decoder = FrameDecoder(rx_cipher)

    def send(self, data: bytes, packet_type: PacketType = PacketType.DATA) -> bytes:
        """
        Encode data for transmission.

        Args:
            data: Data to send
            packet_type: Type of packet

        Returns:
            Encoded frame
        """
        return self.encoder.encode(data, packet_type)

    def recv(self, data: bytes) -> list[tuple[PacketType, bytes]]:
        """
        Feed received data and return decoded packets.

        Args:
            data: Raw bytes from network

        Returns:
            List of (packet_type, plaintext) tuples

        Raises:
            ValueError: If frame format is invalid
            InvalidTag: If authentication fails
        """
        self.decoder.feed(data)
        results = []

        while True:
            frame = self.decoder.decode()
            if frame is None:
                break

            plaintext = self.decoder.decode_frame(frame)
            results.append((frame.packet_type, plaintext))

        return results

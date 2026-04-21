"""
SSH protocol masquerade.

Generates realistic SSH-2.0 traffic to wrap VPN data.
Includes proper protocol version, key exchange init, and binary packets.
"""

import os
import struct
from typing import Optional

from sunbeam_m.core.framing import PacketType
from sunbeam_m.masquerade.base import (
    DecodeError,
    MasqueradeProtocol,
    ProtocolState,
    StreamBuffer,
)


# SSH protocol version strings
SSH_VERSION_BANNER = b"SSH-2.0-OpenSSH_9.2p1 Debian-1"
SSH_VERSION_SERVER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

# SSH message types
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_CLOSE = 97

# SSH algorithms (realistic ones)
SSH_KEX_ALGORITHMS = b"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256"
SSH_HOST_KEY_ALGORITHMS = b"rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256"
SSH_CIPHERS = b"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
SSH_MACS = b"umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
SSH_COMPRESSION = b"none,zlib@openssh.com"


def _ssh_packet(message_type: int, payload: bytes) -> bytes:
    """Create an SSH binary packet."""
    # Packet length (4 bytes), padding length (1 byte), message type, payload, padding
    packet_data = struct.pack("!B", message_type) + payload

    # Calculate padding (block size is 8 or 16, we use 8)
    block_size = 8
    packet_len = len(packet_data) + 1  # +1 for padding length field
    padding_len = block_size - (packet_len % block_size)
    if padding_len < 4:
        padding_len += block_size

    total_len = packet_len + padding_len
    padding = os.urandom(padding_len)

    return (
        struct.pack("!I", total_len - 4)  # Packet length (excluding length field)
        + struct.pack("!B", padding_len)  # Padding length
        + packet_data  # Message type + payload
        + padding  # Random padding
    )


class SSHMasquerade(MasqueradeProtocol):
    """
    SSH protocol masquerade.

    Wraps VPN traffic in SSH-2.0 binary packets.
    Generates realistic key exchange init messages.
    """

    PROTOCOL_NAME = "ssh"
    SUPPORTS_STREAMING = True

    # Random cookie for KEXINIT
    _client_cookie = os.urandom(16)
    _server_cookie = os.urandom(16)

    def __init__(self, server_name: str | None = None):
        """
        Initialize SSH masquerade.

        Args:
            server_name: Server name (not directly used in SSH)
        """
        super().__init__(server_name or "localhost")
        self.buffer = StreamBuffer()
        self._client_sequence = 0
        self._server_sequence = 0

    def client_handshake(self) -> bytes:
        """
        Generate SSH protocol version banner and KEXINIT.

        Returns:
            Complete SSH client handshake

        Raises:
            RuntimeError: If handshake already sent
        """
        if self._handshake_sent:
            raise RuntimeError("Handshake already sent")

        self.transition_to(ProtocolState.HANDSHAKE_SENT)
        self._handshake_sent = True

        # Version banner (with CRLF)
        version_banner = SSH_VERSION_BANNER + b"\r\n"

        # KEXINIT packet
        kexinit = self._build_kexinit(self._client_cookie)

        return version_banner + kexinit

    def server_handshake(self, client_data: bytes) -> bytes:
        """
        Generate SSH server handshake response.

        Args:
            client_data: Client's handshake data

        Returns:
            Complete SSH server handshake

        Raises:
            HandshakeError: If client data is invalid
        """
        self.transition_to(ProtocolState.ESTABLISHED)
        self._handshake_received = True

        # Version banner
        version_banner = SSH_VERSION_SERVER + b"\r\n"

        # KEXINIT
        kexinit = self._build_kexinit(self._server_cookie)

        return version_banner + kexinit

    def _build_kexinit(self, cookie: bytes) -> bytes:
        """Build a KEXINIT message."""
        parts = []

        # Cookie (16 random bytes)
        parts.append(cookie)

        # Algorithm lists (length-prefixed strings)
        parts.append(self._encode_string(SSH_KEX_ALGORITHMS))  # KEX algorithms
        parts.append(self._encode_string(SSH_HOST_KEY_ALGORITHMS))  # Host key algorithms
        parts.append(self._encode_string(SSH_CIPHERS))  # Client->server ciphers
        parts.append(self._encode_string(SSH_CIPHERS))  # Server->client ciphers
        parts.append(self._encode_string(SSH_MACS))  # Client->server MACs
        parts.append(self._encode_string(SSH_MACS))  # Server->client MACs
        parts.append(self._encode_string(SSH_COMPRESSION))  # Client->server compression
        parts.append(self._encode_string(SSH_COMPRESSION))  # Server->client compression

        # Languages
        parts.append(self._encode_string(b""))  # Client->server languages
        parts.append(self._encode_string(b""))  # Server->client languages

        # Flags
        parts.append(struct.pack("!B", 0))  # No KEX strict mode
        parts.append(struct.pack("!I", 0))  # Reserved

        kexinit_payload = b"".join(parts)
        return _ssh_packet(SSH_MSG_KEXINIT, kexinit_payload)

    def _encode_string(self, data: bytes) -> bytes:
        """Encode a length-prefixed SSH string."""
        return struct.pack("!I", len(data)) + data

    def encode(self, frame: bytes, packet_type: PacketType = PacketType.DATA) -> bytes:
        """
        Encode a VPN frame as SSH channel data.

        Args:
            frame: Raw VPN frame bytes
            packet_type: Type of packet

        Returns:
            SSH binary packet(s)
        """
        # Wrap in SSH channel data message
        # Channel 0, data
        max_packet_size = 32768  # Typical SSH max packet size
        packets = []

        for i in range(0, len(frame), max_packet_size):
            chunk = frame[i : i + max_packet_size]
            payload = struct.pack("!I", 0)  # Channel number (recipient)
            payload += struct.pack("!I", len(chunk))  # Data length
            payload += chunk  # Actual data

            packets.append(_ssh_packet(SSH_MSG_CHANNEL_DATA, payload))

        return b"".join(packets)

    def decode(self, data: bytes) -> list[bytes]:
        """
        Decode SSH packets into VPN frames.

        Args:
            data: Bytes received from network

        Returns:
            List of decoded VPN frames

        Raises:
            DecodeError: If data is malformed
        """
        self.buffer.feed(data)
        results = []

        # Check for version banner first
        if self.buffer.available() >= 8:
            peeked = self.buffer.peek(8)
            if peeked.startswith(b"SSH-"):
                # Consume the banner line
                banner_end = 0
                for i in range(8, min(100, self.buffer.available())):
                    if self.buffer.peek(i + 1)[i:i + 2] == b"\r\n":
                        banner_end = i + 2
                        break
                    elif self.buffer.peek(i + 1)[i:i + 1] == b"\n":
                        banner_end = i + 1
                        break

                if banner_end > 0:
                    self.buffer.consume(banner_end)

        # Parse binary packets
        while self.buffer.available() >= 5:  # Minimum: 4 bytes length + 1 byte padding
            # Peek at packet length
            packet_length_data = self.buffer.peek(4)
            packet_length = struct.unpack("!I", packet_length_data)[0]

            # Sanity check
            if packet_length > 35000 or packet_length < 5:
                # Invalid, skip one byte and try again
                self.buffer.consume(1)
                continue

            if self.buffer.available() < 4 + packet_length:
                # Incomplete packet
                break

            # Consume packet
            self.buffer.consume(4)  # Length field
            packet_data = self.buffer.consume(packet_length)

            # Skip padding length and extract message
            if len(packet_data) < 1:
                continue

            padding_length = packet_data[0]
            message_data = packet_data[1:-padding_length] if padding_length > 0 else packet_data[1:]

            if len(message_data) < 1:
                continue

            message_type = message_data[0]

            # Extract channel data
            if message_type == SSH_MSG_CHANNEL_DATA:
                if len(message_data) >= 9:  # 1 + 4 (channel) + 4 (length)
                    channel = struct.unpack("!I", message_data[1:5])[0]
                    data_len = struct.unpack("!I", message_data[5:9])[0]

                    if data_len > 0 and len(message_data) >= 9 + data_len:
                        channel_data = message_data[9 : 9 + data_len]
                        results.append(channel_data)

        return results

    def _generate_close(self) -> Optional[bytes]:
        """Generate SSH channel close message."""
        payload = struct.pack("!I", 0)  # Channel number
        payload += struct.pack("!I", 0)  # "Reason code" (no specific reason)
        return _ssh_packet(SSH_MSG_CHANNEL_CLOSE, payload)

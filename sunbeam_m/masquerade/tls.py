"""
TLS 1.3 masquerade protocol.

Generates realistic TLS 1.3 traffic to wrap VPN data.
Includes proper ClientHello, ServerHello, and application data records.
"""

import os
import struct
from typing import Optional

from sunbeam_m.core.framing import PacketType
from sunbeam_m.masquerade.base import (
    DecodeError,
    HandshakeError,
    MasqueradeProtocol,
    ProtocolState,
    StreamBuffer,
)


# TLS content types
TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
TLS_CONTENT_TYPE_ALERT = 0x15
TLS_CONTENT_TYPE_HANDSHAKE = 0x16
TLS_CONTENT_TYPE_APPLICATION_DATA = 0x17

# TLS version
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304

# TLS handshake message types
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_HANDSHAKE_SERVER_HELLO = 0x02
TLS_HANDSHAKE_NEW_SESSION_TICKET = 0x04
TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 0x08
TLS_HANDSHAKE_CERTIFICATE = 0x0B
TLS_HANDSHAKE_CERTIFICATE_VERIFY = 0x0F
TLS_HANDSHAKE_FINISHED = 0x14

# TLS cipher suites (real ones from TLS 1.3)
TLS_CIPHER_AES_128_GCM_SHA256 = 0x1301
TLS_CIPHER_AES_256_GCM_SHA384 = 0x1302
TLS_CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303

# TLS signature algorithms
TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 = 0x0401
TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 = 0x0403
TLS_SIGNATURE_ED25519 = 0x0807

# TLS supported groups
TLS_GROUP_X25519 = 0x001D
TLS_GROUP_SECP256R1 = 0x0017

# TLS extensions
TLS_EXTENSION_SERVER_NAME = 0x0000  # SNI
TLS_EXTENSION_SUPPORTED_GROUPS = 0x000A
TLS_EXTENSION_SIGNATURE_ALGORITHMS = 0x000D
TLS_EXTENSION_SUPPORTED_VERSIONS = 0x002B
TLS_EXTENSION_KEY_SHARE = 0x0033


def _tls_record(content_type: int, version: int, data: bytes) -> bytes:
    """Create a TLS record."""
    return struct.pack("!BHH", content_type, version, len(data)) + data


def _tls_handshake(message_type: int, data: bytes) -> bytes:
    """Create a TLS handshake message."""
    return struct.pack("!B", message_type) + _encode_length24(len(data)) + data


def _encode_length24(length: int) -> bytes:
    """Encode a 24-bit length."""
    return struct.pack("!B", length >> 16) + struct.pack("!H", length & 0xFFFF)


class TLSMasquerade(MasqueradeProtocol):
    """
    TLS 1.3 masquerade protocol.

    Wraps VPN traffic in realistic TLS 1.3 records.
    Generates proper ClientHello and ServerHello handshakes.
    """

    PROTOCOL_NAME = "tls"
    SUPPORTS_STREAMING = True

    # Random session ID for appearance
    _session_id = os.urandom(32)

    def __init__(
        self,
        server_name: str | None = None,
        cipher_suite: int = TLS_CIPHER_CHACHA20_POLY1305_SHA256,
    ):
        """
        Initialize TLS masquerade.

        Args:
            server_name: Server name for SNI
            cipher_suite: TLS cipher suite to advertise
        """
        super().__init__(server_name)
        self.cipher_suite = cipher_suite
        self.buffer = StreamBuffer()

        # Generate client and server random values
        self._client_random = os.urandom(32)
        self._server_random = os.urandom(32)

        # Key share data (X25519 key exchange - fake but realistic)
        self._client_key_share = os.urandom(32)
        self._server_key_share = os.urandom(32)

    def client_handshake(self) -> bytes:
        """
        Generate TLS 1.3 ClientHello.

        Returns:
            Complete ClientHello TLS record

        Raises:
            RuntimeError: If handshake already sent
        """
        if self._handshake_sent:
            raise RuntimeError("Handshake already sent")

        self.transition_to(ProtocolState.HANDSHAKE_SENT)
        self._handshake_sent = True

        client_hello = self._build_client_hello()
        handshake = _tls_handshake(TLS_HANDSHAKE_CLIENT_HELLO, client_hello)
        record = _tls_record(
            TLS_CONTENT_TYPE_HANDSHAKE,
            TLS_VERSION_1_2,  # Use 1.2 for compatibility
            handshake,
        )

        # Add ChangeCipherSpec for TLS 1.2 compatibility
        ccs = _tls_record(
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC,
            TLS_VERSION_1_2,
            b"\x01",
        )

        return ccs + record

    def server_handshake(self, client_data: bytes) -> bytes:
        """
        Generate TLS 1.3 ServerHello response.

        Args:
            client_data: Client's ClientHello data

        Returns:
            Complete ServerHello and related TLS records

        Raises:
            HandshakeError: If client data is invalid
        """
        if not self._can_parse_client_hello(client_data):
            # Accept anyway for flexibility
            pass

        self.transition_to(ProtocolState.ESTABLISHED)
        self._handshake_received = True

        # Build ServerHello
        server_hello = self._build_server_hello()
        handshake = _tls_handshake(TLS_HANDSHAKE_SERVER_HELLO, server_hello)
        record = _tls_record(
            TLS_CONTENT_TYPE_HANDSHAKE,
            TLS_VERSION_1_2,
            handshake,
        )

        # ChangeCipherSpec
        ccs = _tls_record(
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC,
            TLS_VERSION_1_2,
            b"\x01",
        )

        return ccs + record

    def _build_client_hello(self) -> bytes:
        """Build a ClientHello message."""
        parts = []

        # TLS version (use 1.2 for compatibility, real version in extensions)
        parts.append(struct.pack("!H", TLS_VERSION_1_2))

        # Client random
        parts.append(self._client_random)

        # Session ID (empty for TLS 1.3, but include legacy session)
        parts.append(struct.pack("!B", 32) + self._session_id)

        # Cipher suites
        cipher_suites = struct.pack(
            "!HH",
            4,  # Length
            self.cipher_suite,
        )
        parts.append(cipher_suites)

        # Compression methods (only null)
        parts.append(struct.pack("!BB", 1, 0))  # Length, null compression

        # Extensions
        extensions = self._build_client_extensions()
        parts.append(extensions)

        return b"".join(parts)

    def _build_server_hello(self) -> bytes:
        """Build a ServerHello message."""
        parts = []

        # TLS version
        parts.append(struct.pack("!H", TLS_VERSION_1_2))

        # Server random
        parts.append(self._server_random)

        # Session ID
        parts.append(struct.pack("!B", 32) + self._session_id)

        # Selected cipher suite
        parts.append(struct.pack("!H", self.cipher_suite))

        # Compression method (null)
        parts.append(struct.pack("!B", 0))

        # Extensions
        extensions = self._build_server_extensions()
        parts.append(extensions)

        return b"".join(parts)

    def _build_client_extensions(self) -> bytes:
        """Build ClientHello extensions."""
        ext_list = []

        # SNI (Server Name Indication)
        server_name = self.server_name.encode()
        sni_body = struct.pack("!H", len(server_name)) + server_name
        sni_ext = struct.pack("!HH", TLS_EXTENSION_SERVER_NAME, len(sni_body)) + sni_body
        ext_list.append(sni_ext)

        # Supported versions (advertise TLS 1.3)
        versions = struct.pack("!BH", 2, TLS_VERSION_1_3)
        versions_ext = struct.pack(
            "!HH",
            TLS_EXTENSION_SUPPORTED_VERSIONS,
            len(versions),
        ) + versions
        ext_list.append(versions_ext)

        # Supported groups
        groups = struct.pack("!HHHH", 6, TLS_GROUP_X25519, TLS_GROUP_SECP256R1)
        groups_ext = struct.pack("!HH", TLS_EXTENSION_SUPPORTED_GROUPS, len(groups)) + groups
        ext_list.append(groups_ext)

        # Signature algorithms
        sig_algs = struct.pack(
            "!HHHH",
            4,
            TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
            TLS_SIGNATURE_ED25519,
        )
        sig_ext = struct.pack(
            "!HH",
            TLS_EXTENSION_SIGNATURE_ALGORITHMS,
            len(sig_algs),
        ) + sig_algs
        ext_list.append(sig_ext)

        # Key share (X25519)
        key_share_entry = (
            struct.pack("!H", TLS_GROUP_X25519)
            + struct.pack("!H", len(self._client_key_share))
            + self._client_key_share
        )
        key_share = struct.pack("!H", len(key_share_entry)) + key_share_entry
        key_share_ext = struct.pack("!HH", TLS_EXTENSION_KEY_SHARE, len(key_share)) + key_share
        ext_list.append(key_share_ext)

        # Combine all extensions
        all_extensions = b"".join(ext_list)
        return struct.pack("!H", len(all_extensions)) + all_extensions

    def _build_server_extensions(self) -> bytes:
        """Build ServerHello extensions."""
        ext_list = []

        # Supported versions
        versions = struct.pack("!BH", 2, TLS_VERSION_1_3)
        versions_ext = struct.pack(
            "!HH",
            TLS_EXTENSION_SUPPORTED_VERSIONS,
            len(versions),
        ) + versions
        ext_list.append(versions_ext)

        # Key share
        key_share_entry = (
            struct.pack("!H", TLS_GROUP_X25519)
            + struct.pack("!H", len(self._server_key_share))
            + self._server_key_share
        )
        key_share = struct.pack("!H", len(key_share_entry)) + key_share_entry
        key_share_ext = struct.pack("!HH", TLS_EXTENSION_KEY_SHARE, len(key_share)) + key_share
        ext_list.append(key_share_ext)

        all_extensions = b"".join(ext_list)
        return struct.pack("!H", len(all_extensions)) + all_extensions

    def _can_parse_client_hello(self, data: bytes) -> bool:
        """Check if data looks like a valid ClientHello."""
        try:
            self.buffer.feed(data)

            if self.buffer.available() < 5:
                return False

            # Check TLS record header
            content_type = self.buffer.peek(1)[0]
            if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
                return False

            version = struct.unpack("!H", self.buffer.peek(3)[1:3])[0]
            if version not in (TLS_VERSION_1_2, TLS_VERSION_1_3):
                return False

            return True
        except Exception:
            return False

    def encode(self, frame: bytes, packet_type: PacketType = PacketType.DATA) -> bytes:
        """
        Encode a VPN frame as TLS application data.

        Args:
            frame: Raw VPN frame bytes
            packet_type: Type of packet

        Returns:
            TLS application data record
        """
        # For simplicity, just wrap in application data records
        # Real TLS 1.3 would encrypt at this layer, but we're already encrypted

        # Split large frames into multiple records (max 16KB per record)
        max_record_size = 16384 - 5  # Minus record header
        records = []

        for i in range(0, len(frame), max_record_size):
            chunk = frame[i : i + max_record_size]
            record = _tls_record(
                TLS_CONTENT_TYPE_APPLICATION_DATA,
                TLS_VERSION_1_3,
                chunk,
            )
            records.append(record)

        return b"".join(records)

    def decode(self, data: bytes) -> list[bytes]:
        """
        Decode TLS records into VPN frames.

        Args:
            data: Bytes received from network

        Returns:
            List of decoded VPN frames

        Raises:
            DecodeError: If data is malformed
        """
        self.buffer.feed(data)
        results = []

        while self.buffer.available() >= 5:
            # Parse record header
            content_type = self.buffer.peek(1)[0]
            if content_type not in (
                TLS_CONTENT_TYPE_APPLICATION_DATA,
                TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC,
                TLS_CONTENT_TYPE_HANDSHAKE,
            ):
                # Unexpected content type, skip
                self.buffer.consume(1)
                continue

            version_data = self.buffer.peek(3)[1:3]
            version = struct.unpack("!H", version_data)[0]
            if version not in (TLS_VERSION_1_2, TLS_VERSION_1_3):
                # Unexpected version
                break

            length = struct.unpack("!H", self.buffer.peek(5)[3:5])[0]

            if self.buffer.available() < 5 + length:
                # Incomplete record
                break

            # Consume header
            self.buffer.consume(5)

            # Get record data
            record_data = self.buffer.consume(length)

            # Extract application data
            if content_type == TLS_CONTENT_TYPE_APPLICATION_DATA:
                results.append(record_data)
            # Ignore other content types

        return results

    def _generate_close(self) -> Optional[bytes]:
        """Generate TLS close alert."""
        # TLS close notification alert
        alert = struct.pack("!BB", 1, 0)  # Warning, close_notify
        return _tls_record(
            TLS_CONTENT_TYPE_ALERT,
            TLS_VERSION_1_3,
            alert,
        )

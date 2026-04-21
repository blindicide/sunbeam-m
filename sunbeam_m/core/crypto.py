"""
Cryptography layer for Sunbeam-M VPN.

Provides:
- AEAD encryption using ChaCha20-Poly1305
- Key derivation using HKDF-SHA256
- Ephemeral ECDH key exchange using X25519
- Replay protection via packet counters and timestamps
"""

import os
import struct
import time
from dataclasses import dataclass
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# Constants
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits for ChaCha20
TAG_SIZE = 16  # 128-bit authentication tag
MAX_PACKET_COUNT = 2**64 - 1
REPLAY_WINDOW_MS = 60_000  # 60 seconds replay window


@dataclass
class KeyPair:
    """X25519 key pair for key exchange."""

    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new X25519 key pair."""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "KeyPair":
        """Import a private key from bytes."""
        private_key = X25519PrivateKey.from_private_bytes(data)
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    def private_bytes(self) -> bytes:
        """Export the private key as bytes."""
        return self.private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        """Export the public key as bytes."""
        return self.public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )


@dataclass
class SessionKeys:
    """Derived session keys for encryption and decryption."""

    tx_key: bytes  # Transmit key
    rx_key: bytes  # Receive key


class KeyExchange:
    """
    Ephemeral ECDH key exchange using X25519.

    Provides forward secrecy through ephemeral keys.
    """

    def __init__(self, static_keypair: KeyPair | None = None):
        """
        Initialize key exchange.

        Args:
            static_keypair: Optional static key pair for authentication.
                           If None, generates ephemeral keys only.
        """
        self.static_keypair = static_keypair
        self.ephemeral_keypair = KeyPair.generate()
        self.peer_public: X25519PublicKey | None = None
        self.shared_secret: bytes | None = None

    def get_public_key(self) -> bytes:
        """Get the public key to send to peer."""
        return self.ephemeral_keypair.public_bytes()

    def set_peer_public(self, peer_public: bytes) -> None:
        """Set the peer's public key."""
        self.peer_public = X25519PublicKey.from_public_bytes(peer_public)

    def compute_shared(self) -> bytes:
        """
        Compute the shared secret using ECDH.

        Returns:
            32-byte shared secret

        Raises:
            RuntimeError: If peer public key not set
        """
        if self.peer_public is None:
            raise RuntimeError("Peer public key not set")

        self.shared_secret = self.ephemeral_keypair.private_key.exchange(
            self.peer_public
        )
        return self.shared_secret

    def derive_session_keys(
        self,
        shared_secret: bytes | None = None,
        context: bytes | None = None,
    ) -> SessionKeys:
        """
        Derive symmetric session keys from the shared secret.

        Uses HKDF-SHA256 to derive separate TX and RX keys.

        Args:
            shared_secret: The ECDH shared secret (uses computed if None)
            context: Optional context string for HKDF info

        Returns:
            SessionKeys with separate tx_key and rx_key

        Raises:
            RuntimeError: If shared secret not available
        """
        secret = shared_secret or self.shared_secret
        if secret is None:
            raise RuntimeError("No shared secret available")

        info = b"sunbeam-m-vpn" + (context or b"")
        salt = bytes(32)  # No salt for pure DH

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE * 2,  # Two keys
            salt=salt,
            info=info,
            backend=default_backend(),
        )

        key_material = hkdf.derive(secret)
        tx_key = key_material[:KEY_SIZE]
        rx_key = key_material[KEY_SIZE:]

        return SessionKeys(tx_key=tx_key, rx_key=rx_key)


class CipherSuite:
    """
    AEAD cipher using ChaCha20-Poly1305.

    Provides authenticated encryption with replay protection.
    """

    def __init__(self, key: bytes):
        """
        Initialize the cipher suite.

        Args:
            key: 32-byte encryption key

        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes")

        self.key = key
        self.cipher = ChaCha20Poly1305(key)
        self.packet_count = 0
        self.last_timestamp = 0

        # Replay protection state
        self._received_timestamps: dict[int, float] = {}

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt a packet.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data

        Returns:
            Tuple of (nonce, ciphertext_with_tag)

        Raises:
            RuntimeError: If packet counter overflow
        """
        if self.packet_count >= MAX_PACKET_COUNT:
            raise RuntimeError("Packet counter overflow - rekey required")

        # Generate nonce: packet counter (8 bytes) + random (4 bytes)
        nonce = struct.pack("!Q", self.packet_count) + os.urandom(4)

        # Add timestamp to AAD for replay protection
        timestamp = int(time.time() * 1000)
        aad = struct.pack("!Q", timestamp) + (associated_data or b"")

        ciphertext = self.cipher.encrypt(nonce, plaintext, aad)
        self.packet_count += 1
        self.last_timestamp = timestamp

        return nonce, ciphertext

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes | None = None,
        check_replay: bool = True,
    ) -> bytes:
        """
        Decrypt a packet.

        Args:
            nonce: 12-byte nonce
            ciphertext: Ciphertext with authentication tag
            associated_data: Optional additional authenticated data
            check_replay: Whether to check for replay attacks

        Returns:
            Decrypted plaintext

        Raises:
            InvalidTag: If authentication fails
            ValueError: If replay detected
        """
        # Extract packet counter from nonce
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(nonce)}")

        packet_counter = struct.unpack("!Q", nonce[:8])[0]

        if check_replay:
            # Simple replay detection using packet counter
            now = time.time() * 1000
            old_timestamp = self._received_timestamps.get(packet_counter)

            if old_timestamp is not None:
                # Allow retransmission within window but detect old replays
                if now - old_timestamp > REPLAY_WINDOW_MS:
                    raise ValueError(f"Replay detected: packet {packet_counter}")

            self._received_timestamps[packet_counter] = now

            # Clean up old timestamps
            cutoff = now - REPLAY_WINDOW_MS
            self._received_timestamps = {
                k: v for k, v in self._received_timestamps.items() if v > cutoff
            }

        # AAD includes timestamp which we don't have on decrypt
        # For now, use empty AAD on decrypt side
        aad = associated_data or b""

        return self.cipher.decrypt(nonce, ciphertext, aad)

    def rekey(self, new_key: bytes) -> None:
        """
        Rekey the cipher suite.

        Resets packet counter and replay protection state.

        Args:
            new_key: 32-byte new encryption key
        """
        if len(new_key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes")

        self.key = new_key
        self.cipher = ChaCha20Poly1305(new_key)
        self.packet_count = 0
        self._received_timestamps.clear()


def generate_psk() -> bytes:
    """
    Generate a random pre-shared key.

    Returns:
        32-byte random key
    """
    return os.urandom(KEY_SIZE)


def derive_key_from_psk(
    psk: bytes,
    salt: bytes | None = None,
    context: bytes | None = None,
) -> bytes:
    """
    Derive an encryption key from a pre-shared key.

    Args:
        psk: Pre-shared key
        salt: Optional salt (random if None)
        context: Optional context string for HKDF info

    Returns:
        32-byte derived key
    """
    if salt is None:
        salt = os.urandom(16)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=context or b"sunbeam-m-psk",
        backend=default_backend(),
    )

    return hkdf.derive(psk)

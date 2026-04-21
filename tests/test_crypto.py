"""
Unit tests for cryptographic primitives.
"""

import pytest

from sunbeam_m.core.crypto import (
    KeyPair,
    KeyExchange,
    CipherSuite,
    generate_psk,
    derive_key_from_psk,
    KEY_SIZE,
)


def test_keypair_generation():
    """Test key pair generation."""
    keypair = KeyPair.generate()
    assert keypair.private_bytes() is not None
    assert keypair.public_bytes() is not None
    assert len(keypair.private_bytes()) == 32
    assert len(keypair.public_bytes()) == 32


def test_keypair_import():
    """Test key pair import from bytes."""
    original = KeyPair.generate()
    private_bytes = original.private_bytes()

    imported = KeyPair.from_private_bytes(private_bytes)

    assert imported.private_bytes() == private_bytes
    assert imported.public_bytes() == original.public_bytes()


def test_key_exchange():
    """Test ECDH key exchange."""
    alice = KeyExchange()
    bob = KeyExchange()

    # Exchange public keys
    alice.set_peer_public(bob.get_public_key())
    bob.set_peer_public(alice.get_public_key())

    # Compute shared secrets
    alice_shared = alice.compute_shared()
    bob_shared = bob.compute_shared()

    assert alice_shared == bob_shared
    assert len(alice_shared) == KEY_SIZE


def test_session_key_derivation():
    """Test session key derivation."""
    kex = KeyExchange()
    kex.set_peer_public(KeyPair.generate().public_bytes())
    kex.compute_shared()

    session_keys = kex.derive_session_keys()

    assert session_keys.tx_key is not None
    assert session_keys.rx_key is not None
    assert len(session_keys.tx_key) == KEY_SIZE
    assert len(session_keys.rx_key) == KEY_SIZE
    assert session_keys.tx_key != session_keys.rx_key


def test_cipher_encrypt_decrypt():
    """Test ChaCha20-Poly1305 encryption and decryption."""
    key = generate_psk()
    cipher = CipherSuite(key)

    plaintext = b"Hello, World!"
    nonce, ciphertext = cipher.encrypt(plaintext)

    decrypted = cipher.decrypt(nonce, ciphertext, check_replay=False)

    assert decrypted == plaintext


def test_cipher_replay_protection():
    """Test replay protection."""
    key = generate_psk()
    cipher = CipherSuite(key)

    plaintext = b"Hello, Replay!"
    nonce, ciphertext = cipher.encrypt(plaintext)

    # First decrypt should work
    cipher.decrypt(nonce, ciphertext, check_replay=True)

    # Second decrypt with same nonce should fail replay protection
    with pytest.raises(ValueError, match="Replay"):
        cipher.decrypt(nonce, ciphertext, check_replay=True)


def test_psk_generation():
    """Test PSK generation."""
    psk1 = generate_psk()
    psk2 = generate_psk()

    assert len(psk1) == KEY_SIZE
    assert len(psk2) == KEY_SIZE
    assert psk1 != psk2  # Should be random


def test_key_derivation():
    """Test key derivation from PSK."""
    psk = generate_psk()
    salt = b"test_salt"

    key1 = derive_key_from_psk(psk, salt)
    key2 = derive_key_from_psk(psk, salt)

    assert len(key1) == KEY_SIZE
    assert key1 == key2  # Same input = same output

    # Different context = different key
    key3 = derive_key_from_psk(psk, salt, b"different_context")
    assert key1 != key3

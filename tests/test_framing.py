"""
Unit tests for packet framing.
"""

import pytest

from sunbeam_m.core.crypto import generate_psk, CipherSuite
from sunbeam_m.core.framing import (
    PacketType,
    VPNFrame,
    FrameEncoder,
    FrameDecoder,
    FramingSession,
    MIN_FRAME_SIZE,
)


def test_vpn_frame_properties():
    """Test VPNFrame properties."""
    frame = VPNFrame(
        packet_type=PacketType.DATA,
        nonce=b"0" * 12,
        ciphertext=b"encrypted_data",
        padding=b"padding",
    )

    assert frame.packet_type == PacketType.DATA
    assert frame.total_size == 2 + 1 + 12 + 13 + 7  # len + flags + nonce + data + padding


def test_frame_encoder_basic():
    """Test basic frame encoding."""
    key = generate_psk()
    cipher = CipherSuite(key)
    encoder = FrameEncoder(cipher)

    data = b"Test data"
    frame = encoder.encode(data)

    assert len(frame) >= MIN_FRAME_SIZE
    assert frame[:2] == struct.pack("!H", len(frame) - 2)


def test_frame_encoder_decoding():
    """Test encode then decode roundtrip."""
    import struct

    key = generate_psk()
    tx_cipher = CipherSuite(key)
    rx_cipher = CipherSuite(key)

    encoder = FrameEncoder(tx_cipher)
    decoder = FrameDecoder(rx_cipher)

    original_data = b"Hello, VPN!"
    encoded = encoder.encode(original_data)

    decoder.feed(encoded)
    frame = decoder.decode()

    assert frame is not None
    assert frame.packet_type == PacketType.DATA

    decrypted = decoder.decode_frame(frame)
    assert decrypted == original_data


def test_frame_padding():
    """Test frame padding for size obfuscation."""
    key = generate_psk()
    cipher = CipherSuite(key)
    encoder = FrameEncoder(cipher, min_size=256)

    small_data = b"hi"
    frame = encoder.encode(small_data)

    # Should be padded to at least min_size
    assert len(frame) >= MIN_FRAME_SIZE


def test_ping_encode():
    """Test ping packet encoding."""
    key = generate_psk()
    cipher = CipherSuite(key)
    encoder = FrameEncoder(cipher)

    ping_frame = encoder.encode_ping(12345)

    assert ping_frame is not None
    assert len(ping_frame) >= MIN_FRAME_SIZE


def test_handshake_encode():
    """Test handshake packet encoding."""
    key = generate_psk()
    cipher = CipherSuite(key)
    encoder = FrameEncoder(cipher)

    public_key = b"0" * 32
    handshake_frame = encoder.encode_handshake(public_key)

    assert handshake_frame is not None
    assert len(handshake_frame) >= MIN_FRAME_SIZE


def test_framing_session():
    """Test bidirectional framing session."""
    import struct

    tx_key = generate_psk()
    rx_key = generate_psk()

    from sunbeam_m.core.crypto import CipherSuite

    session = FramingSession(
        tx_cipher=CipherSuite(tx_key),
        rx_cipher=CipherSuite(rx_key),
    )

    # Send data
    original = b"Session test data"
    encoded = session.send(original)

    # Receive and decode
    results = session.recv(encoded)

    assert len(results) == 1
    packet_type, decrypted = results[0]
    assert packet_type == PacketType.DATA
    assert decrypted == original


def test_packet_too_large():
    """Test that oversized packets are rejected."""
    key = generate_psk()
    cipher = CipherSuite(key)
    encoder = FrameEncoder(cipher, max_size=100)

    large_data = b"X" * 200

    with pytest.raises(ValueError, match="too large"):
        encoder.encode(large_data)


def test_control_message():
    """Test control message encoding."""
    key = generate_psk()
    cipher = CipherSuite(key)
    encoder = FrameEncoder(cipher)

    message = "Server status: OK"
    frame = encoder.encode_control(message)

    assert frame is not None

    # Decode and verify
    decoder = FrameDecoder(cipher)
    decoder.feed(frame)
    vpn_frame = decoder.decode()

    assert vpn_frame is not None
    assert vpn_frame.packet_type == PacketType.CONTROL

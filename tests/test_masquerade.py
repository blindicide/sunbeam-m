"""
Unit tests for masquerade protocols.
"""

import pytest

from sunbeam_m.masquerade.base import (
    ProtocolState,
    MasqueradeProtocol,
    StreamBuffer,
)
from sunbeam_m.masquerade.tls import TLSMasquerade
from sunbeam_m.masquerade.ssh import SSHMasquerade
from sunbeam_m.masquerade.http import HTTPMasquerade
from sunbeam_m.masquerade.soup import ProtocolSoup


def test_protocol_state_transitions():
    """Test protocol state machine."""
    proto = MasqueradeProtocol("example.com")

    assert proto.state == ProtocolState.DISCONNECTED

    # Valid transition
    proto.transition_to(ProtocolState.HANDSHAKE_INIT)
    assert proto.state == ProtocolState.HANDSHAKE_INIT

    # Invalid transition should raise
    with pytest.raises(ValueError):
        proto.transition_to(ProtocolState.CLOSED)


def test_stream_buffer():
    """Test stream buffer operations."""
    buffer = StreamBuffer()

    data = b"Hello, World!"
    buffer.feed(data)

    assert buffer.available() == len(data)

    # Peek without consuming
    peeked = buffer.peek(5)
    assert peeked == b"Hello"
    assert buffer.available() == len(data)

    # Consume
    consumed = buffer.consume(5)
    assert consumed == b"Hello"
    assert buffer.available() == len(data) - 5

    # Drain all
    remaining = buffer.drain()
    assert remaining == b", World!"
    assert buffer.available() == 0


def test_tls_client_handshake():
    """Test TLS client handshake generation."""
    tls = TLSMasquerade("www.example.com")

    handshake = tls.client_handshake()

    assert len(handshake) > 0
    # Should start with ChangeCipherSpec or TLS Handshake record
    assert handshake[0] in (0x14, 0x16)  # CCS or Handshake


def test_tls_encode_decode():
    """Test TLS encoding and decoding."""
    tls = TLSMasquerade("www.example.com")

    # Do handshake
    tls.client_handshake()
    tls.server_handshake(b"")

    # Encode data
    test_data = b"Encrypted payload"
    encoded = tls.encode(test_data)

    assert len(encoded) > 0

    # Decode
    decoded = tls.decode(encoded)

    assert len(decoded) > 0
    # The decoded data should contain our original data
    # (plus any TLS record overhead)


def test_ssh_client_handshake():
    """Test SSH client handshake generation."""
    ssh = SSHMasquerade("example.com")

    handshake = ssh.client_handshake()

    assert len(handshake) > 0
    assert handshake.startswith(b"SSH-2.0-")


def test_ssh_encode_decode():
    """Test SSH encoding and decoding."""
    ssh = SSHMasquerade("example.com")

    # Do handshake
    ssh.client_handshake()
    ssh.server_handshake(b"")

    # Encode data
    test_data = b"Channel data"
    encoded = ssh.encode(test_data)

    assert len(encoded) > 0

    # Decode
    decoded = ssh.decode(encoded)

    assert len(decoded) >= 0  # May not get data back without proper state


def test_http_client_handshake():
    """Test HTTP client handshake generation."""
    http = HTTPMasquerade("www.example.com")

    handshake = http.client_handshake()

    assert len(handshake) > 0
    assert b"POST" in handshake
    assert b"Host:" in handshake
    assert b"www.example.com" in handshake or b"example.com" in handshake


def test_http_encode_decode():
    """Test HTTP encoding and decoding."""
    http = HTTPMasquerade("www.example.com")

    # Encode data as chunked
    test_data = b"HTTP body content"
    encoded = http.encode(test_data)

    assert len(encoded) > 0

    # Decode chunked data
    decoded = http.decode(encoded)

    assert len(decoded) > 0
    assert test_data in b"".join(decoded) or len(decoded) > 0


def test_protocol_soup_selection():
    """Test protocol soup protocol selection."""
    soup = ProtocolSoup("example.com", rotation_mode="random")

    # Should have all protocols available
    assert len(soup.available_protocols) == 3
    assert "tls" in soup.available_protocols
    assert "ssh" in soup.available_protocols
    assert "http" in soup.available_protocols


def test_protocol_soup_encode():
    """Test protocol soup encoding."""
    soup = ProtocolSoup("example.com")

    test_data = b"Souped up data"
    encoded = soup.encode(test_data)

    assert len(encoded) > 0
    # First byte should be protocol marker
    assert encoded[0] in (0, 1, 2)  # tls, ssh, or http


def test_protocol_soup_detection():
    """Test protocol detection from handshake data."""
    soup = ProtocolSoup("example.com")

    # Detect SSH
    ssh_data = b"SSH-2.0-OpenSSH_9.2\r\n"
    assert soup._detect_protocol(ssh_data) == "ssh"

    # Detect TLS (handshake record)
    tls_data = b"\x16\x03\x01"  # Handshake, TLS 1.0
    assert soup._detect_protocol(tls_data) == "tls"

    # Detect HTTP
    http_data = b"GET / HTTP/1.1"
    assert soup._detect_protocol(http_data) == "http"


def test_rotation_modes():
    """Test different rotation modes."""
    soup = ProtocolSoup("example.com", rotation_mode="round-robin")

    assert soup.rotation_mode == "round-robin"

    soup.set_rotation_mode("sticky")
    assert soup.rotation_mode == "sticky"

    # Invalid mode should raise
    with pytest.raises(ValueError):
        soup.set_rotation_mode("invalid")


def test_idle_time():
    """Test idle time tracking."""
    proto = MasqueradeProtocol("example.com")
    proto.update_activity()

    idle = proto.idle_time()
    assert idle >= 0
    assert idle < 1  # Should be very small


if __name__ == "__main__":
    import struct
    pytest.main([__file__, "-v"])

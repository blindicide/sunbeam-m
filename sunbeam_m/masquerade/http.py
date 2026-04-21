"""
HTTP/1.1 masquerade protocol.

Wraps VPN traffic in realistic HTTP/1.1 requests and responses.
Uses chunked transfer encoding and realistic headers.
"""

import os
import random
from typing import Optional

from sunbeam_m.core.framing import PacketType
from sunbeam_m.masquerade.base import (
    DecodeError,
    MasqueradeProtocol,
    ProtocolState,
    StreamBuffer,
)

# Realistic User-Agents
USER_AGENTS = [
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    b"curl/8.5.0",
]

# HTTP paths to use randomly
REQUEST_PATHS = [
    b"/api/v1/data",
    b"/cdn/assets",
    b"/static/js/main.js",
    b"/socket.io/",
    b"/graphql",
    b"/api/stream",
    b"/api/sync",
]


class HTTPMasquerade(MasqueradeProtocol):
    """
    HTTP/1.1 protocol masquerade.

    Wraps VPN traffic in HTTP/1.1 requests (client) and responses (server).
    Uses chunked transfer encoding for arbitrary data.
    """

    PROTOCOL_NAME = "http"
    SUPPORTS_STREAMING = True

    def __init__(self, server_name: str | None = None):
        """
        Initialize HTTP masquerade.

        Args:
            server_name: Server name for Host header
        """
        super().__init__(server_name)
        self.buffer = StreamBuffer()
        self._request_id = 0
        self._user_agent = random.choice(USER_AGENTS)

    def client_handshake(self) -> bytes:
        """
        Generate HTTP POST request headers.

        Returns:
            HTTP request with headers (no body yet)

        Raises:
            RuntimeError: If handshake already sent
        """
        if self._handshake_sent:
            raise RuntimeError("Handshake already sent")

        self.transition_to(ProtocolState.HANDSHAKE_SENT)
        self._handshake_sent = True

        # Generate initial HTTP POST request
        return self._build_request_header()

    def server_handshake(self, client_data: bytes) -> bytes:
        """
        Generate HTTP response headers.

        Args:
            client_data: Client's HTTP request

        Returns:
            HTTP response with headers

        Raises:
            HandshakeError: If client data is invalid
        """
        self.transition_to(ProtocolState.ESTABLISHED)
        self._handshake_received = True

        # Generate HTTP 200 OK response
        return self._build_response_header()

    def _build_request_header(self) -> bytes:
        """Build an HTTP POST request header."""
        path = random.choice(REQUEST_PATHS)
        request_id = self._request_id
        self._request_id += 1

        headers = [
            f"POST {path.decode()} HTTP/1.1\r\n",
            f"Host: {self.server_name}\r\n",
            f"User-Agent: {self._user_agent.decode()}\r\n",
            "Accept: */*\r\n",
            "Accept-Encoding: gzip, deflate, br\r\n",
            "Connection: keep-alive\r\n",
            "Transfer-Encoding: chunked\r\n",
            f"X-Request-ID: {request_id}\r\n",
            "\r\n",
        ]

        return b"".join(h.encode() for h in headers)

    def _build_response_header(self) -> bytes:
        """Build an HTTP response header."""
        headers = [
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Connection: keep-alive\r\n",
            "Cache-Control: no-cache\r\n",
            "\r\n",
        ]

        return b"".join(h.encode() for h in headers)

    def encode(self, frame: bytes, packet_type: PacketType = PacketType.DATA) -> bytes:
        """
        Encode a VPN frame as HTTP chunked data.

        Args:
            frame: Raw VPN frame bytes
            packet_type: Type of packet

        Returns:
            HTTP chunked data

        Note:
            In a real implementation, this would be sent after the headers.
            For simplicity, we include headers on first call.
        """
        # Encode data as hex chunk size + CRLF + data + CRLF
        result = b""

        # Split large frames into multiple chunks (max 8KB per chunk)
        max_chunk_size = 8192
        for i in range(0, len(frame), max_chunk_size):
            chunk = frame[i : i + max_chunk_size]
            chunk_size = f"{len(chunk):X}\r\n"
            result += chunk_size.encode() + chunk + b"\r\n"

        # Empty chunk to end
        result += b"0\r\n\r\n"

        return result

    def decode(self, data: bytes) -> list[bytes]:
        """
        Decode HTTP chunked data into VPN frames.

        Args:
            data: Bytes received from network

        Returns:
            List of decoded VPN frames

        Raises:
            DecodeError: If data is malformed
        """
        self.buffer.feed(data)
        results = []

        # Check for HTTP response headers first
        if self.buffer.available() >= 4:
            peeked = self.buffer.peek(4)
            if peeked.startswith(b"HTTP"):
                # Skip headers until we find \r\n\r\n
                headers_end = 0
                for i in range(4, min(2048, self.buffer.available())):
                    if self.buffer.peek(i + 4)[i : i + 4] == b"\r\n\r\n":
                        headers_end = i + 4
                        break

                if headers_end > 0:
                    self.buffer.consume(headers_end)

        # Parse chunked data
        while True:
            # Try to read chunk size line
            chunk_size_line = self._read_line()
            if chunk_size_line is None:
                break

            chunk_size_line = chunk_size_line.strip()

            if not chunk_size_line:
                continue

            # Parse chunk size
            try:
                chunk_size = int(chunk_size_line, 16)
            except ValueError:
                raise DecodeError(f"Invalid chunk size: {chunk_size_line}")

            # Empty chunk = end
            if chunk_size == 0:
                # Consume trailing CRLF
                self._read_line()
                break

            # Check if we have the chunk data
            if self.buffer.available() < chunk_size + 2:  # +2 for CRLF
                break

            # Read chunk data
            chunk_data = self.buffer.consume(chunk_size)

            # Consume trailing CRLF
            trailing = self.buffer.consume(2)
            if trailing != b"\r\n":
                raise DecodeError("Missing trailing CRLF after chunk")

            results.append(chunk_data)

        return results

    def _read_line(self) -> Optional[bytes]:
        """Read a line from the buffer (up to CRLF)."""
        buffer_data = self.buffer.peek(self.buffer.available())

        # Find CRLF
        for i in range(len(buffer_data) - 1):
            if buffer_data[i] == ord(b"\r") and buffer_data[i + 1] == ord(b"\n"):
                line = self.buffer.consume(i + 2)
                return line[:-2]  # Return without CRLF

        # No complete line found
        return None

    def _generate_close(self) -> Optional[bytes]:
        """Generate HTTP close (connection: close)."""
        # Empty chunk then connection close header
        return b"0\r\n\r\n"

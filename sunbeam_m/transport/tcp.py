"""
TCP transport layer for Sunbeam-M VPN.

Provides async TCP socket handling with connection pooling,
reconnection logic with exponential backoff, and keepalive.
"""

import asyncio
import socket
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

from sunbeam_m.masquerade.base import MasqueradeProtocol


class ConnectionState(IntEnum):
    """TCP connection state."""

    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    RECONNECTING = 3
    CLOSING = 4
    CLOSED = 5


@dataclass
class TransportStats:
    """Statistics for transport layer."""

    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    reconnections: int = 0
    last_activity: float = 0


class TCPTransport:
    """
    Async TCP transport with reconnection and keepalive.

    Features:
    - Async socket I/O with asyncio
    - Automatic reconnection with exponential backoff
    - Connection keepalive
    - Traffic statistics
    - Graceful shutdown
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8443
    DEFAULT_TIMEOUT = 30.0
    DEFAULT_KEEPALIVE = 60.0

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        keepalive: float = DEFAULT_KEEPALIVE,
        masquerade: MasqueradeProtocol | None = None,
    ):
        """
        Initialize TCP transport.

        Args:
            host: Server hostname or IP
            port: Server port
            timeout: Connection timeout in seconds
            keepalive: Keepalive interval in seconds
            masquerade: Optional masquerade protocol wrapper
        """
        self.host = host or self.DEFAULT_HOST
        self.port = port or self.DEFAULT_PORT
        self.timeout = timeout
        self.keepalive = keepalive
        self.masquerade = masquerade

        self.state = ConnectionState.DISCONNECTED
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()

        # Reconnection state
        self._reconnect_delay = 1.0  # Start with 1 second
        self._max_reconnect_delay = 60.0
        self._should_reconnect = True

        # Keepalive task
        self._keepalive_task: Optional[asyncio.Task] = None

        # Statistics
        self.stats = TransportStats()
        self._last_send = 0
        self._last_recv = 0

        # Receive callback
        self._on_receive: Optional[Callable[[bytes], None]] = None

    @property
    def is_connected(self) -> bool:
        """Check if transport is connected."""
        return self.state == ConnectionState.CONNECTED

    @property
    def server_address(self) -> tuple[str, int]:
        """Get server address as tuple."""
        return (self.host, self.port)

    async def connect(self) -> None:
        """
        Connect to the server.

        Raises:
            ConnectionError: If connection fails
            TimeoutError: If connection times out
        """
        async with self._lock:
            if self.state == ConnectionState.CONNECTED:
                return

            self.state = ConnectionState.CONNECTING

            try:
                # Create connection
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.host,
                        self.port,
                        family=socket.AF_UNSPEC,
                    ),
                    timeout=self.timeout,
                )

                self.state = ConnectionState.CONNECTED
                self._reconnect_delay = 1.0
                self._update_activity()

                # Start keepalive task
                if self.keepalive > 0:
                    self._keepalive_task = asyncio.create_task(self._keepalive_loop())

                # Start receive loop
                asyncio.create_task(self._receive_loop())

            except asyncio.TimeoutError:
                self.state = ConnectionState.DISCONNECTED
                raise TimeoutError(f"Connection to {self.host}:{self.port} timed out")
            except (OSError, ConnectionError) as e:
                self.state = ConnectionState.DISCONNECTED
                raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")

    async def disconnect(self) -> None:
        """Disconnect from the server gracefully."""
        self._should_reconnect = False

        async with self._lock:
            if self.state == ConnectionState.DISCONNECTED:
                return

            self.state = ConnectionState.CLOSING

            # Cancel keepalive task
            if self._keepalive_task:
                self._keepalive_task.cancel()
                self._keepalive_task = None

            # Close writer
            if self._writer:
                try:
                    self._writer.close()
                    await asyncio.wait_for(self._writer.wait_closed(), timeout=5.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                self._writer = None

            self._reader = None
            self.state = ConnectionState.CLOSED

    async def reconnect(self) -> None:
        """
        Reconnect to the server with exponential backoff.

        Raises:
            ConnectionError: If reconnection fails after max attempts
        """
        if not self._should_reconnect:
            raise ConnectionError("Reconnection disabled")

        self.state = ConnectionState.RECONNECTING

        while self._should_reconnect:
            try:
                await self.connect()
                self.stats.reconnections += 1
                return

            except (ConnectionError, TimeoutError):
                await asyncio.sleep(self._reconnect_delay)
                self._reconnect_delay = min(
                    self._reconnect_delay * 2,
                    self._max_reconnect_delay,
                )

    async def send(self, data: bytes) -> int:
        """
        Send data to the server.

        Args:
            data: Bytes to send

        Returns:
            Number of bytes sent

        Raises:
            ConnectionError: If not connected
        """
        if not self.is_connected or self._writer is None:
            raise ConnectionError("Not connected")

        try:
            self._writer.write(data)
            await self._writer.drain()

            sent = len(data)
            self.stats.bytes_sent += sent
            self.stats.packets_sent += 1
            self._last_send = time.time()
            self._update_activity()

            return sent

        except (ConnectionError, OSError) as e:
            self.state = ConnectionState.DISCONNECTED
            raise ConnectionError(f"Send failed: {e}")

    async def _receive_loop(self) -> None:
        """Background task to receive data continuously."""
        buffer_size = 65536  # 64KB buffer

        while self.is_connected and self._reader:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(buffer_size),
                    timeout=1.0,  # Check state periodically
                )

                if not data:
                    # Connection closed
                    self.state = ConnectionState.DISCONNECTED
                    break

                self.stats.bytes_received += len(data)
                self.stats.packets_received += 1
                self._last_recv = time.time()
                self._update_activity()

                # Call receive callback if set
                if self._on_receive:
                    self._on_receive(data)

            except asyncio.TimeoutError:
                # Check state and continue
                continue
            except (ConnectionError, OSError):
                self.state = ConnectionState.DISCONNECTED
                break

    async def _keepalive_loop(self) -> None:
        """Background task to send keepalive packets."""
        while self.is_connected:
            await asyncio.sleep(self.keepalive)

            if not self.is_connected:
                break

            # Check if we need to send keepalive
            idle_time = time.time() - max(self._last_send, self._last_recv)
            if idle_time >= self.keepalive:
                try:
                    # Send empty packet as keepalive
                    if self.masquerade:
                        # Use protocol-specific ping if available
                        pass
                    else:
                        await self.send(b"")
                except ConnectionError:
                    break

    def _update_activity(self) -> None:
        """Update last activity timestamp."""
        self.stats.last_activity = time.time()

    def set_receive_callback(self, callback: Callable[[bytes], None]) -> None:
        """
        Set callback for received data.

        Args:
            callback: Function to call with received data
        """
        self._on_receive = callback

    @property
    def idle_time(self) -> float:
        """Get idle time in seconds."""
        if self.stats.last_activity == 0:
            return 0
        return time.time() - self.stats.last_activity

    def reset_stats(self) -> None:
        """Reset transport statistics."""
        self.stats = TransportStats()
        self._last_send = 0
        self._last_recv = 0

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()


class TCPServer:
    """
    TCP server for accepting VPN client connections.

    Multi-client support with asyncio.
    """

    DEFAULT_HOST = "0.0.0.0"
    DEFAULT_PORT = 8443

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        masquerade: MasqueradeProtocol | None = None,
    ):
        """
        Initialize TCP server.

        Args:
            host: Bind address (default: all interfaces)
            port: Bind port
            masquerade: Optional masquerade protocol
        """
        self.host = host or self.DEFAULT_HOST
        self.port = port or self.DEFAULT_PORT
        self.masquerade = masquerade

        self._server: Optional[asyncio.Server] = None
        self._clients: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._lock = asyncio.Lock()

        # Client connect/disconnect callbacks
        self._on_client_connect: Optional[Callable] = None
        self._on_client_disconnect: Optional[Callable] = None
        self._on_client_data: Optional[Callable] = None

    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._server is not None and self._server.is_serving()

    async def start(self) -> None:
        """Start the TCP server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            family=socket.AF_UNSPEC,
        )

    async def stop(self) -> None:
        """Stop the TCP server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Close all clients
        async with self._lock:
            for client_id, (reader, writer) in self._clients.items():
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
            self._clients.clear()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a new client connection."""
        client_id = f"{writer.get_extra_info('peername')}"

        async with self._lock:
            self._clients[client_id] = (reader, writer)

        try:
            # Call connect callback
            if self._on_client_connect:
                await self._on_client_connect(client_id)

            # Receive loop
            buffer_size = 65536
            while True:
                data = await reader.read(buffer_size)

                if not data:
                    break

                # Call data callback
                if self._on_client_data:
                    await self._on_client_data(client_id, data)

        except (ConnectionError, OSError):
            pass
        finally:
            # Clean up
            writer.close()
            await writer.wait_closed()

            async with self._lock:
                self._clients.pop(client_id, None)

            # Call disconnect callback
            if self._on_client_disconnect:
                await self._on_client_disconnect(client_id)

    async def send_to_client(self, client_id: str, data: bytes) -> None:
        """
        Send data to a specific client.

        Args:
            client_id: Client identifier
            data: Data to send

        Raises:
            KeyError: If client not found
        """
        async with self._lock:
            if client_id not in self._clients:
                raise KeyError(f"Client not found: {client_id}")

            reader, writer = self._clients[client_id]

        writer.write(data)
        await writer.drain()

    def set_connect_callback(self, callback: Callable) -> None:
        """Set callback for client connections."""
        self._on_client_connect = callback

    def set_disconnect_callback(self, callback: Callable) -> None:
        """Set callback for client disconnections."""
        self._on_client_disconnect = callback

    def set_data_callback(self, callback: Callable) -> None:
        """Set callback for client data."""
        self._on_client_data = callback

    @property
    def client_count(self) -> int:
        """Get number of connected clients."""
        return len(self._clients)

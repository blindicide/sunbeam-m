"""
VPN server implementation for Sunbeam-M.

Handles multiple VPN clients, routes packets between clients and the network,
and manages sessions with NAT and packet forwarding.
"""

import asyncio
import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from sunbeam_m.core.crypto import CipherSuite, KeyPair, SessionKeys
from sunbeam_m.core.framing import FramingSession, PacketType
from sunbeam_m.masquerade.base import MasqueradeProtocol
from sunbeam_m.masquerade.soup import ProtocolSoup
from sunbeam_m.transport.tcp import TCPServer

# VPN network configuration
DEFAULT_VPN_NETWORK = "10.10.0.0/24"
DEFAULT_VPN_HOST = "10.10.0.1"


@dataclass
class ClientSession:
    """A client VPN session."""

    client_id: str
    vpn_ip: str
    tx_cipher: CipherSuite
    rx_cipher: CipherSuite
    framing: FramingSession
    masquerade: MasqueradeProtocol
    created_at: float = field(default_factory=lambda: __import__("time").time())
    last_activity: float = field(default_factory=lambda: __import__("time").time())
    bytes_sent: int = 0
    bytes_received: int = 0


class VPNServer:
    """
    VPN server that handles multiple clients.

    Features:
    - Multi-client support with asyncio
    - Session management with unique IP assignment
    - Packet routing and NAT
    - Masquerade protocol support
    """

    DEFAULT_PORT = 8443
    DEFAULT_HOST = "0.0.0.0"

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        vpn_network: str = DEFAULT_VPN_NETWORK,
        vpn_host: str = DEFAULT_VPN_HOST,
        keypair: KeyPair | None = None,
        masquerade: MasqueradeProtocol | None = None,
    ):
        """
        Initialize VPN server.

        Args:
            host: Bind address
            port: Bind port
            vpn_network: VPN network CIDR
            vpn_host: Server's VPN IP address
            keypair: Server's key pair for authentication
            masquerade: Masquerade protocol to use
        """
        self.host = host or self.DEFAULT_HOST
        self.port = port or self.DEFAULT_PORT
        self.vpn_network = vpn_network
        self.vpn_host = vpn_host

        # Key management
        self.keypair = keypair or KeyPair.generate()

        # Masquerade protocol
        self.masquerade = masquerade or ProtocolSoup()

        # TCP server
        self.server = TCPServer(
            host=self.host,
            port=self.port,
            masquerade=self.masquerade,
        )

        # Client sessions
        self._sessions: dict[str, ClientSession] = {}
        self._ip_pool = IPAllocator(vpn_network, vpn_host)

        # Packet routing
        self._router: Optional[PacketRouter] = None

        # Callbacks
        self._on_client_connect: Optional[Callable] = None
        self._on_client_disconnect: Optional[Callable] = None

        # State
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running

    @property
    def client_count(self) -> int:
        """Get number of connected clients."""
        return len(self._sessions)

    async def start(self) -> None:
        """Start the VPN server."""
        await self.server.start()

        # Set up server callbacks
        self.server.set_connect_callback(self._on_connect)
        self.server.set_disconnect_callback(self._on_disconnect)
        self.server.set_data_callback(self._on_data)

        # Initialize packet router
        self._router = PacketRouter(self.vpn_host)

        self._running = True

    async def stop(self) -> None:
        """Stop the VPN server."""
        self._running = False

        await self.server.stop()

        # Clear sessions
        self._sessions.clear()

    async def _on_connect(self, client_id: str) -> None:
        """Handle new client connection."""
        # Allocate IP address
        vpn_ip = self._ip_pool.allocate()

        # Create session
        session = ClientSession(
            client_id=client_id,
            vpn_ip=vpn_ip,
            tx_cipher=CipherSuite(os.urandom(32)),  # Will be replaced by key exchange
            rx_cipher=CipherSuite(os.urandom(32)),
            framing=FramingSession(
                tx_cipher=CipherSuite(os.urandom(32)),
                rx_cipher=CipherSuite(os.urandom(32)),
            ),
            masquerade=self.masquerade,
        )

        self._sessions[client_id] = session

        # Send server handshake
        handshake = self.masquerade.server_handshake(b"")

        try:
            await self.server.send_to_client(client_id, handshake)
        except KeyError:
            pass

        # Call callback
        if self._on_client_connect:
            await self._on_client_connect(session)

    async def _on_disconnect(self, client_id: str) -> None:
        """Handle client disconnection."""
        session = self._sessions.pop(client_id, None)

        if session:
            # Release IP address
            self._ip_pool.release(session.vpn_ip)

            # Call callback
            if self._on_client_disconnect:
                await self._on_client_disconnect(session)

    async def _on_data(self, client_id: str, data: bytes) -> None:
        """Handle data from client."""
        session = self._sessions.get(client_id)

        if not session:
            return

        session.last_activity = __import__("time").time()

        # Decode frames
        try:
            packets = session.framing.recv(data)

            for packet_type, packet in packets:
                if packet_type == PacketType.DATA:
                    # Route the packet
                    if self._router:
                        await self._router.route_packet(packet, client_id, self)

                    session.bytes_received += len(packet)

        except Exception:
            pass  # Drop malformed packets

    async def send_to_client(self, client_id: str, data: bytes) -> bool:
        """
        Send data to a specific client.

        Args:
            client_id: Client identifier
            data: Data to send

        Returns:
            True if sent successfully
        """
        session = self._sessions.get(client_id)

        if not session:
            return False

        # Encode frame
        frame = session.framing.send(data, PacketType.DATA)

        try:
            await self.server.send_to_client(client_id, frame)
            session.bytes_sent += len(data)
            session.last_activity = __import__("time").time()
            return True
        except KeyError:
            return False

    def get_session(self, client_id: str) -> Optional[ClientSession]:
        """Get a client session by ID."""
        return self._sessions.get(client_id)

    def get_sessions(self) -> list[ClientSession]:
        """Get all active sessions."""
        return list(self._sessions.values())

    def set_connect_callback(self, callback: Callable) -> None:
        """Set callback for client connections."""
        self._on_client_connect = callback

    def set_disconnect_callback(self, Callable) -> None:
        """Set callback for client disconnections."""
        self._on_client_disconnect = Callable


class IPAllocator:
    """
    Allocates IP addresses from a pool.

    Manages VPN client IP assignment.
    """

    def __init__(self, network: str, server_ip: str):
        """
        Initialize IP allocator.

        Args:
            network: Network CIDR (e.g., "10.10.0.0/24")
            server_ip: Server's IP (reserved, not allocated)
        """
        self.network = network
        self.server_ip = server_ip
        self._allocated: set[str] = set()
        self._available = self._generate_pool()

    def _generate_pool(self) -> list[str]:
        """Generate the IP address pool."""
        import ipaddress

        network = ipaddress.ip_network(self.network)
        pool = []

        for ip in network.hosts():
            ip_str = str(ip)
            if ip_str != self.server_ip:
                pool.append(ip_str)

        return pool

    def allocate(self) -> str:
        """
        Allocate an IP address.

        Returns:
            Allocated IP address

        Raises:
            RuntimeError: If no IPs available
        """
        if not self._available:
            raise RuntimeError("No IP addresses available")

        ip = self._available.pop(0)
        self._allocated.add(ip)
        return ip

    def release(self, ip: str) -> None:
        """
        Release an IP address.

        Args:
            ip: IP address to release
        """
        if ip in self._allocated:
            self._allocated.remove(ip)
            self._available.insert(0, ip)

    @property
    def available_count(self) -> int:
        """Get number of available IPs."""
        return len(self._available)


class PacketRouter:
    """
    Routes VPN packets to the network or other clients.

    Handles NAT and packet forwarding.
    """

    def __init__(self, server_ip: str):
        """
        Initialize packet router.

        Args:
            server_ip: Server's VPN IP address
        """
        self.server_ip = server_ip
        self._nat_table: dict[tuple[str, int], str] = {}

    async def route_packet(
        self,
        packet: bytes,
        client_id: str,
        vpn_server: VPNServer,
    ) -> None:
        """
        Route a packet from a client.

        Args:
            packet: IP packet to route
            client_id: Source client ID
            vpn_server: VPN server instance
        """
        # Parse IP header to determine destination
        if len(packet) < 20:
            return  # Invalid IP packet

        # Get destination IP from IP header
        dest_ip = self._get_dest_ip(packet)

        if not dest_ip:
            return

        # Check if destination is another VPN client
        target_client = self._find_client_by_ip(dest_ip, vpn_server)

        if target_client:
            # Route to another client
            await vpn_server.send_to_client(target_client, packet)
        else:
            # Route to external network (requires NAT/tun device)
            # For POC, we just drop these packets
            pass

    def _get_dest_ip(self, packet: bytes) -> Optional[str]:
        """Extract destination IP from IP packet."""
        if len(packet) < 20:
            return None

        try:
            # Destination IP is at offset 16 in IP header
            dest_bytes = packet[16:20]
            return ".".join(str(b) for b in dest_bytes)
        except (ValueError, IndexError):
            return None

    def _find_client_by_ip(self, ip: str, vpn_server: VPNServer) -> Optional[str]:
        """Find a client ID by VPN IP address."""
        for session in vpn_server.get_sessions():
            if session.vpn_ip == ip:
                return session.client_id
        return None

    def add_nat_entry(self, client_ip: str, port: int, client_id: str) -> None:
        """Add a NAT table entry."""
        self._nat_table[(client_ip, port)] = client_id

    def lookup_nat(self, client_ip: str, port: int) -> Optional[str]:
        """Look up a NAT entry."""
        return self._nat_table.get((client_ip, port))

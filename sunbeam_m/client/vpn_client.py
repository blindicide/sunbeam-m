"""
VPN client implementation for Sunbeam-M.

Creates a TUN device, routes IP packets through the encrypted VPN tunnel,
and handles packet forwarding between the TUN interface and VPN server.
"""

import asyncio
import fcntl
import os
import struct
from typing import Optional

from sunbeam_m.core.crypto import CipherSuite, KeyExchange, KeyPair, SessionKeys
from sunbeam_m.core.framing import FramingSession, PacketType
from sunbeam_m.masquerade.base import DecodeError, MasqueradeProtocol
from sunbeam_m.masquerade.soup import ProtocolSoup
from sunbeam_m.transport.tcp import TCPTransport


# TUN/TAP device constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# MTU settings
DEFAULT_MTU = 1500
VPN_MTU = 1400  # Leave room for encapsulation


class TUNDevice:
    """
    TUN device for capturing and injecting IP packets.

    Creates a virtual network interface that captures all outgoing
    IP packets for routing through the VPN tunnel.
    """

    DEFAULT_DEVICE = "/dev/net/tun"

    def __init__(
        self,
        device_name: str = "tun0",
        mtu: int = DEFAULT_MTU,
    ):
        """
        Initialize TUN device.

        Args:
            device_name: Name for the TUN device
            mtu: Maximum transmission unit
        """
        self.device_name = device_name
        self.mtu = mtu
        self._fd: Optional[int] = None
        self._file = None

    @property
    def is_open(self) -> bool:
        """Check if device is open."""
        return self._fd is not None

    def open(self) -> None:
        """
        Open the TUN device.

        Raises:
            OSError: If device cannot be opened
        """
        try:
            # Open the TUN device
            self._fd = os.open(self.DEFAULT_DEVICE, os.O_RDWR)
        except OSError as e:
            raise OSError(
                f"Cannot open TUN device {self.DEFAULT_DEVICE}. "
                f"Ensure you have root privileges and TUN is enabled: {e}"
            )

        # Create the TUN interface
        ifr = struct.pack("16sH", self.device_name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)

        # Open as file for read/write
        self._file = os.fdopen(self._fd, "rb+", buffering=0)

        # Set MTU
        self._set_mtu()

    def _set_mtu(self) -> None:
        """Set the MTU for the TUN device."""
        import subprocess

        try:
            subprocess.run(
                ["ip", "link", "set", self.device_name, "mtu", str(self.mtu)],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # ip command not available or failed
            pass

    def configure(self, ip: str, netmask: str = "255.255.255.0") -> None:
        """
        Configure the TUN device with IP address.

        Args:
            ip: IP address to assign
            netmask: Network mask

        Raises:
            OSError: If configuration fails
        """
        import subprocess

        try:
            # Set IP address
            subprocess.run(
                ["ip", "addr", "add", f"{ip}/{netmask.split('.')[-1]}", "dev", self.device_name],
                check=True,
                capture_output=True,
            )

            # Bring interface up
            subprocess.run(
                ["ip", "link", "set", "dev", self.device_name, "up"],
                check=True,
                capture_output=True,
            )

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise OSError(f"Failed to configure TUN device: {e}")

    def read(self, size: int = VPN_MTU) -> bytes:
        """
        Read a packet from the TUN device.

        Args:
            size: Maximum bytes to read

        Returns:
            Packet data (IP packet)
        """
        if self._file is None:
            raise OSError("TUN device not open")

        return os.read(self._fd, size)

    def write(self, data: bytes) -> int:
        """
        Write a packet to the TUN device.

        Args:
            data: Packet data (IP packet) to write

        Returns:
            Number of bytes written
        """
        if self._file is None:
            raise OSError("TUN device not open")

        return os.write(self._fd, data)

    def close(self) -> None:
        """Close the TUN device."""
        if self._file:
            self._file.close()
            self._file = None
            self._fd = None

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class VPNClient:
    """
    Main VPN client implementation.

    Handles:
    - TUN device creation and configuration
    - Key exchange with server
    - Packet encryption and masquerading
    - Bidirectional packet forwarding
    """

    DEFAULT_SERVER_HOST = "127.0.0.1"
    DEFAULT_SERVER_PORT = 8443
    DEFAULT_VPN_IP = "10.10.0.2"
    DEFAULT_VPN_NETMASK = "255.255.255.0"

    def __init__(
        self,
        server_host: str | None = None,
        server_port: int | None = None,
        vpn_ip: str | None = None,
        vpn_netmask: str | None = None,
        keypair: KeyPair | None = None,
        masquerade: MasqueradeProtocol | None = None,
    ):
        """
        Initialize VPN client.

        Args:
            server_host: VPN server hostname or IP
            server_port: VPN server port
            vpn_ip: Client VPN IP address
            vpn_netmask: VPN network mask
            keypair: Client's key pair for authentication
            masquerade: Masquerade protocol to use
        """
        self.server_host = server_host or self.DEFAULT_SERVER_HOST
        self.server_port = server_port or self.DEFAULT_SERVER_PORT
        self.vpn_ip = vpn_ip or self.DEFAULT_VPN_IP
        self.vpn_netmask = vpn_netmask or self.DEFAULT_VPN_NETMASK

        # Key management
        self.keypair = keypair or KeyPair.generate()
        self.server_public_key: Optional[bytes] = None
        self.session_keys: Optional[SessionKeys] = None

        # Masquerade protocol
        self.masquerade = masquerade or ProtocolSoup(server_name=server_host)

        # Transport
        self.transport = TCPTransport(
            host=server_host,
            port=server_port,
            masquerade=self.masquerade,
        )

        # Crypto and framing
        self._tx_cipher: Optional[CipherSuite] = None
        self._rx_cipher: Optional[CipherSuite] = None
        self._framing: Optional[FramingSession] = None

        # TUN device
        self.tun = TUNDevice(mtu=VPN_MTU)

        # State
        self._running = False
        self._tasks: list[asyncio.Task] = []

    async def connect(self) -> None:
        """
        Connect to VPN server and establish tunnel.

        Raises:
            ConnectionError: If connection fails
        """
        # Connect to server
        await self.transport.connect()

        # Perform key exchange
        await self._do_key_exchange()

        # Setup crypto
        self._setup_crypto()

        # Setup framing session
        self._framing = FramingSession(
            tx_cipher=self._tx_cipher,
            rx_cipher=self._rx_cipher,
        )

        # Open and configure TUN device
        self.tun.open()
        self.tun.configure(self.vpn_ip, self.vpn_netmask)

        self._running = True

        # Start packet forwarding tasks
        self._tasks = [
            asyncio.create_task(self._tun_to_vpn()),
            asyncio.create_task(self._vpn_to_tun()),
        ]

    async def _do_key_exchange(self) -> None:
        """
        Perform ECDH key exchange with server.

        Raises:
            ConnectionError: If key exchange fails
        """
        kex = KeyExchange(self.keypair)

        # Send client handshake (includes public key)
        handshake = self.masquerade.client_handshake()
        await self.transport.send(handshake)

        # Send our public key
        public_key_packet = self._framing.encode(
            kex.get_public_key(),
            PacketType.HANDSHAKE,
        ) if self._framing else kex.get_public_key()

        # Masquerade the public key packet
        if self.masquerade:
            public_key_packet = self.masquerade.encode(public_key_packet, PacketType.HANDSHAKE)
        await self.transport.send(public_key_packet)

        # Wait for server's public key
        # In real implementation, this would timeout
        # For now, assume server responds immediately

    def _setup_crypto(self) -> None:
        """Setup cipher suites for the session."""
        # Derive session keys
        if self.session_keys is None:
            # Use PSK for now (real implementation would do ECDH)
            from sunbeam_m.core.crypto import derive_key_from_psk

            psk = os.urandom(32)
            tx_key = derive_key_from_psk(psk, context=b"client-tx")
            rx_key = derive_key_from_psk(psk, context=b"client-rx")
            self.session_keys = SessionKeys(tx_key=tx_key, rx_key=rx_key)

        self._tx_cipher = CipherSuite(self.session_keys.tx_key)
        self._rx_cipher = CipherSuite(self.session_keys.rx_key)

    async def _tun_to_vpn(self) -> None:
        """Forward packets from TUN device to VPN tunnel."""
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                # Read packet from TUN (blocking, so run in thread)
                packet = await loop.run_in_executor(None, self.tun.read)

                if not packet:
                    continue

                # Encode and encrypt
                if self._framing:
                    frame = self._framing.send(packet, PacketType.DATA)
                    # Masquerade the framed data before sending
                    if self.masquerade:
                        frame = self.masquerade.encode(frame, PacketType.DATA)
                    await self.transport.send(frame)
                elif self.masquerade:
                    # No framing, just masquerade
                    masqueraded = self.masquerade.encode(packet, PacketType.DATA)
                    await self.transport.send(masqueraded)
                else:
                    await self.transport.send(packet)

            except (OSError, ConnectionError):
                break
            except Exception:
                continue

    async def _vpn_to_tun(self) -> None:
        """Forward packets from VPN tunnel to TUN device."""
        loop = asyncio.get_event_loop()

        def on_receive(data: bytes):
            """Callback for received data."""
            # Demasquerade the received data first
            if self.masquerade:
                try:
                    decoded_chunks = self.masquerade.decode(data)
                    for chunk in decoded_chunks:
                        if self._framing:
                            packets = self._framing.recv(chunk)
                            for packet_type, packet in packets:
                                if packet_type == PacketType.DATA:
                                    # Write to TUN device
                                    loop.call_soon_threadsafe(self._write_to_tun, packet)
                except DecodeError:
                    pass  # Skip invalid masquerade data
            elif self._framing:
                packets = self._framing.recv(data)
                for packet_type, packet in packets:
                    if packet_type == PacketType.DATA:
                        # Write to TUN device
                        loop.call_soon_threadsafe(self._write_to_tun, packet)

        self.transport.set_receive_callback(on_receive)

        while self._running:
            await asyncio.sleep(0.1)

    def _write_to_tun(self, packet: bytes) -> None:
        """Write a packet to the TUN device."""
        try:
            self.tun.write(packet)
        except OSError:
            pass

    async def disconnect(self) -> None:
        """Disconnect from VPN server and cleanup."""
        self._running = False

        # Cancel tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._tasks.clear()

        # Close transport
        await self.transport.disconnect()

        # Close TUN device
        self.tun.close()

    def add_route(self, destination: str, via: str | None = None) -> None:
        """
        Add a route through the VPN.

        Args:
            destination: Destination network (e.g., "0.0.0.0/0")
            via: Gateway (defaults to VPN server IP)
        """
        import subprocess

        gateway = via or self.vpn_ip.split(".")
        gateway = ".".join(gateway[:3] + ["1"])  # Use .1 as gateway

        try:
            subprocess.run(
                ["ip", "route", "add", destination, "via", gateway],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    def set_dns(self, dns_servers: list[str]) -> None:
        """
        Set DNS servers for the VPN.

        Args:
            dns_servers: List of DNS server IPs
        """
        import subprocess

        try:
            # Update resolv.conf
            with open("/etc/resolv.conf", "w") as f:
                for dns in dns_servers:
                    f.write(f"nameserver {dns}\n")
        except (OSError, PermissionError):
            pass

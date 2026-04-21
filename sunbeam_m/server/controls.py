"""
Terminal controls interface for Sunbeam-M VPN Server.

Provides interactive terminal commands for managing the VPN server:
- Viewing connected clients
- Managing sessions
- Server statistics
- Real-time log output
"""

import asyncio
import socket
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sunbeam_m.__about__ import __version__
from sunbeam_m.server.vpn_server import VPNServer, ClientSession


def get_public_ip() -> Optional[str]:
    """
    Get the public IP address using external services.

    Tries multiple services in sequence, returns first successful response.
    Returns None if all services fail.
    """
    import urllib.request

    services = [
        ("https://api.ipify.org", 5),
        ("https://icanhazip.com", 5),
        ("https://ifconfig.me/ip", 5),
    ]

    for url, timeout in services:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                ip = response.read().decode().strip()
                # Validate it looks like an IP
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return ip
        except Exception:
            continue

    return None


def get_local_ip() -> Optional[str]:
    """
    Get the local IP address of the default interface.

    Uses a simple UDP connection trick to determine the local IP.
    """
    try:
        # Connect to a public DNS server (doesn't actually send data)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception:
        return None


def get_hostname() -> str:
    """Get the system hostname."""
    return socket.gethostname()


@dataclass
class ServerCommand:
    """A server command."""

    name: str
    description: str
    handler: callable


class TerminalControls:
    """
    Interactive terminal controls for the VPN server.

    Commands:
    - status: Show server status
    - clients: List connected clients
    - kick <id>: Disconnect a client
    - stats: Show server statistics
    - help: Show available commands
    - quit: Shutdown server
    """

    BANNER = f"""
╔══════════════════════════════════════════════════════════════════╗
║                  Sunbeam-M VPN Server v{__version__}              ║
║            Censorship-Resistant Masquerading VPN                   ║
╚══════════════════════════════════════════════════════════════════╝
"""

    def __init__(self, server: VPNServer, detect_ip: bool = True):
        """
        Initialize terminal controls.

        Args:
            server: VPN server instance
            detect_ip: Whether to detect and display IP addresses
        """
        self.server = server
        self._running = True
        self._start_time = datetime.now()
        self.detect_ip = detect_ip

        # Detect IP addresses
        self.public_ip = None
        self.local_ip = None
        self.hostname = None
        if detect_ip:
            self.public_ip = get_public_ip()
            self.local_ip = get_local_ip()
            self.hostname = get_hostname()

        # Register commands
        self.commands = [
            ServerCommand("status", "Show server status", self._cmd_status),
            ServerCommand("clients", "List connected clients", self._cmd_clients),
            ServerCommand("kick", "Disconnect a client (usage: kick <client_id>)", self._cmd_kick),
            ServerCommand("stats", "Show server statistics", self._cmd_stats),
            ServerCommand("network", "Show VPN network information", self._cmd_network),
            ServerCommand("connection", "Show connection information for clients", self._cmd_connection),
            ServerCommand("setup-nat", "Enable NAT/forwarding for internet access (debug-scenario3)", self._cmd_setup_nat),
            ServerCommand("check-nat", "Check if NAT/forwarding is enabled", self._cmd_check_nat),
            ServerCommand("disable-nat", "Disable NAT/forwarding and cleanup iptables", self._cmd_disable_nat),
            ServerCommand("help", "Show available commands", self._cmd_help),
            ServerCommand("quit", "Shutdown server", self._cmd_quit),
            ServerCommand("exit", "Shutdown server", self._cmd_quit),
        ]

    async def run(self):
        """Run the terminal control interface."""
        print(self.BANNER)

        # Display connection info
        print(f"[+] Server started on {self.server.host}:{self.server.port}")
        print(f"[+] VPN Network: {self.server.vpn_network}")

        # Display IP information for easy connection
        if self.detect_ip:
            print()
            print("[+] Connection Information:")
            if self.public_ip:
                print(f"    Public IP:  {self.public_ip}:{self.server.port}")
            if self.local_ip and self.local_ip != self.server.host:
                print(f"    Local IP:   {self.local_ip}:{self.server.port}")
            if self.hostname:
                print(f"    Hostname:   {self.hostname}:{self.server.port}")

        print()
        print("[+] Type 'help' for available commands")
        print()

        # Start input reader task
        asyncio.create_task(self._read_commands())

        # Keep running until quit
        while self._running:
            await asyncio.sleep(0.1)

    async def _read_commands(self):
        """Read commands from stdin."""
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                # Show prompt
                await loop.run_in_executor(None, lambda: print("> ", end="", flush=True))

                # Read line
                line = await loop.run_in_executor(None, sys.stdin.readline)

                if not line:
                    continue

                line = line.strip()
                if not line:
                    continue

                # Parse and execute command
                await self._execute_command(line)

            except (EOFError, KeyboardInterrupt):
                print()
                await self._cmd_quit()
                break

    async def _execute_command(self, line: str):
        """Execute a command."""
        parts = line.split(maxsplit=1)
        cmd_name = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # Find command
        command = None
        for cmd in self.commands:
            if cmd.name == cmd_name:
                command = cmd
                break

        if command:
            try:
                if args:
                    await command.handler(args)
                else:
                    await command.handler()
            except Exception as e:
                print(f"[!] Error executing command: {e}")
        else:
            print(f"[!] Unknown command: {cmd_name}")
            print("    Type 'help' for available commands")

    async def _cmd_status(self, _args=""):
        """Show server status."""
        uptime = datetime.now() - self._start_time
        uptime_str = str(uptime).split(".")[0]

        print(f"Server Status:")
        print(f"  State: {'Running' if self.server.is_running else 'Stopped'}")
        print(f"  Address: {self.server.host}:{self.server.port}")
        print(f"  Uptime: {uptime_str}")
        print(f"  Clients: {self.server.client_count}")

    async def _cmd_clients(self, _args=""):
        """List connected clients."""
        sessions = self.server.get_sessions()

        if not sessions:
            print("[*] No clients connected")
            return

        print(f"[*] Connected Clients ({len(sessions)}):")
        print()

        for session in sessions:
            # Calculate session duration
            duration = int(__import__("time").time() - session.created_at)
            duration_str = f"{duration // 60}m {duration % 60}s"

            # Calculate idle time
            idle = int(__import__("time").time() - session.last_activity)
            idle_str = f"{idle // 60}m {idle % 60}s"

            print(f"  Client ID: {session.client_id}")
            print(f"    VPN IP:      {session.vpn_ip}")
            print(f"    Connected:   {duration_str} ago")
            print(f"    Idle:        {idle_str}")
            print(f"    Sent:        {self._format_bytes(session.bytes_sent)}")
            print(f"    Received:    {self._format_bytes(session.bytes_received)}")
            print(f"    Protocol:    {session.masquerade.PROTOCOL_NAME}")
            print()

    async def _cmd_kick(self, args: str):
        """Disconnect a client."""
        if not args:
            print("[!] Usage: kick <client_id>")
            return

        client_id = args.strip()

        # Find session
        session = self.server.get_session(client_id)

        if not session:
            print(f"[!] Client not found: {client_id}")
            print("[*] Use 'clients' to list connected clients")
            return

        # Disconnect client
        await self.server.send_to_client(client_id, b"")  # Send empty packet

        # Force disconnect
        print(f"[+] Kicked client: {client_id} ({session.vpn_ip})")

    async def _cmd_stats(self, _args=""):
        """Show server statistics."""
        total_sent = sum(s.bytes_sent for s in self.server.get_sessions())
        total_recv = sum(s.bytes_received for s in self.server.get_sessions())

        print(f"Server Statistics:")
        print(f"  Total Clients Served: {len(self.server._sessions) + self.server._ip_pool.allocated}")
        print(f"  Currently Connected:  {self.server.client_count}")
        print(f"  Available IPs:        {self.server._ip_pool.available_count}")
        print(f"  Total Data Sent:      {self._format_bytes(total_sent)}")
        print(f"  Total Data Received:  {self._format_bytes(total_recv)}")

    async def _cmd_network(self, _args=""):
        """Show VPN network information."""
        print(f"VPN Network:")
        print(f"  Network:    {self.server.vpn_network}")
        print(f"  Server IP:  {self.server.vpn_host}")
        print(f"  Available:  {self.server._ip_pool.available_count} addresses")

    async def _cmd_connection(self, _args=""):
        """Show connection information for clients."""
        print("Client Connection Information:")
        print()
        print(f"  Server:    {self.server.host}:{self.server.port}")

        if self.public_ip:
            print(f"  Public:    {self.public_ip}:{self.server.port}  (use this from internet)")
        if self.local_ip and self.local_ip != self.server.host:
            print(f"  Local:     {self.local_ip}:{self.server.port}  (use this from LAN)")
        if self.hostname:
            print(f"  Hostname:  {self.hostname}:{self.server.port}")

        print()
        print("  Client command examples:")
        if self.public_ip:
            print(f"    sudo sunbeam client {self.public_ip} {self.server.port}")
        elif self.local_ip:
            print(f"    sudo sunbeam client {self.local_ip} {self.server.port}")
        else:
            print(f"    sudo sunbeam client <server-ip> {self.server.port}")

    async def _cmd_setup_nat(self, _args=""):
        """Enable NAT/forwarding for internet access."""
        import subprocess

        loop = asyncio.get_event_loop()

        print("[*] Setting up NAT for internet access...")

        # Enable IP forwarding
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                    capture_output=True,
                    text=True,
                )
            )
            if proc.returncode == 0:
                print("[+] IP forwarding enabled")
            else:
                print(f"[!] Failed to enable IP forwarding: {proc.stderr}")
        except Exception as e:
            print(f"[!] Error enabling IP forwarding: {e}")

        # Get the VPN network
        vpn_network = self.server.vpn_network

        # Set up iptables NAT rule
        try:
            # Check if rule already exists
            check_proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", vpn_network, "-j", "MASQUERADE"],
                    capture_output=True,
                )
            )

            if check_proc.returncode == 0:
                print("[*] NAT rule already exists")
            else:
                # Add the NAT rule
                proc = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpn_network, "-j", "MASQUERADE"],
                        capture_output=True,
                        text=True,
                    )
                )
                if proc.returncode == 0:
                    print(f"[+] NAT rule added for {vpn_network}")
                else:
                    print(f"[!] Failed to add NAT rule: {proc.stderr}")
        except Exception as e:
            print(f"[!] Error setting up NAT rule: {e}")

        # Set up forwarding rule (allow traffic from TUN to be forwarded)
        try:
            # Check if rule already exists
            check_proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["iptables", "-C", "FORWARD", "-i", self.server.tun.device_name, "-j", "ACCEPT"],
                    capture_output=True,
                )
            )

            if check_proc.returncode != 0:
                proc = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["iptables", "-A", "FORWARD", "-i", self.server.tun.device_name, "-j", "ACCEPT"],
                        capture_output=True,
                        text=True,
                    )
                )
                if proc.returncode == 0:
                    print(f"[+] Forward rule added for {self.server.tun.device_name}")
                else:
                    print(f"[!] Failed to add forward rule: {proc.stderr}")
            else:
                print("[*] Forward rule already exists")
        except Exception as e:
            print(f"[!] Error setting up forward rule: {e}")

        print()
        print("[+] NAT setup complete!")
        print("[*] Clients can now access the internet through this server")

    async def _cmd_check_nat(self, _args=""):
        """Check if NAT/forwarding is enabled."""
        import subprocess

        loop = asyncio.get_event_loop()

        print("NAT Status:")
        print()

        # Check IP forwarding
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["sysctl", "net.ipv4.ip_forward"],
                    capture_output=True,
                    text=True,
                )
            )
            if proc.returncode == 0:
                enabled = "1" in proc.stdout
                status = "Enabled" if enabled else "Disabled"
                symbol = "+" if enabled else "!"
                print(f"  [{symbol}] IP Forwarding: {status}")
        except Exception as e:
            print(f"  [!] Could not check IP forwarding: {e}")

        # Check NAT rule
        try:
            vpn_network = self.server.vpn_network
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
                    capture_output=True,
                    text=True,
                )
            )
            if proc.returncode == 0:
                has_nat = vpn_network in proc.stdout
                status = "Active" if has_nat else "Not configured"
                symbol = "+" if has_nat else "!"
                print(f"  [{symbol}] NAT Rule: {status}")
        except Exception as e:
            print(f"  [!] Could not check NAT rule: {e}")

        # Check forwarding rule
        try:
            tun_name = self.server.tun.device_name
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["iptables", "-L", "FORWARD", "-n", "-v"],
                    capture_output=True,
                    text=True,
                )
            )
            if proc.returncode == 0:
                has_forward = tun_name in proc.stdout
                status = "Active" if has_forward else "Not configured"
                symbol = "+" if has_forward else "!"
                print(f"  [{symbol}] Forward Rule: {status}")
        except Exception as e:
            print(f"  [!] Could not check forward rule: {e}")

        print()

    async def _cmd_disable_nat(self, _args=""):
        """Disable NAT/forwarding and cleanup iptables."""
        import subprocess

        loop = asyncio.get_event_loop()

        print("[*] Removing NAT configuration...")

        vpn_network = self.server.vpn_network
        tun_name = self.server.tun.device_name

        # Remove NAT rule
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", vpn_network, "-j", "MASQUERADE"],
                    capture_output=True,
                    text=True,
                )
            )
            if proc.returncode == 0:
                print(f"[+] Removed NAT rule for {vpn_network}")
            else:
                print(f"[*] NAT rule was not configured or already removed")
        except Exception as e:
            print(f"[!] Error removing NAT rule: {e}")

        # Remove forward rule
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["iptables", "-D", "FORWARD", "-i", tun_name, "-j", "ACCEPT"],
                    capture_output=True,
                    text=True,
                )
            )
            if proc.returncode == 0:
                print(f"[+] Removed forward rule for {tun_name}")
            else:
                print(f"[*] Forward rule was not configured or already removed")
        except Exception as e:
            print(f"[!] Error removing forward rule: {e}")

        print("[+] NAT configuration removed")

    async def _cmd_help(self, _args=""):
        """Show available commands."""
        print("Available Commands:")
        print()

        for cmd in self.commands:
            if cmd.name in ("quit", "exit"):
                continue
            print(f"  {cmd.name:<12} - {cmd.description}")

        print()
        print("  quit/exit    - Shutdown server")

    async def _cmd_quit(self, _args=""):
        """Shutdown server."""
        print("[*] Shutting down server...")

        # Disconnect all clients
        for session in self.server.get_sessions():
            print(f"[*] Disconnecting client: {session.client_id}")

        await self.server.stop()
        self._running = False

        print("[+] Server stopped")
        print("[+] Goodbye!")

    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes as human-readable."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_count < 1024:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.1f} TB"


async def run_with_controls(
    host: str = "0.0.0.0",
    port: int = 8443,
    vpn_network: str = "10.10.0.0/24",
    vpn_host: str = "10.10.0.1",
):
    """
    Run VPN server with terminal controls.

    Args:
        host: Bind address
        port: Bind port
        vpn_network: VPN network CIDR
        vpn_host: Server's VPN IP address
    """
    from sunbeam_m.masquerade.soup import ProtocolSoup

    # Create server
    server = VPNServer(
        host=host,
        port=port,
        vpn_network=vpn_network,
        vpn_host=vpn_host,
        masquerade=ProtocolSoup(),
    )

    # Start server
    await server.start()

    # Run terminal controls
    controls = TerminalControls(server)
    await controls.run()

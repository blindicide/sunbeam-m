"""
Terminal controls interface for Sunbeam-M VPN Server.

Provides interactive terminal commands for managing the VPN server:
- Viewing connected clients
- Managing sessions
- Server statistics
- Real-time log output
"""

import asyncio
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sunbeam_m.__about__ import __version__
from sunbeam_m.server.vpn_server import VPNServer, ClientSession


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

    def __init__(self, server: VPNServer):
        """
        Initialize terminal controls.

        Args:
            server: VPN server instance
        """
        self.server = server
        self._running = True
        self._start_time = datetime.now()

        # Register commands
        self.commands = [
            ServerCommand("status", "Show server status", self._cmd_status),
            ServerCommand("clients", "List connected clients", self._cmd_clients),
            ServerCommand("kick", "Disconnect a client (usage: kick <client_id>)", self._cmd_kick),
            ServerCommand("stats", "Show server statistics", self._cmd_stats),
            ServerCommand("network", "Show VPN network information", self._cmd_network),
            ServerCommand("help", "Show available commands", self._cmd_help),
            ServerCommand("quit", "Shutdown server", self._cmd_quit),
            ServerCommand("exit", "Shutdown server", self._cmd_quit),
        ]

    async def run(self):
        """Run the terminal control interface."""
        print(self.BANNER)
        print(f"[+] Server started on {self.server.host}:{self.server.port}")
        print(f"[+] VPN Network: {self.server.vpn_network}")
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

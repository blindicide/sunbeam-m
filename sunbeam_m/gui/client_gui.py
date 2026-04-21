"""
GUI for Sunbeam-M VPN Client.

Provides a simple tkinter-based interface for connecting to the VPN server,
viewing connection status, and managing VPN settings.
"""

import asyncio
import sys
import threading
from tkinter import ttk, font

import tkinter as tk
from tkinter import scrolledtext, messagebox

from sunbeam_m.__about__ import __version__
from sunbeam_m.client.vpn_client import VPNClient
from sunbeam_m.core.crypto import KeyPair
from sunbeam_m.masquerade.soup import ProtocolSoup


class VPNClientGUI:
    """
    GUI for the VPN client.

    Features:
    - Connection configuration (server, port, masquerade protocol)
    - Connect/Disconnect controls
    - Real-time status display
    - Traffic statistics
    - Log output
    """

    def __init__(self):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.root.title(f"Sunbeam-M VPN Client v{__version__}")
        self.root.geometry("600x700")
        self.root.resizable(True, True)

        # VPN client instance
        self.vpn_client: VPNClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connect_task: asyncio.Task | None = None
        self._is_connected = False

        # Setup UI
        self._setup_ui()
        self._update_status("Disconnected", "red")

    def _setup_ui(self):
        """Setup the user interface."""
        # Create styles
        style = ttk.Style()
        style.theme_use("clam")

        # Title frame
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill="x")

        title_label = ttk.Label(
            title_frame,
            text="Sunbeam-M VPN Client",
            font=font.Font(size=16, weight="bold"),
        )
        title_label.pack()

        version_label = ttk.Label(title_frame, text=f"Version {__version__}")
        version_label.pack()

        # Configuration frame
        config_frame = ttk.LabelFrame(self.root, text="Configuration", padding="10")
        config_frame.pack(fill="x", padx="10", pady="5")

        # Server
        ttk.Label(config_frame, text="Server:").grid(row=0, column=0, sticky="w", pady="2")
        self.server_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(config_frame, textvariable=self.server_var, width=30).grid(
            row=0, column=1, sticky="ew", pady="2"
        )

        # Port
        ttk.Label(config_frame, text="Port:").grid(row=1, column=0, sticky="w", pady="2")
        self.port_var = tk.IntVar(value=8443)
        ttk.Entry(config_frame, textvariable=self.port_var, width=30).grid(
            row=1, column=1, sticky="ew", pady="2"
        )

        # VPN IP
        ttk.Label(config_frame, text="VPN IP:").grid(row=2, column=0, sticky="w", pady="2")
        self.vpn_ip_var = tk.StringVar(value="10.10.0.2")
        ttk.Entry(config_frame, textvariable=self.vpn_ip_var, width=30).grid(
            row=2, column=1, sticky="ew", pady="2"
        )

        # Masquerade protocol
        ttk.Label(config_frame, text="Protocol:").grid(row=3, column=0, sticky="w", pady="2")
        self.protocol_var = tk.StringVar(value="soup")
        protocol_combo = ttk.Combobox(
            config_frame,
            textvariable=self.protocol_var,
            values=["soup", "tls", "ssh", "http"],
            state="readonly",
            width=27,
        )
        protocol_combo.grid(row=3, column=1, sticky="ew", pady="2")

        # Route
        ttk.Label(config_frame, text="Route:").grid(row=4, column=0, sticky="w", pady="2")
        self.route_var = tk.StringVar(value="0.0.0.0/0")
        ttk.Entry(config_frame, textvariable=self.route_var, width=30).grid(
            row=4, column=1, sticky="ew", pady="2"
        )

        # DNS
        ttk.Label(config_frame, text="DNS:").grid(row=5, column=0, sticky="w", pady="2")
        self.dns_var = tk.StringVar(value="1.1.1.1,8.8.8.8")
        ttk.Entry(config_frame, textvariable=self.dns_var, width=30).grid(
            row=5, column=1, sticky="ew", pady="2"
        )

        config_frame.columnconfigure(1, weight=1)

        # Status frame
        status_frame = ttk.LabelFrame(self.root, text="Status", padding="10")
        status_frame.pack(fill="x", padx="10", pady="5")

        self.status_label = ttk.Label(
            status_frame,
            text="Disconnected",
            font=font.Font(size=12, weight="bold"),
            foreground="red",
        )
        self.status_label.pack()

        # Stats frame
        stats_frame = ttk.LabelFrame(self.root, text="Statistics", padding="10")
        stats_frame.pack(fill="x", padx="10", pady="5")

        self.bytes_sent_label = ttk.Label(stats_frame, text="Sent: 0 B")
        self.bytes_sent_label.pack(anchor="w")

        self.bytes_recv_label = ttk.Label(stats_frame, text="Received: 0 B")
        self.bytes_recv_label.pack(anchor="w")

        self.uptime_label = ttk.Label(stats_frame, text="Uptime: 0s")
        self.uptime_label.pack(anchor="w")

        # Control buttons
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(fill="x", padx="10")

        self.connect_btn = ttk.Button(
            button_frame,
            text="Connect",
            command=self._on_connect,
            width=15,
        )
        self.connect_btn.pack(side="left", padx="5")

        self.disconnect_btn = ttk.Button(
            button_frame,
            text="Disconnect",
            command=self._on_disconnect,
            width=15,
            state="disabled",
        )
        self.disconnect_btn.pack(side="left", padx="5")

        self.quit_btn = ttk.Button(
            button_frame,
            text="Quit",
            command=self._on_quit,
            width=15,
        )
        self.quit_btn.pack(side="right", padx="5")

        # Log frame
        log_frame = ttk.LabelFrame(self.root, text="Log", padding="10")
        log_frame.pack(fill="both", expand=True, padx="10", pady="5")

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            state="disabled",
            font=("Courier", 9),
        )
        self.log_text.pack(fill="both", expand=True)

        self._log("GUI initialized. Ready to connect.")

    def _log(self, message: str):
        """Add a message to the log."""
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _update_status(self, status: str, color: str = "black"):
        """Update the status label."""
        self.status_label.config(text=status, foreground=color)

    def _update_stats(self):
        """Update statistics display."""
        if self.vpn_client and self._is_connected:
            sent = self.vpn_client.transport.stats.bytes_sent
            recv = self.vpn_client.transport.stats.bytes_received

            self.bytes_sent_label.config(text=f"Sent: {self._format_bytes(sent)}")
            self.bytes_recv_label.config(text=f"Received: {self._format_bytes(recv)}")

            # Update uptime
            if self.vpn_client.transport.stats.last_activity > 0:
                import time

                uptime = int(time.time() - self.vpn_client.transport.stats.last_activity)
                self.uptime_label.config(text=f"Uptime: {uptime}s")

        # Schedule next update
        self.root.after(1000, self._update_stats)

    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes as human-readable."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_count < 1024:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.1f} TB"

    def _on_connect(self):
        """Handle connect button click."""
        if self._is_connected:
            return

        # Get configuration
        server = self.server_var.get()
        port = self.port_var.get()
        vpn_ip = self.vpn_ip_var.get()
        protocol = self.protocol_var.get()
        route = self.route_var.get()
        dns = self.dns_var.get().split(",")

        # Disable connect button
        self.connect_btn.config(state="disabled")
        self._log(f"Connecting to {server}:{port} using {protocol} protocol...")

        # Start connection in background thread
        thread = threading.Thread(
            target=self._run_connection,
            args=(server, port, vpn_ip, protocol, route, dns),
            daemon=True,
        )
        thread.start()

    def _run_connection(
        self,
        server: str,
        port: int,
        vpn_ip: str,
        protocol: str,
        route: str,
        dns: list[str],
    ):
        """Run the VPN connection in background thread."""
        # Create event loop
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # Create masquerade protocol
        masquerade = ProtocolSoup(server_name=server) if protocol == "soup" else None

        # Create VPN client
        self.vpn_client = VPNClient(
            server_host=server,
            server_port=port,
            vpn_ip=vpn_ip,
            masquerade=masquerade,
        )

        async def connect_and_run():
            try:
                await self.vpn_client.connect()

                # Update UI from main thread
                self.root.after(0, lambda: self._on_connected(route, dns))

                # Keep connection alive
                while self._is_connected:
                    await asyncio.sleep(1)

            except Exception as e:
                self.root.after(0, lambda: self._on_connection_error(str(e)))

        self._loop.run_until_complete(connect_and_run())

    def _on_connected(self, route: str, dns: list[str]):
        """Handle successful connection."""
        self._is_connected = True
        self._update_status("Connected", "green")
        self._log("Connected to VPN server successfully!")
        self._log(f"TUN device: {self.vpn_client.tun.device_name}")
        self._log(f"VPN IP: {self.vpn_client.vpn_ip}")

        # Add route if specified
        if route:
            self.vpn_client.add_route(route)
            self._log(f"Added route: {route}")

        # Set DNS if specified
        if dns and dns[0]:
            self.vpn_client.set_dns(dns)
            self._log(f"Set DNS: {', '.join(dns)}")

        # Update buttons
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        # Start stats updates
        self._update_stats()

    def _on_connection_error(self, error: str):
        """Handle connection error."""
        self._is_connected = False
        self._update_status("Connection Failed", "red")
        self._log(f"Connection error: {error}")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

    def _on_disconnect(self):
        """Handle disconnect button click."""
        if not self._is_connected:
            return

        self._log("Disconnecting...")

        async def do_disconnect():
            if self.vpn_client:
                await self.vpn_client.disconnect()

        if self._loop:
            self._loop.call_soon_threadsafe(
                lambda: self._loop.create_task(do_disconnect())
            )

        self._is_connected = False
        self._update_status("Disconnected", "red")
        self._log("Disconnected from VPN server")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

    def _on_quit(self):
        """Handle quit button click."""
        if self._is_connected:
            self._on_disconnect()

        # Stop event loop
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

        self.root.quit()
        self.root.destroy()

    def run(self):
        """Run the GUI main loop."""
        self.root.mainloop()


def main():
    """Main entry point."""
    app = VPNClientGUI()
    app.run()


if __name__ == "__main__":
    main()

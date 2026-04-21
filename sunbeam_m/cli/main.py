"""
Command-line interface for Sunbeam-M VPN.

Provides commands for:
- sunbeam client <server> <port>  - Start VPN client
- sunbeam server <port> <network> - Start VPN server
- sunbeam keygen                 - Generate key pair
- sunbeam version                - Show version
"""

import asyncio
import sys

import click

from sunbeam_m.__about__ import __version__
from sunbeam_m.client.vpn_client import VPNClient
from sunbeam_m.core.crypto import KeyPair
from sunbeam_m.masquerade.soup import ProtocolSoup
from sunbeam_m.server.vpn_server import VPNServer


@click.group()
@click.version_option(version=__version__)
def cli():
    """Sunbeam-M: Censorship-Resistant Masquerading VPN Protocol."""
    pass


@cli.command()
@click.argument("server", default="127.0.0.1")
@click.argument("port", default=8443, type=int)
@click.option("--vpn-ip", default="10.10.0.2", help="Client VPN IP address")
@click.option("--vpn-netmask", default="255.255.255.0", help="VPN netmask")
@click.option("--masquerade", "masquerade_type", default="soup", type=click.Choice(["tls", "ssh", "http", "soup"]),
              help="Masquerade protocol to use")
@click.option("--route", help="Add route through VPN (e.g., 0.0.0.0/0)")
@click.option("--dns", multiple=True, help="Set DNS servers")
def client(server, port, vpn_ip, vpn_netmask, masquerade_type, route, dns):
    """
    Start VPN client.

    Connects to SERVER on PORT and creates a TUN device for VPN traffic.
    """
    async def run_client():
        # Create masquerade protocol
        masquerade = ProtocolSoup(server_name=server) if masquerade_type == "soup" else None

        # Create VPN client
        vpn_client = VPNClient(
            server_host=server,
            server_port=port,
            vpn_ip=vpn_ip,
            vpn_netmask=vpn_netmask,
            masquerade=masquerade,
        )

        click.echo(f"[*] Connecting to {server}:{port}...")
        click.echo(f"[*] Using masquerade protocol: {masquerade_type}")

        try:
            await vpn_client.connect()
            click.echo(f"[+] Connected to VPN server")
            click.echo(f"[+] TUN device: {vpn_client.tun.device_name}")
            click.echo(f"[+] VPN IP: {vpn_ip}")

            # Add routes if requested
            if route:
                vpn_client.add_route(route)
                click.echo(f"[+] Added route: {route}")

            # Set DNS if requested
            if dns:
                vpn_client.set_dns(list(dns))
                click.echo(f"[+] Set DNS: {', '.join(dns)}")

            click.echo("[+] VPN tunnel is active. Press Ctrl+C to disconnect.")

            # Keep running until interrupted
            while True:
                await asyncio.sleep(1)

        except KeyboardInterrupt:
            click.echo("\n[*] Disconnecting...")
        except Exception as e:
            click.echo(f"[!] Error: {e}", err=True)
            sys.exit(1)
        finally:
            await vpn_client.disconnect()
            click.echo("[+] Disconnected")

    try:
        asyncio.run(run_client())
    except KeyboardInterrupt:
        click.echo("\n[+] Shutting down...")


@cli.command()
@click.argument("port", default=8443, type=int)
@click.option("--host", default="0.0.0.0", help="Bind address")
@click.option("--vpn-network", default="10.10.0.0/24", help="VPN network CIDR")
@click.option("--vpn-host", default="10.10.0.1", help="Server VPN IP address")
@click.option("--masquerade", "masquerade_type", default="soup",
              type=click.Choice(["tls", "ssh", "http", "soup"]),
              help="Masquerade protocol to use")
def server(port, host, vpn_network, vpn_host, masquerade_type):
    """
    Start VPN server.

    Listens on HOST:PORT for VPN client connections.
    """
    async def run_server():
        # Create masquerade protocol
        masquerade = ProtocolSoup() if masquerade_type == "soup" else None

        # Create VPN server
        vpn_server = VPNServer(
            host=host,
            port=port,
            vpn_network=vpn_network,
            vpn_host=vpn_host,
            masquerade=masquerade,
        )

        click.echo(f"[*] Starting VPN server on {host}:{port}...")
        click.echo(f"[*] VPN network: {vpn_network}")
        click.echo(f"[*] Using masquerade protocol: {masquerade_type}")

        try:
            await vpn_server.start()
            click.echo(f"[+] VPN server is running")
            click.echo("[+] Press Ctrl+C to stop")

            # Periodically print status
            while True:
                await asyncio.sleep(10)
                count = vpn_server.client_count
                if count > 0:
                    click.echo(f"[*] Active clients: {count}")

        except KeyboardInterrupt:
            click.echo("\n[*] Stopping server...")
        except Exception as e:
            click.echo(f"[!] Error: {e}", err=True)
            sys.exit(1)
        finally:
            await vpn_server.stop()
            click.echo("[+] Server stopped")

    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        click.echo("\n[+] Shutting down...")


@cli.command()
@click.option("--output", "-o", default="keypair.json", help="Output file for key pair")
@click.option("--private-only", is_flag=True, help="Only export private key")
def keygen(output, private_only):
    """
    Generate a new key pair.

    Creates a X25519 key pair for VPN authentication.
    """
    keypair = KeyPair.generate()

    private_bytes = keypair.private_bytes()
    public_bytes = keypair.public_bytes()

    click.echo(f"[+] Generated new key pair")
    click.echo(f"[+] Private key ({len(private_bytes)} bytes): {private_bytes.hex()[:32]}...")
    click.echo(f"[+] Public key ({len(public_bytes)} bytes): {public_bytes.hex()[:32]}...")

    # Save to file if requested
    if output:
        import json

        data = {
            "private_key": private_bytes.hex(),
            "public_key": public_bytes.hex(),
        }

        if private_only:
            del data["public_key"]

        with open(output, "w") as f:
            json.dump(data, f, indent=2)

        click.echo(f"[+] Saved to {output}")


@cli.command()
def version():
    """Show version information."""
    click.echo(f"Sunbeam-M version {__version__}")
    click.echo(f"Python {sys.version}")


@cli.command()
def protocols():
    """List available masquerade protocols."""
    click.echo("Available masquerade protocols:")
    click.echo("  tls    - TLS 1.3 masquerade (realistic ClientHello)")
    click.echo("  ssh    - SSH-2.0 masquerade (protocol version + KEX)")
    click.echo("  http   - HTTP/1.1 masquerade (chunked transfer encoding)")
    click.echo("  soup   - Protocol soup (random rotation between all)")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

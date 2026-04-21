"""
Domain fronting transport for Sunbeam-M VPN.

Hides the true destination of VPN traffic by routing through CDNs/proxies.
Supports HTTP/HTTPS CONNECT proxies and SNI-based domain fronting.
"""

import asyncio
import ssl
from typing import Optional

import aiohttp

from sunbeam_m.transport.tcp import TCPTransport


class DomainFrontingTransport:
    """
    Transport that uses domain fronting to hide the true destination.

    Domain fronting works by:
    1. Making a TLS connection to a CDN/proxy with SNI of a benign domain
    2. Sending HTTP requests with Host header pointing to the benign domain
    3. But the actual data is destined for the hidden VPN server

    This is implemented via CONNECT proxies or HTTP tunneling.
    """

    # Common CDN fronting domains (examples)
    FRONTING_DOMAINS = [
        "www.cloudflare.com",
        "www.amazon.com",
        "www.microsoft.com",
        "content.googleapis.com",
        "ajax.googleapis.com",
    ]

    def __init__(
        self,
        frontend_domain: str | None = None,
        frontend_host: str | None = None,
        frontend_port: int = 443,
        true_host: str | None = None,
        true_port: int | None = None,
        use_https: bool = True,
    ):
        """
        Initialize domain fronting transport.

        Args:
            frontend_domain: Domain for SNI (what censor sees)
            frontend_host: Frontend server hostname
            frontend_port: Frontend server port
            true_host: True VPN server hostname (hidden in Host header or path)
            true_port: True VPN server port
            use_https: Use HTTPS for frontend connection
        """
        self.frontend_domain = frontend_domain or self.FRONTING_DOMAINS[0]
        self.frontend_host = frontend_host or self.frontend_domain
        self.frontend_port = frontend_port
        self.true_host = true_host
        self.true_port = true_port or 443
        self.use_https = use_https

        self._session: Optional[aiohttp.ClientSession] = None
        self._socket: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    @property
    def frontend_url(self) -> str:
        """Get the frontend URL."""
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.frontend_host}:{self.frontend_port}"

    async def connect_via_connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect using HTTP CONNECT method.

        This sends a CONNECT request to the frontend server,
        which then proxies the connection to the true destination.

        Returns:
            Tuple of (reader, writer) for the tunneled connection

        Raises:
            ConnectionError: If connection fails
        """
        # Connect to frontend server
        reader, writer = await asyncio.open_connection(
            self.frontend_host,
            self.frontend_port,
            ssl=self.use_https,
        )

        # Send CONNECT request
        connect_request = (
            f"CONNECT {self.true_host}:{self.true_port} HTTP/1.1\r\n"
            f"Host: {self.frontend_domain}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
        )

        writer.write(connect_request.encode())
        await writer.drain()

        # Read response
        response_line = await reader.readline()
        if not response_line:
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("No response from CONNECT proxy")

        # Check for 200 OK
        if b"200" not in response_line:
            writer.close()
            await writer.wait_closed()
            raise ConnectionError(f"CONNECT failed: {response_line.decode()}")

        # Skip headers until empty line
        while True:
            line = await reader.readline()
            if line == b"\r\n" or line == b"\n":
                break

        return reader, writer

    async def connect_via_http_tunnel(self) -> aiohttp.ClientResponse:
        """
        Connect using HTTP tunneling via POST requests.

        Data is sent as the body of HTTP POST requests.
        The Host header uses the frontend domain while the URL path
        encodes the true destination.

        Returns:
            aiohttp response object

        Raises:
            ConnectionError: If connection fails
        """
        if self._session is None:
            # Create session with SSL context that doesn't verify
            # (we're connecting to frontend, not true host)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            connector = aiohttp.TCPConnector(ssl=ssl_context)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )

        # Path encodes true destination
        path = f"/tunnel/{self.true_host}/{self.true_port}"

        headers = {
            "Host": self.frontend_domain,
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/octet-stream",
            "X-Fronted-Request": "true",
        }

        try:
            # Initiate tunnel with empty POST
            async with self._session.post(
                f"{self.frontend_url}{path}",
                headers=headers,
                data=b"",
            ) as response:
                if response.status != 200:
                    raise ConnectionError(
                        f"HTTP tunnel failed: {response.status}"
                    )
                return response

        except aiohttp.ClientError as e:
            raise ConnectionError(f"HTTP tunnel failed: {e}")

    async def send_via_http(self, data: bytes) -> None:
        """
        Send data via HTTP POST requests.

        Args:
            data: Data to send

        Raises:
            ConnectionError: If send fails
        """
        if self._session is None:
            await self.connect_via_http_tunnel()

        path = f"/tunnel/{self.true_host}/{self.true_port}"

        headers = {
            "Host": self.frontend_domain,
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/octet-stream",
        }

        try:
            async with self._session.post(
                f"{self.frontend_url}{path}",
                headers=headers,
                data=data,
            ) as response:
                if response.status != 200:
                    raise ConnectionError(f"Send failed: {response.status}")

        except aiohttp.ClientError as e:
            raise ConnectionError(f"Send via HTTP failed: {e}")

    async def receive_via_http(self) -> bytes:
        """
        Receive data via HTTP GET requests.

        Returns:
            Received data

        Raises:
            ConnectionError: If receive fails
        """
        if self._session is None:
            await self.connect_via_http_tunnel()

        path = f"/tunnel/{self.true_host}/{self.true_port}/poll"

        headers = {
            "Host": self.frontend_domain,
            "User-Agent": "Mozilla/5.0",
        }

        try:
            async with self._session.get(
                f"{self.frontend_url}{path}",
                headers=headers,
            ) as response:
                if response.status != 200:
                    raise ConnectionError(f"Receive failed: {response.status}")

                return await response.read()

        except aiohttp.ClientError as e:
            raise ConnectionError(f"Receive via HTTP failed: {e}")

    async def close(self) -> None:
        """Close the domain fronting connection."""
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
            self._writer = None

        if self._session:
            await self._session.close()
            self._session = None


class SNIWrapper:
    """
    Wrapper for TCP transport that adds SNI-based domain fronting.

    Modifies the TLS handshake to use a different SNI than the actual destination.
    """

    def __init__(
        self,
        transport: TCPTransport,
        sni_hostname: str | None = None,
    ):
        """
        Initialize SNI wrapper.

        Args:
            transport: Base TCP transport
            sni_hostname: Hostname to use in SNI (if different from destination)
        """
        self.transport = transport
        self.sni_hostname = sni_hostname or transport.host

    async def connect_with_sni(self) -> None:
        """
        Connect using custom SNI.

        Creates a TLS connection with SNI set to sni_hostname
        while connecting to the actual transport destination.

        Raises:
            ConnectionError: If connection fails
        """
        # Create SSL context with custom SNI
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Wrap the socket with SSL
        reader, writer = await asyncio.open_connection(
            self.transport.host,
            self.transport.port,
            ssl=ssl_context,
            server_hostname=self.sni_hostname,
        )

        self.transport._reader = reader
        self.transport._writer = writer
        self.transport.state = self.transport.__class__.ConnectionState.CONNECTED

    async def disconnect(self) -> None:
        """Disconnect the transport."""
        await self.transport.disconnect()


class FrontingConfig:
    """Configuration for domain fronting."""

    # CloudFlare fronting configuration
    CLOUDFLARE = {
        "frontend_host": "www.cloudflare.com",
        "frontend_port": 443,
        "cdn_ip": "1.1.1.1",  # Direct IP to bypass DNS
    }

    # Google App Engine fronting
    GOOGLE_APPENGINE = {
        "frontend_host": "www.google.com",
        "frontend_port": 443,
        "appspot_host": "your-app.appspot.com",
    }

    # Amazon CloudFront fronting
    CLOUDFRONT = {
        "frontend_host": "d123456.cloudfront.net",
        "frontend_port": 443,
        "sni_domain": "www.amazonaws.com",
    }

    @classmethod
    def get_config(cls, name: str) -> dict:
        """
        Get a fronting configuration by name.

        Args:
            name: Configuration name (cloudflare, google, cloudfront)

        Returns:
            Configuration dictionary

        Raises:
            KeyError: If configuration not found
        """
        configs = {
            "cloudflare": cls.CLOUDFLARE,
            "google": cls.GOOGLE_APPENGINE,
            "cloudfront": cls.CLOUDFRONT,
        }

        return configs[name.lower()].copy()

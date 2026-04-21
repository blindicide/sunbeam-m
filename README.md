# Sunbeam-M: Censorship-Resistant Masquerading VPN

> **Warning**: This is a research/POC implementation. Not ready for production use.

Sunbeam-M is a VPN protocol that uses "protocol soup" masquerading to resist censorship. Traffic is wrapped in realistic-looking protocol frames (TLS, SSH, HTTP) that rotate randomly, with domain fronting support for hiding the true destination.

## Features

- **Protocol Soup Masquerading**: Randomly rotates between TLS 1.3, SSH-2.0, and HTTP/1.1
- **Domain Fronting**: Routes traffic through CDNs to hide true destination
- **Modern Cryptography**: ChaCha20-Poly1305 AEAD, X25519 ECDH, HKDF-SHA256
- **Traffic Analysis Resistance**: Variable padding, random timing jitter
- **Async I/O**: Built on asyncio for efficient concurrent connections
- **GUI Client**: Simple tkinter-based graphical interface
- **Server Controls**: Interactive terminal commands for server management

## Installation

### Prerequisites

- **Python 3.10 or higher**
- **Linux** (for TUN/TAP support)
- **Root privileges** (for TUN device creation and network configuration)
- **tkinter** (for GUI client, usually pre-installed)

### Step 1: Install System Dependencies

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip python3-tkinter
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip tk
```

### Step 2: Clone and Install

```bash
# Clone the repository
git clone https://github.com/username/sunbeam-m.git
cd sunbeam-m

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Step 3: Verify Installation

```bash
sunbeam version
# Output: Sunbeam-M version 0.1.0-alpha.1
```

## Usage

### Quick Start

1. **Start the server** (on your VPS/cloud server):
   ```bash
   sudo sunbeam server 8443
   ```

2. **Start the client** (on your local machine):
   ```bash
   sudo sunbeam client your-server.com 8443 --route 0.0.0.0/0
   ```

### Server Modes

#### Basic Server (Simple)
```bash
sudo sunbeam server 8443
```

#### Server with Interactive Controls
```bash
sudo sunbeam server-ctrl --host 0.0.0.0 --port 8443
```

**Available commands in server-ctrl mode:**
- `status` - Show server status and uptime
- `clients` - List all connected clients with details
- `kick <client_id>` - Disconnect a specific client
- `stats` - Show server statistics
- `network` - Show VPN network information
- `help` - Show all available commands
- `quit` - Shutdown the server

### Client Modes

#### Command Line Client
```bash
# Basic connection
sudo sunbeam client example.com 8443

# Route all traffic through VPN
sudo sunbeam client example.com 8443 --route 0.0.0.0/0

# Custom VPN IP
sudo sunbeam client example.com 8443 --vpn-ip 10.10.0.50

# Specific masquerade protocol
sudo sunbeam client example.com 8443 --masquerade tls

# Set custom DNS
sudo sunbeam client example.com 8443 --dns 1.1.1.1 --dns 8.8.8.8
```

#### GUI Client
```bash
sudo sunbeam gui
```

The GUI provides:
- Connection configuration (server, port, protocol)
- Connect/Disconnect buttons
- Real-time status display
- Traffic statistics (sent/received bytes)
- Connection log

## Configuration

### Server Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 0.0.0.0 | Bind address |
| `--port` | 8443 | Bind port |
| `--vpn-network` | 10.10.0.0/24 | VPN network CIDR |
| `--vpn-host` | 10.10.0.1 | Server's VPN IP |
| `--masquerade` | soup | Masquerade protocol |

### Client Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--vpn-ip` | 10.10.0.2 | Client's VPN IP |
| `--vpn-netmask` | 255.255.255.0 | VPN netmask |
| `--masquerade` | soup | Masquerade protocol |
| `--route` | None | Route to add through VPN |
| `--dns` | None | DNS servers to use |

## Masquerade Protocols

| Protocol | Description |
|----------|-------------|
| `tls` | TLS 1.3 with realistic ClientHello/ServerHello |
| `ssh` | SSH-2.0 with protocol version and KEXINIT |
| `http` | HTTP/1.1 with chunked transfer encoding |
| `soup` | Random rotation between all protocols (default) |

## Key Management

Generate a key pair for authentication:

```bash
# Generate and save to file
sunbeam keygen -o keypair.json

# Generate and display only
sunbeam keygen
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Application ──► TUN ──► Encrypt ──► Masquerade ──► Domain Fronting ──► TCP │
│                    ◄──── TUN ◄──── Decrypt ◄──── Decode ◄──── TCP ◄─────   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SERVER                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  TCP ──► Domain Fronting ──► Decode ──► Decrypt ──► TUN ──► Network       │
│  ◄──── TCP ◄──── Encode ◄──── Encrypt ◄──── TUN ◄──── Network ◄─────      │
└─────────────────────────────────────────────────────────────────────────────┘
```

See [OVERVIEW.md](OVERVIEW.md) for detailed architecture documentation.

## Troubleshooting

### TUN Device Permission Denied
```bash
# Add user to tun/tap group (if applicable)
sudo usermod -aG tun $USER

# Or run with sudo
sudo sunbeam client example.com 8443
```

### Cannot Import GUI (tkinter)
```bash
# Install tkinter
sudo apt install python3-tk  # Debian/Ubuntu
sudo dnf install python3-tkinter  # Fedora
```

### Connection Refused
- Check server is running: `sudo netstat -tlnp | grep 8443`
- Verify firewall allows port 8443
- Check server logs for errors

### sudo: sunbeam: command not found
If `sudo sunbeam` fails but `sunbeam` works without sudo, it's because sudo's `secure_path` doesn't include your local bin directory. Workarounds:

```bash
# Option 1: Use Python module directly (recommended)
sudo /path/to/venv/bin/python -m sunbeam_m.cli.main client example.com 8443

# Option 2: Full path to sunbeam script
sudo ~/.local/bin/sunbeam client example.com 8443

# Option 3: Preserve PATH with sudo
sudo PATH="$PATH" sunbeam client example.com 8443
```

## Security Considerations

- **Forward secrecy**: Ephemeral X25519 ECDH per session
- **Authentication**: Pre-shared public keys
- **Replay protection**: Packet counters + timestamps
- **No protocol leaks**: Masquerade protocols pass real parser checks

**This is a research/POC implementation. Security properties have not been audited.**

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest --cov=sunbeam_m tests/
```

### Code Style

```bash
# Format with black
black sunbeam_m/

# Lint with ruff
ruff check sunbeam_m/

# Type checking with mypy (optional)
mypy sunbeam_m/
```

## All Commands

```
sunbeam client <server> <port>     Start VPN client (CLI)
sunbeam server <port>               Start VPN server (simple)
sunbeam server-ctrl                 Start VPN server (interactive)
sunbeam gui                         Launch GUI client
sunbeam keygen                      Generate key pair
sunbeam protocols                   List masquerade protocols
sunbeam version                     Show version
```

## License

MIT

## Contributing

Contributions welcome! Please read CLAUDE.md for coding standards.

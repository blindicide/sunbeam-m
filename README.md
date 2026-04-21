# Sunbeam-M: Censorship-Resistant Masquerading VPN

> **Warning**: This is a research/POC implementation. Not ready for production use.

Sunbeam-M is a VPN protocol that uses "protocol soup" masquerading to resist censorship. Traffic is wrapped in realistic-looking protocol frames (TLS, SSH, HTTP) that rotate randomly, with domain fronting support for hiding the true destination.

## Features

- **Protocol Soup Masquerading**: Randomly rotates between TLS 1.3, SSH-2.0, and HTTP/1.1
- **Domain Fronting**: Routes traffic through CDNs to hide true destination
- **Modern Cryptography**: ChaCha20-Poly1305 AEAD, X25519 ECDH, HKDF-SHA256
- **Traffic Analysis Resistance**: Variable padding, random timing jitter
- **Async I/O**: Built on asyncio for efficient concurrent connections

## Installation

```bash
# Clone the repository
git clone https://github.com/username/sunbeam-m.git
cd sunbeam-m

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Requirements

- Python 3.10+
- Root privileges (for TUN device)
- Linux (for TUN/TAP support)

## Usage

### Server

```bash
sudo sunbeam server 8443
```

### Client

```bash
# Basic connection
sudo sunbeam client example.com 8443

# With routing (all traffic through VPN)
sudo sunbeam client example.com 8443 --route 0.0.0.0/0

# With custom VPN IP
sudo sunbeam client example.com 8443 --vpn-ip 10.10.0.2

# With specific masquerade protocol
sudo sunbeam client example.com 8443 --masquerade tls
```

### Key Generation

```bash
sunbeam keygen -o keypair.json
```

### Available Commands

- `sunbeam client <server> <port>` - Start VPN client
- `sunbeam server <port>` - Start VPN server
- `sunbeam keygen` - Generate key pair
- `sunbeam protocols` - List masquerade protocols
- `sunbeam version` - Show version

## Masquerade Protocols

| Protocol | Description |
|----------|-------------|
| `tls` | TLS 1.3 with realistic ClientHello/ServerHello |
| `ssh` | SSH-2.0 with protocol version and KEXINIT |
| `http` | HTTP/1.1 with chunked transfer encoding |
| `soup` | Random rotation between all protocols (default) |

## Architecture

```
Client: Application → TUN → Encrypt → Masquerade → Domain Fronting → TCP
                                                                  │
                                                                  ▼
Server: TCP → Domain Fronting → Decode → Decrypt → TUN → Network
```

See [OVERVIEW.md](OVERVIEW.md) for detailed architecture documentation.

## Security Considerations

- **Forward secrecy**: Ephemeral X25519 ECDH per session
- **Authentication**: Pre-shared public keys
- **Replay protection**: Packet counters + timestamps
- **No protocol leaks**: Masquerade protocols pass real parser checks

This is a research/POC implementation. Security properties have not been audited.

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Style

```bash
# Format with black
black sunbeam_m/

# Lint with ruff
ruff check sunbeam_m/
```

## License

MIT

## Contributing

Contributions welcome! Please read CLAUDE.md for coding standards.

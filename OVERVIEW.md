# Sunbeam-M: Architecture Overview

## Summary

Sunbeam-M is a censorship-resistant VPN protocol that uses protocol masquerading to bypass deep packet inspection. It wraps VPN traffic in realistic-looking protocol frames (TLS, SSH, HTTP) that rotate randomly, with domain fronting support for hiding the true destination.

## High-Level Architecture

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

## Directory Structure

```
sunbeam-m/
├── sunbeam_m/              # Main package
│   ├── __init__.py         # Package exports
│   ├── __about__.py        # Version info
│   ├── core/               # Core VPN protocol
│   │   ├── crypto.py       # Encryption (ChaCha20-Poly1305)
│   │   ├── framing.py      # Packet framing format
│   │   └── protocol.py     # Core protocol logic
│   ├── masquerade/         # Protocol masquerading
│   │   ├── base.py         # Base interface
│   │   ├── tls.py          # TLS 1.3 masquerade
│   │   ├── ssh.py          # SSH-2.0 masquerade
│   │   ├── http.py         # HTTP/1.1 masquerade
│   │   └── soup.py         # Protocol rotator
│   ├── transport/          # Transport layer
│   │   ├── tcp.py          # TCP transport
│   │   └── domain_front.py # Domain fronting
│   ├── client/             # VPN client
│   │   └── vpn_client.py   # Client implementation
│   ├── server/             # VPN server
│   │   └── vpn_server.py   # Server implementation
│   └── cli/                # Command-line interface
│       └── main.py         # CLI commands
├── tests/                  # Test suite
├── requirements.txt        # Dependencies
└── pyproject.toml         # Package config
```

## Key Components

### Core (`core/`)

| Component | Description |
|-----------|-------------|
| `crypto.py` | ChaCha20-Poly1305 AEAD encryption, X25519 ECDH key exchange, HKDF-SHA256 key derivation, replay protection |
| `framing.py` | Binary packet format with length prefix, nonce, ciphertext, and variable padding |
| `protocol.py` | Core protocol logic combining crypto and framing |

### Masquerade (`masquerade/`)

| Component | Description |
|-----------|-------------|
| `base.py` | Abstract `MasqueradeProtocol` class with state machine |
| `tls.py` | Realistic TLS 1.3 ClientHello/ServerHello, application data records |
| `ssh.py` | SSH-2.0 version string, KEXINIT, binary packet encoding |
| `http.py` | HTTP/1.1 POST with chunked transfer encoding |
| `soup.py` | Random protocol selection per packet |

### Transport (`transport/`)

| Component | Description |
|-----------|-------------|
| `tcp.py` | Async TCP sockets with reconnection and keepalive |
| `domain_front.py` | HTTP CONNECT proxy, SNI-based domain fronting |

### Client/Server

| Component | Description |
|-----------|-------------|
| `vpn_client.py` | TUN device creation, packet forwarding, routing |
| `vpn_server.py` | Multi-client support, session management, NAT |

## Entry Points

- **CLI**: `sunbeam client <server> <port>` or `sunbeam server <port>`
- **Library**: `from sunbeam_m import VPNClient, VPNServer`

## Key Public Functions/Classes

| Class | Purpose |
|-------|---------|
| `KeyPair` | X25519 key pair for authentication |
| `KeyExchange` | ECDH key exchange with forward secrecy |
| `CipherSuite` | ChaCha20-Poly1305 AEAD cipher |
| `FrameEncoder/Decoder` | Packet framing (length prefix, nonce, ciphertext, padding) |
| `MasqueradeProtocol` | Base class for protocol masquerading |
| `ProtocolSoup` | Random protocol rotator |
| `VPNClient` | VPN client with TUN integration |
| `VPNServer` | Multi-client VPN server |

## Security Properties

- **Forward secrecy**: Ephemeral X25519 ECDH per session
- **Authentication**: Pre-shared public keys
- **Replay protection**: Packet counters + timestamps
- **Traffic analysis resistance**: Variable padding, random timing jitter
- **No protocol leaks**: Masquerade protocols pass real parser checks

## Start Here

1. To **run** the VPN:
   ```bash
   # Server
   sudo sunbeam server 8443

   # Client
   sudo sunbeam client example.com 443 --route 0.0.0.0/0
   ```

2. To **develop**:
   - Start with `core/crypto.py` - the cryptographic foundation
   - Then `core/framing.py` - packet format
   - Then `masquerade/` - protocol masquerading

3. **Gotchas**:
   - TUN device requires root privileges
   - Domain fronting requires compatible CDN/HTTP proxy
   - Protocol soup requires careful state management per packet

# Changelog

All notable changes to Sunbeam-M will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-04-21

### Added
- Initial release of Sunbeam-M VPN protocol
- ChaCha20-Poly1305 AEAD encryption layer
- X25519 ECDH key exchange with forward secrecy
- HKDF-SHA256 key derivation
- Replay protection via packet counters and timestamps
- Binary packet framing with length prefix and variable padding
- TLS 1.3 masquerade protocol
- SSH-2.0 masquerade protocol
- HTTP/1.1 masquerade protocol
- Protocol soup masquerade (random rotation)
- Async TCP transport with reconnection
- Domain fronting support (HTTP CONNECT, SNI)
- VPN client with TUN device integration
- Multi-client VPN server
- Command-line interface
- Unit tests for crypto, framing, and masquerade

### Security
- Forward secrecy via ephemeral ECDH
- Authentication via pre-shared public keys
- Replay protection on decrypted packets
- Traffic analysis resistance via padding

[Unreleased]: https://github.com/username/sunbeam-m/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/username/sunbeam-m/releases/tag/v0.1.0-alpha.1

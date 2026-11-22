# HelloVPN

**HelloVPN (HVPN)** is an independent, open-source VPN protocol and implementation written in Rust.

> ⚠️ **Status: Pre-alpha / Research.** This software has NOT been audited by independent security researchers. Do not use in production. See [SECURITY.md](SECURITY.md).

---

## Design Goals

- **Mutual authentication** — both client and server verify each other's identity
- **Forward secrecy** — session key compromise does not expose past traffic
- **Memory safety** — implemented in Rust with no custom cryptography
- **Cross-platform** — Linux, macOS, Windows, Android, iOS
- **Simple configuration** — human-readable `.hvpn` config files

## Technology

| Component       | Technology                              |
|-----------------|-----------------------------------------|
| Language        | Rust (2021 edition)                     |
| Async runtime   | Tokio                                   |
| Handshake       | Noise IK (snow crate)                   |
| DH              | X25519                                  |
| AEAD            | ChaCha20-Poly1305                       |
| Hash/PRF        | BLAKE2s                                 |
| Transport       | UDP (primary), TCP (fallback)           |

## Workspace

```
crates/hello-protocol/   # Packet format + Noise handshake (exists)
crates/hello-core/       # Shared types and errors (phase 3)
crates/hello-crypto/     # AEAD, nonce, replay window (phase 3)
crates/hello-transport/  # UDP/TCP socket layer (phase 6)
crates/hello-session/    # Session state machine (phase 8)
crates/hello-tun/        # TUN adapter (phase 9)
...
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture.
See [docs/PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) for the protocol specification.

## Development Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Workspace architecture, bug fixes, docs | ✅ Complete |
| 2 | Protocol specification | ✅ Complete |
| 3 | hello-core + hello-crypto | 🔜 Next |
| 4–19 | See ARCHITECTURE.md | ⏳ Planned |

## Building

```bash
# Check all crates compile
cargo check

# Run all tests
cargo test

# Run specific crate tests
cargo test -p hello-protocol
```

## License

Licensed under either of:
- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

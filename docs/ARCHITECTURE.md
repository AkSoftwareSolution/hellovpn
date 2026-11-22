# HelloVPN — Architecture

> **Status**: Phase 1 — Workspace Architecture & Specification
> **Last updated**: 2026-11-21
> **Protocol version**: HVPN/1

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Layer Model](#2-layer-model)
3. [Workspace Structure](#3-workspace-structure)
4. [Crate Responsibilities](#4-crate-responsibilities)
5. [Dependency Graph](#5-dependency-graph)
6. [Existing Crate Audit](#6-existing-crate-audit)
7. [Missing Components](#7-missing-components)
8. [Implementation Phases](#8-implementation-phases)
9. [Platform Strategy](#9-platform-strategy)
10. [Security Boundaries](#10-security-boundaries)

---

## 1. Design Philosophy

| Invariant | Rationale |
|-----------|-----------|
| No custom cryptography | Only audited crates (snow, ring, aes-gcm) |
| Layered separation | Each crate has one concern; no cross-layer leakage |
| Incremental delivery | Each phase is independently testable and mergeable |
| Honest security claims | No "production ready" claim without independent audit |
| Memory safety | Rust throughout; unsafe blocks documented and minimised |
| Zero allocation in hot path | Packet encode/decode uses pre-allocated byte buffers |

---

## 2. Layer Model

```
+-----------------------------------------------------+
|  Layer 1 - Application                              |
|  hello-cli . hello-config                           |
|  hvpn . hvpn-server . hvpn-client                   |
+-----------------------------------------------------+
|  Layer 2 - Control Plane                            |
|  hello-session . hello-handshake                    |
|  Session lifecycle, key rotation, keepalive         |
+-----------------------------------------------------+
|  Layer 3 - Security                                 |
|  hello-crypto . hello-handshake                     |
|  Noise IK, AEAD, HKDF, replay window, nonce mgmt   |
+-----------------------------------------------------+
|  Layer 4 - Transport                                |
|  hello-transport . hello-packet                     |
|  UDP primary . TCP fallback . framing . timeouts    |
+-----------------------------------------------------+
|  Layer 5 - Tunnel                                   |
|  hello-tun . hello-routing                          |
|  TUN interface . IP forwarding . MTU . DNS          |
+-----------------------------------------------------+
```

---

## 3. Workspace Structure

```
hellovpn/
|
+-- Cargo.toml                  # Workspace root
+-- Cargo.lock
+-- README.md
+-- LICENSE-MIT
+-- LICENSE-APACHE
+-- SECURITY.md
+-- CONTRIBUTING.md
|
+-- crates/
|   +-- hello-core/             # Shared types, errors, constants
|   +-- hello-protocol/         # EXISTS - packet format + Noise handshake
|   +-- hello-crypto/           # Key derivation, AEAD wrappers, nonce mgmt
|   +-- hello-transport/        # UDP/TCP socket abstraction
|   +-- hello-session/          # Session state machine, keepalive, rekeying
|   +-- hello-packet/           # Packet builder/parser (typed API over raw bytes)
|   +-- hello-handshake/        # High-level handshake orchestration (async)
|   +-- hello-config/           # .hvpn / .toml parsing and validation
|   +-- hello-tun/              # TUN adapter (platform-specific features)
|   +-- hello-routing/          # Route/DNS management
|   +-- hello-client/           # Client connection logic
|   +-- hello-server/           # Server accept loop, peer registry
|   +-- hello-cli/              # clap CLI, dialoguer, indicatif
|
+-- apps/
|   +-- hvpn/                   # Main CLI binary
|   +-- hvpn-server/            # Server binary
|   +-- hvpn-client/            # Client binary
|
+-- configs/
|   +-- server.example.toml
|   +-- client.example.hvpn
|
+-- docs/
|   +-- ARCHITECTURE.md         # <- this file
|   +-- PROTOCOL_SPEC.md
|   +-- SECURITY_MODEL.md
|   +-- HANDSHAKE.md
|   +-- PACKET_FORMAT.md
|   +-- DEPLOYMENT.md
|
+-- tests/
    +-- integration/
    +-- interoperability/
    +-- security/
```

---

## 4. Crate Responsibilities

### hello-core
Zero-dependency shared foundation.
- Protocol constants (MAGIC, VERSION, HEADER_SIZE, MAX_PAYLOAD_SIZE)
- Shared error types (ProtocolError, CryptoError, SessionError, TransportError)
- Common traits (Encode, Decode)
- Identifier types (SessionId, SequenceNumber, PeerId)
- Dependencies: thiserror, bytes

### hello-protocol (EXISTS)
Raw packet format and low-level Noise handshake.
- lib.rs: Packet, PacketType, encode/decode, 8 unit tests PASSING
- handshake.rs: generate_static_keypair, create_server/client_handshake, 6 tests PASSING
- Dependencies: snow

### hello-crypto
Cryptographic primitives layer.
- KeyPair: X25519 static key management (load/save/zeroize)
- SessionKeys: derived keys from completed Noise handshake
- AeadCipher: ChaCha20-Poly1305 encrypt/decrypt with counter nonce
- NonceCounter: monotonically increasing nonce, panic-on-wrap safety
- HkdfDeriver: HKDF-SHA256 key expansion
- ReplayWindow: 64-bit sliding bitmap for sequence number deduplication
- Dependencies: snow, ring, zeroize, rand_core, thiserror

### hello-transport
Async socket abstraction over UDP and TCP.
- Transport trait: send, recv, peer_addr
- UdpTransport: primary transport using tokio::net::UdpSocket
- TcpTransport: fallback framed with length prefix (tokio_util::codec)
- Dependencies: tokio, tokio-util, bytes, anyhow

### hello-packet
Typed, ergonomic API over raw hello-protocol wire format.
- PacketBuilder: builds typed packets from application data
- PacketParser: validates and decodes incoming byte frames
- Associates AEAD context (encrypts/decrypts payload inline)
- Handles AAD construction (header bytes as associated data)
- Dependencies: hello-protocol, hello-crypto, bytes

### hello-handshake
Async orchestration of the Noise IK handshake over a transport.
- HandshakeInitiator: drives client side, times out in 5s
- HandshakeResponder: drives server side, validates client identity
- Server-side client allow-list lookup
- Outputs SessionKeys on success
- Dependencies: hello-protocol, hello-crypto, hello-transport, tokio, tracing

### hello-session
Session state machine.

  Connecting -> Handshaking -> Active -> Rekeying -> Closed

- Session: holds SessionKeys, nonce counter, replay window, stats
- SessionManager: concurrent map of SessionId -> Session
- Keepalive timer (default 25s)
- Rekey trigger (at 2^60 messages or 1h wall clock, whichever first)
- Dependencies: hello-crypto, hello-packet, tokio, dashmap, tracing

### hello-config
Parse, validate and generate .hvpn and .toml configs.
- ClientConfig: connection params, security params, network params
- ServerConfig: listen address, peer allow-list, TUN config
- Never serialises private keys to distributable configs
- Dependencies: serde, toml, base64, thiserror

### hello-tun
Platform-specific TUN adapter.
- TunDevice trait: send_ip_packet, recv_ip_packet, mtu
- LinuxTun: via tun crate
- AndroidTun: file-descriptor based (from VpnService)
- WindowsTun: Wintun via FFI
- MacOsTun/IosTun: utun socket
- Dependencies: tun (Linux), platform-specific FFI

### hello-routing
Routing and DNS management.
- Add/remove routes via netlink (Linux) or platform equivalents
- DNS push (resolv.conf or systemd-resolved)
- Kill switch (default-route override, iptables/nftables)
- IPv4 and IPv6 support
- Dependencies: netlink-packet-route, tokio

### hello-client
Client connection engine.
- Resolves server address, opens transport, drives handshake
- Manages session lifecycle, reconnect with exponential backoff
- Reads from TUN, encrypts, sends; receives, decrypts, writes to TUN
- Dependencies: hello-handshake, hello-session, hello-tun, hello-routing

### hello-server
Server accept loop.
- Binds UDP/TCP sockets
- Dispatches packets to per-session tasks
- Peer registry (public key -> session)
- Rate limiting per source IP
- Concurrent session support via tokio tasks
- Dependencies: hello-handshake, hello-session, hello-tun, hello-routing

### hello-cli
Command-line interface (clap, dialoguer, indicatif).
Commands:
  hvpn server install | start | stop | status
  hvpn client generate-config | connect | disconnect | status
  hvpn key generate | show
  hvpn version

---

## 5. Dependency Graph

```
                         hello-core
                        /    |    \
              hello-protocol |     \
              /      \       |      \
    hello-crypto  hello-packet  hello-config
         \            /               |
          hello-transport        hello-session
               \          /          |
            hello-handshake    hello-tun + hello-routing
                      \            /
                    hello-client / hello-server
                             \   /
                          hello-cli
                         /    |    \
                       hvpn  hvpn-server  hvpn-client
```

Rule: lower crates must never import higher crates (no upward deps).

---

## 6. Existing Crate Audit

| Crate | Status | Notes |
|-------|--------|-------|
| hello-protocol | COMPILES (after fix) | 14 tests passing |
| Root hellovpn binary | STUB | main.rs prints Hello only |
| src/cli/ | EMPTY | No implementation |
| src/client/ | EMPTY | No implementation |
| src/server/ | EMPTY | No implementation |
| src/configs/ | EMPTY | No implementation |

Bugs fixed in Phase 1:
1. Duplicate create_server_handshake / create_client_handshake (removed bad copies)
2. Missing ? on snow::Builder method chain (.local_private_key()?, .remote_public_key()?)

---

## 7. Missing Components

| Component | Priority | Phase |
|-----------|----------|-------|
| hello-core | Critical | 1 |
| hello-crypto | Critical | 3 |
| hello-transport | Critical | 6 |
| hello-session | High | 8 |
| hello-packet | High | 5 |
| hello-handshake | High | 4 |
| hello-config | High | 14 |
| hello-tun | High | 9 |
| hello-routing | Medium | 10 |
| hello-client | High | 12 |
| hello-server | High | 11 |
| hello-cli | Medium | 14 |
| Android platform | Low | 15 |
| Windows platform | Low | 16 |
| macOS/iOS platform | Low | 17 |

---

## 8. Implementation Phases

| Phase | Deliverable |
|-------|-------------|
| 1 | Workspace architecture, docs, bug fixes (CURRENT) |
| 2 | Protocol specification, packet format spec |
| 3 | hello-core + hello-crypto crates |
| 4 | Async handshake (hello-handshake) |
| 5 | Typed packet API (hello-packet) + replay window |
| 6 | UDP transport (hello-transport) |
| 7 | Replay protection integration + sequence tests |
| 8 | Session state machine (hello-session) |
| 9 | Linux TUN (hello-tun) |
| 10 | IP routing + DNS (hello-routing) |
| 11 | Linux VPN server (hello-server) |
| 12 | Linux VPN client (hello-client) |
| 13 | TCP fallback transport |
| 14 | CLI + .hvpn config (hello-cli, hello-config) |
| 15 | Android integration |
| 16 | Windows integration |
| 17 | macOS/iOS integration |
| 18 | Performance, fuzzing, benchmarks |
| 19 | Security audit, interoperability |

---

## 9. Platform Strategy

```
  hello-core / hello-crypto / hello-protocol
  (pure Rust, no OS calls, all platforms)
            |
  hello-transport / hello-session
  (tokio - Linux, macOS, Windows, Android)
            |
  hello-tun  (feature-gated per platform)
  +-- linux   -> tun crate / TUN/TAP ioctl
  +-- android -> Java JNI -> VpnService fd
  +-- ios     -> NetworkExtension NE tunnel
  +-- windows -> Wintun FFI
  +-- macos   -> utun socket
```

---

## 10. Security Boundaries

```
  TRUST BOUNDARY: Internet (untrusted)
  All bytes arriving on UDP/TCP treated as adversarial.
            |
            v  parse + validate + decrypt
  TRUST BOUNDARY: Session (authenticated)
  Bytes survived Noise IK auth, AEAD decryption, replay check.
            |
            v  IP packet forwarding
  TRUST BOUNDARY: TUN (local network)
  Plain IP packets routed into the kernel.
```

Known limitations (Phase 1):
- No revocation mechanism for compromised client keys
- No certificate authority; TOFU trust model for now
- No DoS rate limiting yet (Phase 11)
- No kill switch yet (Phase 10)
- No memory zeroing of session keys on drop (Phase 3, via zeroize)

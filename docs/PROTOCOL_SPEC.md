# HelloVPN Protocol Specification

> **Protocol**: HVPN/1
> **Status**: DRAFT — Phase 1
> **Last updated**: 2026-11-21

---

## 1. Overview

HelloVPN (HVPN) is a secure VPN protocol combining:
- Noise IK handshake for mutual authentication and key establishment
- ChaCha20-Poly1305 AEAD for data encryption
- UDP as the primary transport (TCP fallback available)
- Custom binary packet framing

HVPN is NOT compatible with WireGuard or OpenVPN at the wire level.

---

## 2. Packet Format

All multi-byte integers are big-endian (network byte order).

### 2.1 Wire Layout

```
Offset  Size  Field
------  ----  -----
0       4     Magic number: 0x48 0x56 0x50 0x4E ("HVPN")
4       1     Protocol version: 0x01
5       1     Packet type (see 2.2)
6       2     Flags (see 2.3)
8       8     Session ID (u64, assigned at handshake completion)
16      8     Sequence number (u64, monotonically increasing per session)
24      2     Payload length in bytes (u16, max 65535)
26      N     Payload (may be encrypted, see 2.4)
26+N    16    AEAD authentication tag (present on Data/Keepalive/Close types)
```

Total minimum header size: 26 bytes (HEADER_SIZE constant).
Maximum packet size: 26 + 65535 + 16 = 65577 bytes.
Recommended MTU: 1420 bytes (IP) => 1420 - 20 (IP) - 8 (UDP) - 42 (HVPN overhead) = 1350 bytes usable.

### 2.2 Packet Types

| Value | Name       | Description                              |
|-------|------------|------------------------------------------|
| 0x01  | Hello      | Initiates handshake (unencrypted)        |
| 0x02  | Handshake  | Noise handshake messages (unencrypted)   |
| 0x03  | Data       | Encrypted IP payload                     |
| 0x04  | Keepalive  | Encrypted keepalive (empty payload)      |
| 0x05  | Close      | Encrypted session termination            |

Packets with unknown type values MUST be silently dropped.

### 2.3 Flags

| Bit | Name       | Description                   |
|-----|------------|-------------------------------|
| 0   | REKEY      | Rekeying requested            |
| 1   | COMPRESSED | Payload is compressed (future)|
| 2-15| Reserved   | MUST be zero, ignore if set   |

### 2.4 Payload Encryption

Data, Keepalive, and Close packets use ChaCha20-Poly1305 AEAD:

Nonce (12 bytes):
  - Bytes 0-3: Session ID lower 32 bits (big-endian)
  - Bytes 4-11: Sequence number (big-endian u64)

Associated Authenticated Data (AAD):
  - The 26-byte packet header (Magic through Payload Length inclusive)
  - This binds the ciphertext to its header; header tampering is detected

The 16-byte authentication tag is appended after the ciphertext.

CRITICAL: Sequence numbers MUST NOT be reused. The nonce is derived from
the sequence number. If a session's sequence number reaches 2^64 - 1,
the session MUST be rekeyed or terminated.

---

## 3. Handshake Protocol

### 3.1 Noise Pattern

Pattern:  Noise_IK_25519_ChaChaPoly_BLAKE2s
Library:  snow 0.10.x

Properties of Noise IK:
- I = Static key of initiator (client) is known to responder (server) at start
- K = Static key of responder (server) is known to initiator (client) at start
- Mutual authentication: Both parties prove possession of their static key
- Forward secrecy: Compromise of static keys does not expose past sessions
- Identity hiding: Client static key is encrypted in the first message

### 3.2 Trust Model

Server trust:
  - Server public key is embedded in the client's .hvpn config file
  - Distributed out-of-band (download, QR code, etc.)
  - Client MUST reject servers with unknown keys

Client trust:
  - Server maintains an allow-list of authorised client public keys
  - Stored in server.toml: [[peers]] sections
  - Clients not on the allow-list are rejected BEFORE the handshake completes
  - Current limitation: No revocation mechanism (manual removal only)

### 3.3 Handshake Message Flow

```
Client                                Server
  |                                     |
  |-- Hello (PacketType::Hello) ------->|  Session request, unencrypted
  |                                     |  Server validates client is allowed
  |<- Hello (PacketType::Hello) --------|  Server acknowledges
  |                                     |
  |-- Handshake msg 1 (Noise init) ---->|  Noise IK message 1
  |   Contains encrypted client identity|
  |<- Handshake msg 2 (Noise resp) -----|  Noise IK message 2
  |                                     |
  |   [Both parties derive session keys]|
  |                                     |
  |== Encrypted data channel ==========>|  PacketType::Data
  |<= Encrypted data channel ===========|
```

### 3.4 Session ID Assignment

After handshake completion:
- Server generates a cryptographically random 64-bit Session ID
- Server sends the Session ID in the first encrypted packet
- Both parties use this ID for all subsequent packets in the session

### 3.5 Handshake Timeout

- Client MUST time out the handshake after 5 seconds
- Server MUST time out incomplete handshakes after 10 seconds
- After timeout: exponential backoff starting at 1s, max 30s

---

## 4. Session Management

### 4.1 Session Lifecycle

```
  INIT -> HELLO_SENT -> HANDSHAKING -> ACTIVE -> REKEYING -> CLOSED
                                          |                     ^
                                          +------ TIMEOUT ------+
```

### 4.2 Sequence Numbers

- Each session maintains two monotonic counters: send_seq and recv_seq
- send_seq starts at 0 and increments by 1 per packet sent
- send_seq MUST NOT wrap; sessions MUST rekey before reaching 2^64 - 1024

### 4.3 Replay Window

- Server and client each maintain a 64-slot sliding window
- Packets with sequence numbers older than (highest_seen - 64) are dropped
- Packets with sequence numbers already seen in the window are dropped
- This prevents replay attacks within the window

### 4.4 Keepalive

- Default interval: 25 seconds
- Either party may send a Keepalive packet if no data was sent for 25s
- If no packet received for 90s: session considered dead, reconnect

### 4.5 Rekeying

Rekeying is triggered when:
- Session has been active for 1 hour
- 2^60 packets have been sent in the session

Rekeying procedure:
- Initiating party sends a Data packet with REKEY flag set
- Both parties perform a fresh Noise handshake (new ephemeral keys)
- New session keys replace old ones atomically
- Old session keys are securely zeroed from memory

### 4.6 Graceful Close

- Sending party sends a Close packet (encrypted)
- Receiving party acknowledges with a Close packet
- If no ACK within 2s: close anyway, do not block shutdown

---

## 5. UDP Transport

### 5.1 Socket Behaviour

- UDP socket: SO_REUSEPORT enabled on server
- Server listens on port 51820 by default (configurable)
- Client uses an ephemeral port chosen by the OS
- Maximum datagram size: 65527 bytes (but limited by MTU in practice)

### 5.2 Packet Loss and Ordering

HVPN does NOT provide reliable or ordered delivery of data packets.
IP packets are individually encapsulated; TCP within the tunnel handles
its own reliability. This is the same model as WireGuard.

---

## 6. TCP Fallback Transport

When UDP is blocked:
- Client attempts TCP connection to server on the same port
- Packets are length-prefixed (u32 big-endian length + payload)
- All other protocol semantics are identical

---

## 7. Configuration File Format

### 7.1 Client Configuration (.hvpn)

```toml
protocol = "hellovpn"
version = 1

[connection]
server = "vpn.example.com"
port = 51820
transport = "udp"       # or "tcp" for fallback

[security]
handshake = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
server_public_key = "BASE64_URL_ENCODED_32_BYTE_KEY"
# client private key is NEVER stored in this file
# it is stored separately in the OS keychain or key file

[network]
ipv4 = "10.10.0.2/24"
dns = ["1.1.1.1", "1.0.0.1"]
mtu = 1420
routes = ["0.0.0.0/0"]    # default: route all traffic through VPN

[client]
name = "my-device"
keepalive = 25
```

### 7.2 Server Configuration (.toml)

```toml
[server]
listen = "0.0.0.0"
port = 51820
transport = ["udp", "tcp"]

[server.keys]
private_key_file = "/etc/hvpn/server_private.key"

[server.network]
tun_name = "hvpn0"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1", "1.0.0.1"]

[[peers]]
name = "alice-laptop"
public_key = "BASE64_URL_ENCODED_32_BYTE_KEY"
allowed_ips = ["10.10.0.2/32"]

[[peers]]
name = "bob-phone"
public_key = "BASE64_URL_ENCODED_32_BYTE_KEY"
allowed_ips = ["10.10.0.3/32"]
```

---

## 8. Key Management

### 8.1 Key Generation

hvpn key generate
  - Generates a fresh X25519 keypair
  - Stores private key in platform keychain or permission-restricted file
  - Outputs public key in base64url for registration with server

### 8.2 Key Storage

- Private keys: chmod 600 file or OS keychain (never in .hvpn config)
- Public keys: freely distributable (embedded in .hvpn and server.toml)
- Server private key: /etc/hvpn/server_private.key (chmod 600, root only)

### 8.3 Key Rotation

Manual key rotation:
1. Generate new keypair on client
2. Register new public key with server operator
3. Server operator adds to allow-list and removes old key
4. Client updates .hvpn config with new server-issued config

---

## 9. Error Handling

| Error | Action |
|-------|--------|
| Invalid magic | Drop packet silently |
| Unsupported version | Drop packet, log warning |
| Unknown packet type | Drop packet silently |
| AEAD decryption failure | Drop packet, increment counter |
| Replay detected | Drop packet, increment counter |
| Handshake auth failure | Close connection, rate-limit source IP |
| Session not found | Drop packet silently |
| Oversized packet | Drop packet, log warning |

No error responses are sent for unauthenticated packets to prevent
information leakage and amplification attacks.

---

## 10. Version Negotiation

HVPN/1 does not perform version negotiation in the handshake.
Clients and servers MUST reject packets with version != 0x01.

Future versions will introduce a version negotiation Hello message
before the Noise handshake begins. This is tracked in the roadmap.

---

## 11. Security Limitations and Non-Goals

This protocol DOES NOT provide:
- Protection against traffic analysis (timing, volume, pattern analysis)
- Anonymity at the network layer (server sees client IP)
- Key revocation without out-of-band coordination
- Resistance to a compromised server (server can see all client traffic)
- Post-quantum security (X25519 is vulnerable to future quantum computers)

Future consideration: Noise_IK with post-quantum hybrid (ML-KEM + X25519).

This specification MUST be reviewed by a qualified cryptographer
before the protocol is used in production.

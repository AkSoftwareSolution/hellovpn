# Security Policy

## ⚠️ Pre-Alpha Warning

HelloVPN has NOT been audited by independent security researchers.
This software MUST NOT be used in any production or sensitive environment
until a full independent security audit has been completed.

## Threat Model Summary

### Assets Protected
- Client IP packets (confidentiality, integrity)
- Client identity (hidden from passive observers)
- Session keys (forward secrecy)

### Threats Addressed
| Threat | Mitigation |
|--------|-----------|
| Passive eavesdropping | ChaCha20-Poly1305 AEAD encryption |
| Active MITM | Noise IK mutual authentication (static key pinning) |
| Replay attacks | 64-slot sliding sequence number window |
| Nonce reuse | Monotonic counter; session rekeyed before exhaustion |
| Packet tampering | AEAD authentication tag over header + payload |
| Downgrade attack | Noise pattern is fixed, not negotiated |
| Rogue server | Server public key pinned in .hvpn config |
| Rogue client | Client public key allow-list on server |

### Threats NOT Addressed
| Threat | Status |
|--------|--------|
| Traffic analysis / timing analysis | Not mitigated |
| Compromised server seeing client traffic | By design (VPN model) |
| Post-quantum cryptography | Not implemented; X25519 is quantum-vulnerable |
| Key revocation | Manual only (remove from server allow-list) |
| Client anonymity | Server sees client IP address |

## Known Limitations

1. **No revocation**: Compromised client keys remain valid until manually removed.
2. **TOFU trust model**: Server public key must be verified out-of-band.
3. **No DoS protection**: Rate limiting is planned (Phase 11) but not implemented.
4. **Memory zeroing**: Session keys are not yet zeroed on drop (Phase 3, via zeroize).
5. **No post-quantum**: Planned for a future version using hybrid ML-KEM + X25519.

## Reporting Vulnerabilities

Do not open public GitHub issues for security vulnerabilities.

Please report security issues by email to: **security@hellovpn.example** (placeholder)

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fix

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

## Cryptographic Design Principles

1. We use only well-audited cryptographic libraries (snow, ring).
2. We never implement cryptographic algorithms from scratch.
3. We never make security guarantees we cannot back with code and tests.
4. All cryptographic decisions are documented in PROTOCOL_SPEC.md.
5. All known limitations are documented here and in ARCHITECTURE.md.

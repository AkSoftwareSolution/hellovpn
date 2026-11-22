//! Unified error hierarchy for the HelloVPN protocol stack.
//!
//! Each crate in the workspace maps its errors to one of these variants.
//! The top-level `HvpnError` aggregates all of them for binary entry-points.

use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Protocol layer errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Invalid magic bytes: expected HVPN")]
    InvalidMagic,
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    #[error("Invalid or unknown packet type: {0}")]
    InvalidPacketType(u8),
    #[error("Invalid payload length field or buffer too short")]
    InvalidLength,
    #[error("Payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("Packet buffer too small to encode: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },
}

// ──────────────────────────────────────────────────────────────────────────────
// Cryptography / security errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD authentication/decryption failed")]
    DecryptFailed,
    #[error("Nonce counter exhausted — rekeying is required")]
    NonceExhausted,
    #[error("Invalid key length: expected {expected} bytes, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Invalid key format (expected base64url)")]
    InvalidKeyFormat,
    #[error("Noise handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("Snow error: {0}")]
    Snow(#[from] snow::Error),
    #[error("I/O error reading key file: {0}")]
    Io(#[from] std::io::Error),
}

// ──────────────────────────────────────────────────────────────────────────────
// Session errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    NotFound(u64),
    #[error("Session has expired")]
    Expired,
    #[error("Replay detected: sequence number {0} already received")]
    Replay(u64),
    #[error("Maximum concurrent session limit reached")]
    LimitReached,
    #[error("Session is not in the expected state for this operation")]
    InvalidState,
    #[error("Handshake timeout")]
    HandshakeTimeout,
    #[error("Peer authentication failed")]
    AuthFailed,
}

// ──────────────────────────────────────────────────────────────────────────────
// Transport errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Connection or receive timeout")]
    Timeout,
    #[error("Packet too large: {0} bytes")]
    PacketTooLarge(usize),
    #[error("Transport connection closed")]
    Closed,
    #[error("DNS resolution failed for {0}")]
    DnsFailure(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// TUN device errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TunError {
    #[error("Failed to open TUN device: {0}")]
    Open(String),
    #[error("TUN read error: {0}")]
    Read(std::io::Error),
    #[error("TUN write error: {0}")]
    Write(std::io::Error),
    #[error("MTU configuration error: {0}")]
    Mtu(String),
    #[error("TUN device closed")]
    Closed,
}

// ──────────────────────────────────────────────────────────────────────────────
// Routing / DNS errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Route command failed: {0}")]
    CommandFailed(String),
    #[error("DNS configuration failed: {0}")]
    DnsFailed(String),
    #[error("Kill switch error: {0}")]
    KillSwitch(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// Configuration errors
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Invalid or malformed key: {0}")]
    InvalidKey(String),
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Version mismatch: config version {0} not supported")]
    VersionMismatch(u32),
}

// ──────────────────────────────────────────────────────────────────────────────
// Top-level aggregate error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HvpnError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("TUN error: {0}")]
    Tun(#[from] TunError),
    #[error("Routing error: {0}")]
    Routing(#[from] RoutingError),
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

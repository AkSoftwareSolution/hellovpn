//! hello-config — parse, validate, and generate HelloVPN configuration files.
//!
//! # File formats
//! - Client: `.hvpn` (TOML internally)
//! - Server: `.toml`
//!
//! # Security notes
//! - Private keys are NEVER stored in distributable config files.
//! - Public keys are stored as base64url-encoded 32-byte values.
//! - Config loading validates all key lengths and formats.

pub mod client;
pub mod server;

pub use client::ClientConfig;
pub use server::{PeerConfig, ServerConfig};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hello_core::ConfigError;

/// Decode a base64url-encoded 32-byte X25519 public key.
pub fn decode_public_key(s: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ConfigError::InvalidKey(format!("base64url decode failed: {e}")))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| ConfigError::InvalidKey(
        format!("key must be 32 bytes, got {} bytes", len)
    ))
}

/// Encode a 32-byte X25519 key as base64url (no padding).
pub fn encode_key(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

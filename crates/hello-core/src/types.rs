//! Shared identifier newtypes and common traits.

use std::fmt;

// ──────────────────────────────────────────────────────────────────────────────
// Identifier newtypes
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier assigned to a VPN session after handshake completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

impl SessionId {
    pub fn new(v: u64) -> Self { Self(v) }
    pub fn as_u64(self) -> u64 { self.0 }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────

/// Monotonically increasing sequence number on the data channel.
/// Used both for nonce derivation and replay window position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SequenceNumber(pub u64);

impl SequenceNumber {
    pub const MAX: SequenceNumber = SequenceNumber(u64::MAX);
    /// Upper bound at which a rekey must be triggered.
    pub const REKEY_THRESHOLD: u64 = 1u64 << 60;

    pub fn new(v: u64) -> Self { Self(v) }
    pub fn as_u64(self) -> u64 { self.0 }

    /// Advance and return the previous value. Saturates at MAX to signal exhaustion.
    pub fn next(&mut self) -> u64 {
        let v = self.0;
        self.0 = self.0.saturating_add(1);
        v
    }

    pub fn needs_rekey(self) -> bool {
        self.0 >= Self::REKEY_THRESHOLD
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────

/// A peer's identity, represented by their X25519 static public key (32 bytes).
/// This is what is pinned in the server allow-list and in the client .hvpn config.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", hex::fmt_bytes(&self.0))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::fmt_bytes(&self.0))
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = crate::error::CryptoError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = b.try_into().map_err(|_| crate::error::CryptoError::InvalidKeyLength {
            expected: 32,
            got: b.len(),
        })?;
        Ok(Self(arr))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal hex formatting helper (avoids pulling in hex crate)
// ──────────────────────────────────────────────────────────────────────────────

mod hex {
    pub fn fmt_bytes(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut s, byte| {
            use std::fmt::Write;
            write!(s, "{byte:02x}").unwrap();
            s
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Encode / Decode traits
// ──────────────────────────────────────────────────────────────────────────────

pub trait Encode {
    fn encode_to_vec(&self) -> Result<Vec<u8>, crate::error::ProtocolError>;
}

pub trait Decode: Sized {
    fn decode_from(data: &[u8]) -> Result<Self, crate::error::ProtocolError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_roundtrip() {
        let id = SessionId::new(0xdeadbeefcafe1234);
        assert_eq!(id.as_u64(), 0xdeadbeefcafe1234);
    }

    #[test]
    fn sequence_number_next() {
        let mut seq = SequenceNumber::new(0);
        assert_eq!(seq.next(), 0);
        assert_eq!(seq.next(), 1);
        assert_eq!(seq.as_u64(), 2);
    }

    #[test]
    fn sequence_number_saturation() {
        let mut seq = SequenceNumber::new(u64::MAX);
        let _ = seq.next(); // should not panic
        assert_eq!(seq.as_u64(), u64::MAX);
    }

    #[test]
    fn sequence_number_rekey_threshold() {
        let seq = SequenceNumber::new(SequenceNumber::REKEY_THRESHOLD);
        assert!(seq.needs_rekey());
        let seq2 = SequenceNumber::new(SequenceNumber::REKEY_THRESHOLD - 1);
        assert!(!seq2.needs_rekey());
    }

    #[test]
    fn peer_id_from_bytes() {
        let key = [42u8; 32];
        let id = PeerId::from_bytes(key);
        assert_eq!(id.as_bytes(), &key);
    }

    #[test]
    fn peer_id_try_from_slice_ok() {
        let slice = [1u8; 32];
        let id = PeerId::try_from(slice.as_ref()).unwrap();
        assert_eq!(id.as_bytes(), &slice);
    }

    #[test]
    fn peer_id_try_from_bad_length() {
        let bad = [0u8; 16];
        assert!(PeerId::try_from(bad.as_ref()).is_err());
    }
}

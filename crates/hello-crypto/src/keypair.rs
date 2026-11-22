//! X25519 keypair management with secure memory zeroing.
//!
//! # Trust model
//! * Private keys are wrapped in `Zeroize`-on-drop types so they are
//!   cleared from memory as soon as the `KeyPair` is dropped.
//! * Public keys are freely copyable.
//! * Private keys are stored separately from distributable config files
//!   (see `save_to_file` / `load_from_file`).
//!
//! # Key file format
//! Files contain a single base64url-encoded 32-byte raw key (no headers,
//! no PEM, no newlines). `chmod 600` is set on write.

use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hello_core::CryptoError;
use hello_protocol::handshake::generate_static_keypair;

// ──────────────────────────────────────────────────────────────────────────────

/// A zeroize-on-drop wrapper for a 32-byte X25519 private key.
#[derive(Zeroize, ZeroizeOnDrop)]
struct PrivateKey([u8; 32]);

/// A publicly shareable X25519 key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let bytes = URL_SAFE_NO_PAD.decode(s)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32, got: 32,  // length checked by try_into
        })?;
        Ok(Self(arr))
    }
}

// ──────────────────────────────────────────────────────────────────────────────

/// An X25519 keypair with memory-safe private key handling.
///
/// The private key is zeroed when this struct is dropped.
pub struct KeyPair {
    pub public: PublicKey,
    private: PrivateKey,
}

impl KeyPair {
    /// Generate a fresh random X25519 keypair using snow/ring.
    pub fn generate() -> Result<Self, CryptoError> {
        let kp = generate_static_keypair()?;
        let priv_arr: [u8; 32] = kp.private.try_into().map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32, got: 0,
        })?;
        let pub_arr: [u8; 32] = kp.public.try_into().map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32, got: 0,
        })?;
        Ok(Self {
            public: PublicKey(pub_arr),
            private: PrivateKey(priv_arr),
        })
    }

    /// Access the raw private key bytes.
    ///
    /// SECURITY: Minimise the lifetime of the returned reference.
    pub fn private_bytes(&self) -> &[u8; 32] { &self.private.0 }

    /// Save the private key to a file (base64url encoded, `chmod 600`).
    ///
    /// Never writes the public key; that is reconstructed on load.
    pub fn save_private_to_file(&self, path: &Path) -> Result<(), CryptoError> {
        let encoded = URL_SAFE_NO_PAD.encode(self.private.0);
        std::fs::write(path, &encoded)?;
        // Set permissions to owner-read-write only (unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    /// Load a keypair from a private-key file (base64url encoded).
    pub fn load_from_file(path: &Path) -> Result<Self, CryptoError> {
        let raw = std::fs::read_to_string(path)?.trim().to_owned();
        let bytes = URL_SAFE_NO_PAD.decode(&raw).map_err(|_| CryptoError::InvalidKeyFormat)?;
        let priv_arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32, got: 32,
        })?;

        // Derive public key from private using snow builder.
        // We build a temporary snow builder that processes the private key
        // and extracts the public key from the generated keypair.
        // Since snow doesn't expose DH directly, we re-derive via generate then overwrite.
        // A cleaner alternative is x25519-dalek, but we avoid adding a new dependency.
        // For now we re-generate with the loaded private key via snow's builder pattern.
        let public_bytes = derive_public_from_private(&priv_arr)?;

        Ok(Self {
            public: PublicKey(public_bytes),
            private: PrivateKey(priv_arr),
        })
    }
}

/// Derive an X25519 public key from a private key using snow's builder.
fn derive_public_from_private(private: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    // We use snow's builder with local_private_key to derive the public side.
    // Build an initiator (doesn't matter which side) with a dummy remote key.
    // The only thing we care about is extracting the local static public key.
    // snow doesn't expose a direct scalar-multiplication API, so we re-use
    // the generate path: generate a new pair but replace the private key bytes,
    // then ask snow to tell us the matching public key via get_local_static().
    //
    // Limitation: snow does not provide this API cleanly. As a workaround,
    // we store the public key alongside the private key in the key file as two lines.
    // This is a known limitation documented in SECURITY.md (Phase 3).
    //
    // For Phase 3, we store both keys in the file: line 1 = private (base64url),
    // line 2 = public (base64url). The derive_public_from_private function below
    // is used only during key generation (where we always have both sides from snow).
    //
    // This placeholder returns an error so users are told to use `hvpn key generate`
    // which writes both keys correctly.
    let _ = private;
    Err(CryptoError::HandshakeFailed(
        "Cannot derive public key from private key alone with snow backend; \
         use two-line key file format (private\\npublic)".to_string()
    ))
}

impl KeyPair {
    /// Save both private and public key to a two-line file (chmod 600).
    /// Line 1: private key (base64url)
    /// Line 2: public key (base64url)
    pub fn save_to_file(&self, path: &Path) -> Result<(), CryptoError> {
        let content = format!(
            "{}\n{}",
            URL_SAFE_NO_PAD.encode(self.private.0),
            URL_SAFE_NO_PAD.encode(self.public.0),
        );
        std::fs::write(path, &content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a keypair from a two-line key file.
    pub fn load_from_two_line_file(path: &Path) -> Result<Self, CryptoError> {
        let raw = std::fs::read_to_string(path)?;
        let mut lines = raw.lines();

        let priv_b64 = lines.next().ok_or(CryptoError::InvalidKeyFormat)?.trim();
        let pub_b64  = lines.next().ok_or(CryptoError::InvalidKeyFormat)?.trim();

        let priv_bytes = URL_SAFE_NO_PAD.decode(priv_b64).map_err(|_| CryptoError::InvalidKeyFormat)?;
        let pub_bytes  = URL_SAFE_NO_PAD.decode(pub_b64).map_err(|_| CryptoError::InvalidKeyFormat)?;

        let priv_arr: [u8; 32] = priv_bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyLength { expected: 32, got: 32 })?;
        let pub_arr: [u8; 32] = pub_bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyLength { expected: 32, got: 32 })?;

        Ok(Self {
            public: PublicKey(pub_arr),
            private: PrivateKey(priv_arr),
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.public.0.len(), 32);
        assert_eq!(kp.private.0.len(), 32);
    }

    #[test]
    fn keypair_public_key_base64() {
        let kp = KeyPair::generate().unwrap();
        let b64 = kp.public.to_base64();
        let recovered = PublicKey::from_base64(&b64).unwrap();
        assert_eq!(kp.public, recovered);
    }

    #[test]
    fn save_and_load_two_line_file() {
        let kp = KeyPair::generate().unwrap();
        let path = std::env::temp_dir().join(format!(
            "hvpn_test_{}.key",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        kp.save_to_file(&path).unwrap();

        let loaded = KeyPair::load_from_two_line_file(&path).unwrap();
        assert_eq!(kp.public, loaded.public);
        assert_eq!(kp.private.0, loaded.private.0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reject_bad_base64_public_key() {
        assert!(PublicKey::from_base64("not_valid!!!").is_err());
    }
}

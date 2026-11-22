//! SessionCipher — AEAD data-plane encryption using snow's StatelessTransportState.
//!
//! # Cryptographic Design
//!
//! After completing a Noise IK handshake, both initiator and responder transition
//! into transport mode with symmetric cipher states (ChaCha20-Poly1305).
//!
//! [`SessionCipher`] wraps `snow::StatelessTransportState`, which enables:
//! - Explicit sequence numbers passed directly as nonces (`u64`), preventing nonce reuse.
//! - Out-of-order packet decryption over UDP transport.
//! - Monotonically increasing sequence counters maintained by the session layer.
//! - ChaCha20-Poly1305 authenticated encryption with a 16-byte authentication tag.

use hello_core::CryptoError;
use snow::{HandshakeState, StatelessTransportState};

/// Authentication tag length for ChaCha20-Poly1305 (16 bytes).
pub const TAG_LEN: usize = 16;

/// Wraps snow's `StatelessTransportState` for data-plane encryption and decryption.
pub struct SessionCipher {
    state: StatelessTransportState,
}

impl SessionCipher {
    /// Construct a `SessionCipher` by consuming a finished `HandshakeState`.
    ///
    /// # Errors
    /// Returns `CryptoError::HandshakeFailed` if the handshake is not yet finished.
    pub fn from_handshake(handshake: HandshakeState) -> Result<Self, CryptoError> {
        if !handshake.is_handshake_finished() {
            return Err(CryptoError::HandshakeFailed(
                "Cannot transition to transport mode: handshake is not finished".to_string(),
            ));
        }

        let state = handshake
            .into_stateless_transport_mode()
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;

        Ok(Self { state })
    }

    /// Construct a `SessionCipher` directly from a `StatelessTransportState`.
    pub fn from_stateless(state: StatelessTransportState) -> Self {
        Self { state }
    }

    /// Encrypt `plaintext` using the specified `nonce` (sequence number).
    ///
    /// The ciphertext (including the 16-byte AEAD authentication tag) is written into `out`.
    /// `out` must have capacity of at least `plaintext.len() + TAG_LEN`.
    ///
    /// Returns the number of bytes written to `out` (which equals `plaintext.len() + TAG_LEN`).
    pub fn encrypt(&self, nonce: u64, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if out.len() < plaintext.len() + TAG_LEN {
            return Err(CryptoError::EncryptFailed);
        }

        self.state
            .write_message(nonce, plaintext, out)
            .map_err(|_| CryptoError::EncryptFailed)
    }

    /// Decrypt `ciphertext` using the specified `nonce` (sequence number).
    ///
    /// The authenticated plaintext is written into `out`.
    /// `out` must have capacity of at least `ciphertext.len().saturating_sub(TAG_LEN)`.
    ///
    /// Returns the number of bytes written to `out`.
    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::DecryptFailed);
        }

        self.state
            .read_message(nonce, ciphertext, out)
            .map_err(|_| CryptoError::DecryptFailed)
    }

    /// Convenience method: Encrypt `plaintext` allocating and returning a new `Vec<u8>`.
    pub fn encrypt_vec(&self, nonce: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; plaintext.len() + TAG_LEN];
        let written = self.encrypt(nonce, plaintext, &mut out)?;
        out.truncate(written);
        Ok(out)
    }

    /// Convenience method: Decrypt `ciphertext` allocating and returning a new `Vec<u8>`.
    pub fn decrypt_vec(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::DecryptFailed);
        }
        let mut out = vec![0u8; ciphertext.len() - TAG_LEN];
        let written = self.decrypt(nonce, ciphertext, &mut out)?;
        out.truncate(written);
        Ok(out)
    }

    /// Check if this endpoint is the handshake initiator.
    pub fn is_initiator(&self) -> bool {
        self.state.is_initiator()
    }

    /// Retrieve the remote party's static public key, if available.
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }

    /// Generate a new key for egress symmetric cipher (Noise rekey).
    pub fn rekey_outgoing(&mut self) {
        self.state.rekey_outgoing();
    }

    /// Generate a new key for ingress symmetric cipher (Noise rekey).
    pub fn rekey_incoming(&mut self) {
        self.state.rekey_incoming();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hello_protocol::handshake::{
        create_client_handshake, create_server_handshake, generate_static_keypair,
    };

    fn create_test_ciphers() -> (SessionCipher, SessionCipher) {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut client_handshake =
            create_client_handshake(&server_keys.public, &client_keys.private).unwrap();
        let mut server_handshake = create_server_handshake(&server_keys.private).unwrap();

        // Msg 1: Client -> Server
        let mut msg1 = vec![0u8; 1024];
        let len1 = client_handshake.write_message(&[], &mut msg1).unwrap();
        let mut payload_buf = vec![0u8; 1024];
        server_handshake
            .read_message(&msg1[..len1], &mut payload_buf)
            .unwrap();

        // Msg 2: Server -> Client
        let mut msg2 = vec![0u8; 1024];
        let len2 = server_handshake.write_message(&[], &mut msg2).unwrap();
        client_handshake
            .read_message(&msg2[..len2], &mut payload_buf)
            .unwrap();

        let client_cipher = SessionCipher::from_handshake(client_handshake).unwrap();
        let server_cipher = SessionCipher::from_handshake(server_handshake).unwrap();

        (client_cipher, server_cipher)
    }

    #[test]
    fn test_session_cipher_roundtrip() {
        let (client, server) = create_test_ciphers();

        let message = b"HelloVPN payload packet over UDP tunnel";
        let mut ciphertext = vec![0u8; message.len() + TAG_LEN];
        let enc_len = client.encrypt(0, message, &mut ciphertext).unwrap();
        assert_eq!(enc_len, message.len() + TAG_LEN);

        let mut decrypted = vec![0u8; message.len()];
        let dec_len = server
            .decrypt(0, &ciphertext[..enc_len], &mut decrypted)
            .unwrap();
        assert_eq!(dec_len, message.len());
        assert_eq!(&decrypted[..dec_len], message);

        // Server to Client reverse path
        let reply = b"Server ack response payload";
        let mut reply_ciphertext = vec![0u8; reply.len() + TAG_LEN];
        let rep_enc_len = server.encrypt(0, reply, &mut reply_ciphertext).unwrap();

        let mut reply_decrypted = vec![0u8; reply.len()];
        let rep_dec_len = client
            .decrypt(0, &reply_ciphertext[..rep_enc_len], &mut reply_decrypted)
            .unwrap();
        assert_eq!(&reply_decrypted[..rep_dec_len], reply);
    }

    #[test]
    fn test_session_cipher_wrong_nonce_fails() {
        let (client, server) = create_test_ciphers();

        let message = b"Critical data packet";
        let mut ciphertext = vec![0u8; message.len() + TAG_LEN];
        client.encrypt(42, message, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; message.len()];
        // Attempt decrypt with wrong nonce
        let result = server.decrypt(43, &ciphertext, &mut decrypted);
        assert!(result.is_err(), "Decryption with wrong nonce must fail");
    }

    #[test]
    fn test_session_cipher_tampered_ciphertext_fails() {
        let (client, server) = create_test_ciphers();

        let message = b"Authentic payload";
        let mut ciphertext = vec![0u8; message.len() + TAG_LEN];
        client.encrypt(1, message, &mut ciphertext).unwrap();

        // Flip a single bit in the ciphertext
        ciphertext[0] ^= 0x01;

        let mut decrypted = vec![0u8; message.len()];
        let result = server.decrypt(1, &ciphertext, &mut decrypted);
        assert!(result.is_err(), "Tampered ciphertext must fail AEAD verification");
    }

    #[test]
    fn test_session_cipher_encrypt_vec_roundtrip() {
        let (client, server) = create_test_ciphers();

        let message = b"Vector-based allocation test message";
        let ciphertext = client.encrypt_vec(10, message).unwrap();
        assert_eq!(ciphertext.len(), message.len() + TAG_LEN);

        let decrypted = server.decrypt_vec(10, &ciphertext).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_session_cipher_rekey() {
        let (mut client, mut server) = create_test_ciphers();

        let msg1 = b"Pre-rekey packet";
        let ct1 = client.encrypt_vec(0, msg1).unwrap();
        assert_eq!(server.decrypt_vec(0, &ct1).unwrap(), msg1);

        // Rekey client outgoing and server incoming
        client.rekey_outgoing();
        server.rekey_incoming();

        let msg2 = b"Post-rekey packet";
        let ct2 = client.encrypt_vec(1, msg2).unwrap();
        assert_eq!(server.decrypt_vec(1, &ct2).unwrap(), msg2);
    }
}

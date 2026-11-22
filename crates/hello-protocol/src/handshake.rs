//! Noise IK handshake for HelloVPN.
//!
//! Pattern: Noise_IK_25519_ChaChaPoly_BLAKE2s
//!
//! Security properties:
//! - Mutual authentication (both sides prove identity via static keys)
//! - Forward secrecy (ephemeral DH each session)
//! - Identity hiding (client identity hidden from passive observers)
//! - Downgrade protection (pattern fixed in code and config)
//!
//! # Trust model
//! The server's static public key must be pre-distributed to the client
//! out-of-band (embedded in the .hvpn config file).
//! The client's static public key must be pre-registered on the server
//! (allow-list of authorised public keys).
//!
//! LIMITATION: This implementation does not yet include revocation.
//! A compromised client key remains valid until manually removed from
//! the server allow-list.

use snow::{Builder, HandshakeState, Keypair, TransportState, params::NoiseParams};

/// The Noise protocol pattern used by HelloVPN.
///
/// IK: static keys known in advance by both parties.
/// 25519: X25519 Diffie-Hellman.
/// ChaChaPoly: ChaCha20-Poly1305 AEAD.
/// BLAKE2s: hash/PRF function.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Parse HelloVPN Noise protocol parameters.
fn noise_params() -> NoiseParams {
    NOISE_PATTERN
        .parse()
        .expect("NOISE_PATTERN is a compile-time constant and must always parse successfully")
}

/// Generate a static X25519 keypair.
///
/// Should be called once at node provisioning time and stored securely.
/// The public key is distributed to peers; the private key never leaves the node.
pub fn generate_static_keypair() -> Result<Keypair, snow::Error> {
    Builder::new(noise_params()).generate_keypair()
}

/// Create the server-side Noise IK handshake state (responder).
///
/// # Arguments
/// * `private_key` – The server's 32-byte X25519 private key.
///
/// # Errors
/// Returns `snow::Error::Input` if `private_key` is not exactly 32 bytes.
pub fn create_server_handshake(private_key: &[u8]) -> Result<HandshakeState, snow::Error> {
    if private_key.len() != 32 {
        return Err(snow::Error::Input);
    }

    Builder::new(noise_params())
        .local_private_key(private_key)?
        .build_responder()
}

/// Create the client-side Noise IK handshake state (initiator).
///
/// # Arguments
/// * `server_public_key`  – The server's 32-byte X25519 public key (from .hvpn config).
/// * `client_private_key` – The client's 32-byte X25519 private key.
///
/// # Errors
/// Returns `snow::Error::Input` if either key is not exactly 32 bytes.
pub fn create_client_handshake(
    server_public_key: &[u8],
    client_private_key: &[u8],
) -> Result<HandshakeState, snow::Error> {
    if server_public_key.len() != 32 || client_private_key.len() != 32 {
        return Err(snow::Error::Input);
    }

    Builder::new(noise_params())
        .remote_public_key(server_public_key)?
        .local_private_key(client_private_key)?
        .build_initiator()
}

/// Perform a full in-memory Noise IK handshake and return transport states.
///
/// This function is primarily intended for unit/integration testing.
/// Production code drives each handshake message over the network.
///
/// # Returns
/// `(client_transport, server_transport)` – symmetric AEAD channels.
pub fn perform_handshake(
    server_private_key: &[u8],
    client_private_key: &[u8],
    server_public_key: &[u8],
) -> Result<(TransportState, TransportState), snow::Error> {
    let mut client = create_client_handshake(server_public_key, client_private_key)?;
    let mut server = create_server_handshake(server_private_key)?;

    // Message 1: Client → Server  (IK initiator message)
    let mut message1 = vec![0u8; 1024];
    let len1 = client.write_message(&[], &mut message1)?;

    let mut payload_buf = vec![0u8; 1024];
    server.read_message(&message1[..len1], &mut payload_buf)?;

    // Message 2: Server → Client  (IK responder message)
    let mut message2 = vec![0u8; 1024];
    let len2 = server.write_message(&[], &mut message2)?;

    client.read_message(&message2[..len2], &mut payload_buf)?;

    // Upgrade to transport mode — both sides now hold symmetric session keys.
    let client_transport = client.into_transport_mode()?;
    let server_transport = server.into_transport_mode()?;

    Ok((client_transport, server_transport))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keys = generate_static_keypair().unwrap();
        assert_eq!(keys.private.len(), 32, "X25519 private key must be 32 bytes");
        assert_eq!(keys.public.len(), 32, "X25519 public key must be 32 bytes");
    }

    #[test]
    fn test_noise_ik_handshake_succeeds() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let result = perform_handshake(
            &server_keys.private,
            &client_keys.private,
            &server_keys.public,
        );

        assert!(result.is_ok(), "Full Noise IK handshake must succeed");
    }

    #[test]
    fn test_client_to_server_encryption() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let (mut client, mut server) = perform_handshake(
            &server_keys.private,
            &client_keys.private,
            &server_keys.public,
        )
        .unwrap();

        let original = b"HelloVPN encrypted message";
        let mut encrypted = vec![0u8; 1024];
        let encrypted_len = client.write_message(original, &mut encrypted).unwrap();

        let mut decrypted = vec![0u8; 1024];
        let decrypted_len = server
            .read_message(&encrypted[..encrypted_len], &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..decrypted_len], original);
    }

    #[test]
    fn test_server_to_client_encryption() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let (mut client, mut server) = perform_handshake(
            &server_keys.private,
            &client_keys.private,
            &server_keys.public,
        )
        .unwrap();

        let original = b"HelloVPN server response";
        let mut encrypted = vec![0u8; 1024];
        let encrypted_len = server.write_message(original, &mut encrypted).unwrap();

        let mut decrypted = vec![0u8; 1024];
        let decrypted_len = client
            .read_message(&encrypted[..encrypted_len], &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..decrypted_len], original);
    }

    #[test]
    fn test_wrong_server_key_fails() {
        let server_keys = generate_static_keypair().unwrap();
        let wrong_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        // Client thinks server has `wrong_keys.public` — handshake must fail.
        let mut client =
            create_client_handshake(&wrong_keys.public, &client_keys.private).unwrap();
        let mut server = create_server_handshake(&server_keys.private).unwrap();

        let mut message = vec![0u8; 1024];
        let message_len = client.write_message(&[], &mut message).unwrap();

        let mut payload = vec![0u8; 1024];
        let result = server.read_message(&message[..message_len], &mut payload);

        assert!(
            result.is_err(),
            "Server must reject client using wrong server key"
        );
    }

    #[test]
    fn test_short_private_key_rejected() {
        let result = create_server_handshake(&[0u8; 16]);
        assert!(result.is_err(), "Short private key must be rejected");
    }

    #[test]
    fn test_short_client_key_rejected() {
        let server_keys = generate_static_keypair().unwrap();
        let result = create_client_handshake(&server_keys.public, &[0u8; 16]);
        assert!(result.is_err(), "Short client private key must be rejected");
    }
}

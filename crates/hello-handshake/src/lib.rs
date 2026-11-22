//! hello-handshake — High-level Noise IK handshake orchestration for HelloVPN.
//!
//! # Responsibilities
//! - Drives 1-RTT Noise IK handshake between Client (Initiator) and Server (Responder).
//! - Encapsulates handshake messages into wire-format `hello_protocol::Packet` structures.
//! - Validates client identity against an authorization allow-list before completing the session.
//! - Generates cryptographically secure 64-bit session identifiers.
//! - Outputs authenticated [`SessionCipher`] states ready for immediate data transport.

use hello_core::{CryptoError, PeerId, SessionError, SessionId};
use hello_crypto::SessionCipher;
use hello_protocol::{Packet, PacketType};
use rand_core::{OsRng, RngCore};
use snow::HandshakeState;

/// Result of a successfully negotiated and authenticated Noise IK handshake.
pub struct HandshakeResult {
    /// Unique 64-bit session ID assigned to the session.
    pub session_id: SessionId,
    /// Symmetric AEAD cipher ready for data plane encryption.
    pub cipher: SessionCipher,
    /// Static identity of the remote peer.
    pub peer_id: PeerId,
}

/// Trait implemented by peer registries or authorization lists to validate client identity.
pub trait PeerValidator: Send + Sync {
    /// Returns true if the client identified by `peer_id` is permitted to connect.
    fn validate_peer(&self, peer_id: &PeerId) -> bool;
}

impl<F> PeerValidator for F
where
    F: Fn(&PeerId) -> bool + Send + Sync,
{
    fn validate_peer(&self, peer_id: &PeerId) -> bool {
        self(peer_id)
    }
}

/// Allow-list validator storing authorized peer public keys.
#[derive(Clone, Default, Debug)]
pub struct AllowListValidator {
    allowed_peers: Vec<[u8; 32]>,
}

impl AllowListValidator {
    pub fn new(allowed_peers: Vec<[u8; 32]>) -> Self {
        Self { allowed_peers }
    }

    pub fn add_peer(&mut self, peer_public_key: [u8; 32]) {
        if !self.allowed_peers.contains(&peer_public_key) {
            self.allowed_peers.push(peer_public_key);
        }
    }
}

impl PeerValidator for AllowListValidator {
    fn validate_peer(&self, peer_id: &PeerId) -> bool {
        self.allowed_peers.contains(peer_id.as_bytes())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client / Initiator
// ──────────────────────────────────────────────────────────────────────────────

/// State held by the initiator between sending Message 1 and receiving Message 2.
pub struct InitiatorState {
    handshake: HandshakeState,
    server_peer_id: PeerId,
}

/// Initiates Noise IK handshakes with a designated HelloVPN server.
pub struct HandshakeInitiator {
    server_public_key: [u8; 32],
    client_private_key: [u8; 32],
}

impl HandshakeInitiator {
    pub fn new(server_public_key: [u8; 32], client_private_key: [u8; 32]) -> Self {
        Self {
            server_public_key,
            client_private_key,
        }
    }

    /// Create Message 1 of the Noise IK handshake, wrapped in a wire `Packet`.
    pub fn start(&self) -> Result<(InitiatorState, Packet), CryptoError> {
        let mut handshake = hello_protocol::handshake::create_client_handshake(
            &self.server_public_key,
            &self.client_private_key,
        )?;

        let mut msg_buf = vec![0u8; 1024];
        let msg_len = handshake
            .write_message(&[], &mut msg_buf)
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;
        msg_buf.truncate(msg_len);

        let packet = Packet {
            packet_type: PacketType::Handshake,
            flags: 0,
            session_id: 0,
            sequence: 0,
            payload: msg_buf,
        };

        let state = InitiatorState {
            handshake,
            server_peer_id: PeerId::from_bytes(self.server_public_key),
        };

        Ok((state, packet))
    }

    /// Process Message 2 response packet from the server and finalize the session.
    pub fn complete(
        state: InitiatorState,
        response_packet: &Packet,
    ) -> Result<HandshakeResult, CryptoError> {
        if response_packet.packet_type != PacketType::Handshake {
            return Err(CryptoError::HandshakeFailed(format!(
                "Expected Handshake packet, got {:?}",
                response_packet.packet_type
            )));
        }

        let mut initiator = state.handshake;
        let mut payload_buf = vec![0u8; 1024];
        initiator
            .read_message(&response_packet.payload, &mut payload_buf)
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;

        let cipher = SessionCipher::from_handshake(initiator)?;
        let session_id = SessionId::new(response_packet.session_id);

        Ok(HandshakeResult {
            session_id,
            cipher,
            peer_id: state.server_peer_id,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Server / Responder
// ──────────────────────────────────────────────────────────────────────────────

/// Responds to Noise IK handshake requests and authenticates connecting clients.
pub struct HandshakeResponder<V: PeerValidator> {
    server_private_key: [u8; 32],
    validator: V,
}

impl<V: PeerValidator> HandshakeResponder<V> {
    pub fn new(server_private_key: [u8; 32], validator: V) -> Self {
        Self {
            server_private_key,
            validator,
        }
    }

    /// Process Message 1 from a client, authenticate their public key, and generate Message 2.
    pub fn process_initiation(
        &self,
        init_packet: &Packet,
    ) -> Result<(HandshakeResult, Packet), SessionError> {
        if init_packet.packet_type != PacketType::Handshake {
            return Err(SessionError::InvalidState);
        }

        let mut responder = hello_protocol::handshake::create_server_handshake(
            &self.server_private_key,
        )
        .map_err(|_| SessionError::AuthFailed)?;

        let mut payload_buf = vec![0u8; 1024];
        responder
            .read_message(&init_packet.payload, &mut payload_buf)
            .map_err(|_| SessionError::AuthFailed)?;

        // Extract client public key authenticated by Noise IK
        let client_pub = responder
            .get_remote_static()
            .ok_or(SessionError::AuthFailed)?;

        let client_pub_arr: [u8; 32] = client_pub
            .try_into()
            .map_err(|_| SessionError::AuthFailed)?;
        let client_peer_id = PeerId::from_bytes(client_pub_arr);

        // Enforce authorization check
        if !self.validator.validate_peer(&client_peer_id) {
            tracing::warn!(peer = %client_peer_id, "Rejected unauthorized client connection attempt");
            return Err(SessionError::AuthFailed);
        }

        // Generate cryptographically random 64-bit session ID
        let mut session_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut session_bytes);
        let session_id_val = u64::from_be_bytes(session_bytes);
        let session_id = SessionId::new(session_id_val);

        // Generate Message 2 (Responder message)
        let mut resp_msg_buf = vec![0u8; 1024];
        let resp_len = responder
            .write_message(&[], &mut resp_msg_buf)
            .map_err(|_| SessionError::AuthFailed)?;
        resp_msg_buf.truncate(resp_len);

        let response_packet = Packet {
            packet_type: PacketType::Handshake,
            flags: 0,
            session_id: session_id.as_u64(),
            sequence: 0,
            payload: resp_msg_buf,
        };

        let cipher = SessionCipher::from_handshake(responder)
            .map_err(|_| SessionError::AuthFailed)?;

        Ok((
            HandshakeResult {
                session_id,
                cipher,
                peer_id: client_peer_id,
            },
            response_packet,
        ))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hello_protocol::handshake::generate_static_keypair;

    #[test]
    fn test_handshake_flow_authorized_client() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        // Allow-list containing client
        let validator = AllowListValidator::new(vec![client_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);
        let initiator = HandshakeInitiator::new(server_pub, client_priv);

        // 1. Client starts handshake
        let (initiator_state, msg1_pkt) = initiator.start().unwrap();

        // 2. Server processes Message 1 and responds with Message 2
        let (server_result, msg2_pkt) = responder.process_initiation(&msg1_pkt).unwrap();

        // 3. Client processes Message 2 and finishes
        let client_result = HandshakeInitiator::complete(initiator_state, &msg2_pkt).unwrap();

        // Validate results
        assert_eq!(server_result.session_id, client_result.session_id);
        assert_eq!(server_result.peer_id.as_bytes(), &client_pub);
        assert_eq!(client_result.peer_id.as_bytes(), &server_pub);

        // Verify mutual encryption capability
        let test_data = b"Handshake verified payload transmission";
        let encrypted = client_result.cipher.encrypt_vec(0, test_data).unwrap();
        let decrypted = server_result.cipher.decrypt_vec(0, &encrypted).unwrap();
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_handshake_unauthorized_client_rejected() {
        let server_keys = generate_static_keypair().unwrap();
        let authorized_keys = generate_static_keypair().unwrap();
        let attacker_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut auth_pub = [0u8; 32];
        auth_pub.copy_from_slice(&authorized_keys.public);

        let mut attacker_priv = [0u8; 32];
        attacker_priv.copy_from_slice(&attacker_keys.private);

        // Server only allows authorized client
        let validator = AllowListValidator::new(vec![auth_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);

        // Attacker attempts connection
        let attacker_initiator = HandshakeInitiator::new(server_pub, attacker_priv);
        let (_, msg1_pkt) = attacker_initiator.start().unwrap();

        let result = responder.process_initiation(&msg1_pkt);
        assert!(
            matches!(result, Err(SessionError::AuthFailed)),
            "Unauthorized client must be rejected with AuthFailed"
        );
    }

    #[test]
    fn test_handshake_wrong_server_key_fails() {
        let server_keys = generate_static_keypair().unwrap();
        let wrong_server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);

        let mut wrong_server_pub = [0u8; 32];
        wrong_server_pub.copy_from_slice(&wrong_server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        let validator = AllowListValidator::new(vec![client_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);

        // Client configured with wrong server public key
        let initiator = HandshakeInitiator::new(wrong_server_pub, client_priv);
        let (_, msg1_pkt) = initiator.start().unwrap();

        let result = responder.process_initiation(&msg1_pkt);
        assert!(
            result.is_err(),
            "Server must reject handshake when client used wrong static key"
        );
    }

    #[test]
    fn test_handshake_corrupted_message1_payload_fails() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        let validator = AllowListValidator::new(vec![client_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);
        let initiator = HandshakeInitiator::new(server_pub, client_priv);

        let (_, mut msg1_pkt) = initiator.start().unwrap();
        // Tamper with message 1 payload
        if !msg1_pkt.payload.is_empty() {
            msg1_pkt.payload[0] ^= 0xff;
        }

        let result = responder.process_initiation(&msg1_pkt);
        assert!(
            matches!(result, Err(SessionError::AuthFailed)),
            "Server must reject corrupted Message 1"
        );
    }

    #[test]
    fn test_handshake_corrupted_message2_payload_fails() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        let validator = AllowListValidator::new(vec![client_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);
        let initiator = HandshakeInitiator::new(server_pub, client_priv);

        let (initiator_state, msg1_pkt) = initiator.start().unwrap();
        let (_, mut msg2_pkt) = responder.process_initiation(&msg1_pkt).unwrap();

        // Tamper with message 2 payload
        if !msg2_pkt.payload.is_empty() {
            msg2_pkt.payload[0] ^= 0xff;
        }

        let result = HandshakeInitiator::complete(initiator_state, &msg2_pkt);
        assert!(
            result.is_err(),
            "Client must reject corrupted Message 2 from server"
        );
    }

    #[test]
    fn test_handshake_invalid_packet_types_rejected() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        let validator = AllowListValidator::new(vec![client_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);
        let initiator = HandshakeInitiator::new(server_pub, client_priv);

        let (initiator_state, mut msg1_pkt) = initiator.start().unwrap();
        msg1_pkt.packet_type = PacketType::Data;

        let res1 = responder.process_initiation(&msg1_pkt);
        assert!(
            matches!(res1, Err(SessionError::InvalidState)),
            "Responder must reject non-Handshake packet type"
        );

        let bad_response_pkt = Packet {
            packet_type: PacketType::Data,
            flags: 0,
            session_id: 12345,
            sequence: 0,
            payload: vec![1, 2, 3],
        };

        let res2 = HandshakeInitiator::complete(initiator_state, &bad_response_pkt);
        assert!(
            res2.is_err(),
            "Initiator must reject non-Handshake packet type"
        );
    }

    #[test]
    fn test_handshake_session_id_randomness_and_uniqueness() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&server_keys.private);
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        let validator = AllowListValidator::new(vec![client_pub]);
        let responder = HandshakeResponder::new(server_priv, validator);

        let mut session_ids = std::collections::HashSet::new();
        for _ in 0..10 {
            let initiator = HandshakeInitiator::new(server_pub, client_priv);
            let (_, msg1_pkt) = initiator.start().unwrap();
            let (res, _) = responder.process_initiation(&msg1_pkt).unwrap();
            assert_ne!(res.session_id.as_u64(), 0);
            assert!(session_ids.insert(res.session_id.as_u64()), "Session IDs must be unique");
        }
    }

    #[test]
    fn test_allow_list_validator_add_peer() {
        let mut validator = AllowListValidator::default();
        let peer_a = PeerId::from_bytes([1u8; 32]);
        let peer_b = PeerId::from_bytes([2u8; 32]);

        assert!(!validator.validate_peer(&peer_a));
        validator.add_peer([1u8; 32]);
        assert!(validator.validate_peer(&peer_a));
        assert!(!validator.validate_peer(&peer_b));

        // Duplicate addition should be idempotent
        validator.add_peer([1u8; 32]);
        assert!(validator.validate_peer(&peer_a));
    }
}

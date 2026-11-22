//! hello-packet — Typed packet representations and AEAD codec pipeline.
//!
//! # Architecture
//! This crate bridges the raw wire-level `hello_protocol::Packet` and higher-level
//! application types (`DataPacket`, `KeepalivePacket`, `ClosePacket`, etc.).
//!
//! # Codec Pipeline
//! Encrypted packet egress:
//! 1. Assign monotonic sequence number.
//! 2. Encrypt plaintext payload with ChaCha20-Poly1305 AEAD (`SessionCipher`).
//! 3. Encode 26-byte wire header + ciphertext into big-endian byte frame.
//!
//! Encrypted packet ingress:
//! 1. Validate magic, protocol version, and header length.
//! 2. Rough sliding-window check (drop if obviously too old before decryption).
//! 3. Decrypt ciphertext + verify 16-byte Poly1305 authentication tag (`SessionCipher`).
//! 4. Commit sequence number to `ReplayWindow` (drops replays safely without window poisoning).
//! 5. Dispatch typed payload.

use hello_core::{HvpnError, SequenceNumber, SessionError, SessionId};
use hello_crypto::{ReplayWindow, SessionCipher};
use hello_protocol::{Packet, PacketType, ProtocolError as RawProtoError};

fn map_proto_err(err: RawProtoError) -> HvpnError {
    match err {
        RawProtoError::InvalidMagic => HvpnError::Protocol(hello_core::ProtocolError::InvalidMagic),
        RawProtoError::UnsupportedVersion => {
            HvpnError::Protocol(hello_core::ProtocolError::UnsupportedVersion(1))
        }
        RawProtoError::InvalidPacketType => {
            HvpnError::Protocol(hello_core::ProtocolError::InvalidPacketType(0))
        }
        RawProtoError::InvalidLength => {
            HvpnError::Protocol(hello_core::ProtocolError::InvalidLength)
        }
        RawProtoError::PayloadTooLarge => {
            HvpnError::Protocol(hello_core::ProtocolError::PayloadTooLarge {
                size: 0,
                max: 65535,
            })
        }
    }
}

/// Typed representation of valid protocol packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedPacket {
    Hello,
    Handshake(Vec<u8>),
    Data {
        session_id: SessionId,
        sequence: SequenceNumber,
        payload: Vec<u8>,
    },
    Keepalive {
        session_id: SessionId,
        sequence: SequenceNumber,
    },
    Close {
        session_id: SessionId,
        sequence: SequenceNumber,
    },
}

pub struct PacketCodec;

impl PacketCodec {
    /// Encode a typed packet into raw wire bytes.
    ///
    /// For encrypted packet types (`Data`, `Keepalive`, `Close`), the payload is encrypted
    /// with `cipher` using the packet's `sequence` number as the AEAD nonce.
    pub fn encode(packet: &TypedPacket, cipher: Option<&SessionCipher>) -> Result<Vec<u8>, HvpnError> {
        match packet {
            TypedPacket::Hello => {
                let pkt = Packet {
                    packet_type: PacketType::Hello,
                    flags: 0,
                    session_id: 0,
                    sequence: 0,
                    payload: vec![],
                };
                Ok(pkt.encode().map_err(map_proto_err)?)
            }
            TypedPacket::Handshake(payload) => {
                let pkt = Packet {
                    packet_type: PacketType::Handshake,
                    flags: 0,
                    session_id: 0,
                    sequence: 0,
                    payload: payload.clone(),
                };
                Ok(pkt.encode().map_err(map_proto_err)?)
            }
            TypedPacket::Data {
                session_id,
                sequence,
                payload,
            } => {
                let cipher = cipher.ok_or(SessionError::InvalidState)?;
                let encrypted_payload = cipher.encrypt_vec(sequence.as_u64(), payload)?;
                let pkt = Packet {
                    packet_type: PacketType::Data,
                    flags: 0,
                    session_id: session_id.as_u64(),
                    sequence: sequence.as_u64(),
                    payload: encrypted_payload,
                };
                Ok(pkt.encode().map_err(map_proto_err)?)
            }
            TypedPacket::Keepalive {
                session_id,
                sequence,
            } => {
                let cipher = cipher.ok_or(SessionError::InvalidState)?;
                let encrypted_payload = cipher.encrypt_vec(sequence.as_u64(), &[])?;
                let pkt = Packet {
                    packet_type: PacketType::Keepalive,
                    flags: 0,
                    session_id: session_id.as_u64(),
                    sequence: sequence.as_u64(),
                    payload: encrypted_payload,
                };
                Ok(pkt.encode().map_err(map_proto_err)?)
            }
            TypedPacket::Close {
                session_id,
                sequence,
            } => {
                let cipher = cipher.ok_or(SessionError::InvalidState)?;
                let encrypted_payload = cipher.encrypt_vec(sequence.as_u64(), &[])?;
                let pkt = Packet {
                    packet_type: PacketType::Close,
                    flags: 0,
                    session_id: session_id.as_u64(),
                    sequence: sequence.as_u64(),
                    payload: encrypted_payload,
                };
                Ok(pkt.encode().map_err(map_proto_err)?)
            }
        }
    }

    /// Decode raw wire bytes into a typed packet.
    ///
    /// Validates magic, version, header length, replay window, and AEAD tag.
    pub fn decode(
        raw_bytes: &[u8],
        cipher: Option<&SessionCipher>,
        window: Option<&mut ReplayWindow>,
    ) -> Result<TypedPacket, HvpnError> {
        let raw_packet = Packet::decode(raw_bytes).map_err(map_proto_err)?;

        match raw_packet.packet_type {
            PacketType::Hello => Ok(TypedPacket::Hello),
            PacketType::Handshake => Ok(TypedPacket::Handshake(raw_packet.payload)),
            PacketType::Data => {
                let cipher = cipher.ok_or(SessionError::InvalidState)?;
                let window = window.ok_or(SessionError::InvalidState)?;

                // 1. Fast-path out-of-window check (drop if obviously too old)
                if window.is_too_old(raw_packet.sequence) {
                    return Err(SessionError::Replay(raw_packet.sequence).into());
                }

                // 2. AEAD decrypt + verify authentication tag
                let decrypted_payload = cipher.decrypt_vec(raw_packet.sequence, &raw_packet.payload)?;

                // 3. Mark sequence number as received in replay window
                window.check_and_insert(raw_packet.sequence)?;

                Ok(TypedPacket::Data {
                    session_id: SessionId::new(raw_packet.session_id),
                    sequence: SequenceNumber::new(raw_packet.sequence),
                    payload: decrypted_payload,
                })
            }
            PacketType::Keepalive => {
                let cipher = cipher.ok_or(SessionError::InvalidState)?;
                let window = window.ok_or(SessionError::InvalidState)?;

                if window.is_too_old(raw_packet.sequence) {
                    return Err(SessionError::Replay(raw_packet.sequence).into());
                }

                let _decrypted = cipher.decrypt_vec(raw_packet.sequence, &raw_packet.payload)?;
                window.check_and_insert(raw_packet.sequence)?;

                Ok(TypedPacket::Keepalive {
                    session_id: SessionId::new(raw_packet.session_id),
                    sequence: SequenceNumber::new(raw_packet.sequence),
                })
            }
            PacketType::Close => {
                let cipher = cipher.ok_or(SessionError::InvalidState)?;
                let window = window.ok_or(SessionError::InvalidState)?;

                if window.is_too_old(raw_packet.sequence) {
                    return Err(SessionError::Replay(raw_packet.sequence).into());
                }

                let _decrypted = cipher.decrypt_vec(raw_packet.sequence, &raw_packet.payload)?;
                window.check_and_insert(raw_packet.sequence)?;

                Ok(TypedPacket::Close {
                    session_id: SessionId::new(raw_packet.session_id),
                    sequence: SequenceNumber::new(raw_packet.sequence),
                })
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hello_protocol::HEADER_SIZE;
    use hello_protocol::handshake::{
        create_client_handshake, create_server_handshake, generate_static_keypair,
    };

    fn create_test_cipher_pair() -> (SessionCipher, SessionCipher) {
        let s_keys = generate_static_keypair().unwrap();
        let c_keys = generate_static_keypair().unwrap();

        let mut c_hs = create_client_handshake(&s_keys.public, &c_keys.private).unwrap();
        let mut s_hs = create_server_handshake(&s_keys.private).unwrap();

        let mut m1 = vec![0u8; 1024];
        let l1 = c_hs.write_message(&[], &mut m1).unwrap();
        let mut p_buf = vec![0u8; 1024];
        s_hs.read_message(&m1[..l1], &mut p_buf).unwrap();

        let mut m2 = vec![0u8; 1024];
        let l2 = s_hs.write_message(&[], &mut m2).unwrap();
        c_hs.read_message(&m2[..l2], &mut p_buf).unwrap();

        (
            SessionCipher::from_handshake(c_hs).unwrap(),
            SessionCipher::from_handshake(s_hs).unwrap(),
        )
    }

    #[test]
    fn test_hello_and_handshake_unencrypted_roundtrip() {
        // Hello
        let hello = TypedPacket::Hello;
        let encoded = PacketCodec::encode(&hello, None).unwrap();
        let decoded = PacketCodec::decode(&encoded, None, None).unwrap();
        assert_eq!(decoded, hello);

        // Handshake
        let hs = TypedPacket::Handshake(b"noise_raw_message_bytes".to_vec());
        let enc_hs = PacketCodec::encode(&hs, None).unwrap();
        let dec_hs = PacketCodec::decode(&enc_hs, None, None).unwrap();
        assert_eq!(dec_hs, hs);
    }

    #[test]
    fn test_data_packet_codec_roundtrip() {
        let (client_cipher, server_cipher) = create_test_cipher_pair();
        let mut server_window = ReplayWindow::new();

        let orig_data = b"Simulated IPv4 packet payload (TCP SYN)";
        let packet = TypedPacket::Data {
            session_id: SessionId::new(99887766),
            sequence: SequenceNumber::new(0),
            payload: orig_data.to_vec(),
        };

        // Client encodes and encrypts
        let wire_bytes = PacketCodec::encode(&packet, Some(&client_cipher)).unwrap();
        assert!(wire_bytes.len() >= HEADER_SIZE + orig_data.len() + 16);

        // Server decodes, checks replay window, and decrypts
        let decoded = PacketCodec::decode(
            &wire_bytes,
            Some(&server_cipher),
            Some(&mut server_window),
        )
        .unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_replay_packet_rejected_at_codec() {
        let (client_cipher, server_cipher) = create_test_cipher_pair();
        let mut server_window = ReplayWindow::new();

        let packet = TypedPacket::Data {
            session_id: SessionId::new(12345),
            sequence: SequenceNumber::new(5),
            payload: b"Data payload".to_vec(),
        };

        let wire_bytes = PacketCodec::encode(&packet, Some(&client_cipher)).unwrap();

        // First receive must succeed
        assert!(PacketCodec::decode(
            &wire_bytes,
            Some(&server_cipher),
            Some(&mut server_window)
        )
        .is_ok());

        // Second receive (replay) must be rejected
        let replay_result = PacketCodec::decode(
            &wire_bytes,
            Some(&server_cipher),
            Some(&mut server_window),
        );
        assert!(
            matches!(replay_result, Err(HvpnError::Session(SessionError::Replay(5)))),
            "Replay must be rejected with SessionError::Replay"
        );
    }

    #[test]
    fn test_keepalive_and_close_roundtrip() {
        let (client_cipher, server_cipher) = create_test_cipher_pair();
        let mut server_window = ReplayWindow::new();

        // Keepalive
        let keepalive = TypedPacket::Keepalive {
            session_id: SessionId::new(42),
            sequence: SequenceNumber::new(1),
        };
        let wire = PacketCodec::encode(&keepalive, Some(&client_cipher)).unwrap();
        let decoded =
            PacketCodec::decode(&wire, Some(&server_cipher), Some(&mut server_window)).unwrap();
        assert_eq!(decoded, keepalive);

        // Close
        let close = TypedPacket::Close {
            session_id: SessionId::new(42),
            sequence: SequenceNumber::new(2),
        };
        let wire_close = PacketCodec::encode(&close, Some(&client_cipher)).unwrap();
        let decoded_close =
            PacketCodec::decode(&wire_close, Some(&server_cipher), Some(&mut server_window))
                .unwrap();
        assert_eq!(decoded_close, close);
    }
}

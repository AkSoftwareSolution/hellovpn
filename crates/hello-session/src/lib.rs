//! hello-session — Session state machine, keepalive tracking, and multi-client manager.
//!
//! # Lifecycle States
//! ```text
//! [Connecting] -> [Handshaking] -> [Active] <-> [Rekeying] -> [Closed]
//!                                      |
//!                                      v (Timeout / Inactivity)
//!                                   [Expired]
//! ```
//!
//! # Responsibilities
//! - Manages monotonic send sequence counter (nonce safety).
//! - Holds AEAD symmetric [`SessionCipher`] and sliding [`ReplayWindow`].
//! - Monitors heartbeat / keepalive intervals (default 25s) and inactivity timeouts (default 90s).
//! - Signals rekey threshold triggers ($2^{60}$ packets or 1 hour wall-clock time).
//! - Provides [`SessionManager`] for multi-tenant concurrent sessions on the server.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use hello_core::{HvpnError, PeerId, SequenceNumber, SessionError, SessionId};
use hello_crypto::{ReplayWindow, SessionCipher};
use hello_packet::{PacketCodec, TypedPacket};

/// Current state in the session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Handshaking,
    Active,
    Rekeying,
    Closed,
}

/// An established VPN session between client and server.
pub struct Session {
    pub session_id: SessionId,
    pub peer_id: PeerId,
    cipher: SessionCipher,
    replay_window: ReplayWindow,
    send_seq: SequenceNumber,
    created_at: Instant,
    last_recv: Instant,
    last_sent: Instant,
    state: SessionState,
}

impl Session {
    /// Construct a newly authenticated active session.
    pub fn new(session_id: SessionId, peer_id: PeerId, cipher: SessionCipher) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_id,
            cipher,
            replay_window: ReplayWindow::new(),
            send_seq: SequenceNumber::new(0),
            created_at: now,
            last_recv: now,
            last_sent: now,
            state: SessionState::Active,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    pub fn current_send_seq(&self) -> SequenceNumber {
        self.send_seq
    }

    /// Encrypt an IP packet into wire-format bytes, advancing sequence counter.
    pub fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>, HvpnError> {
        if self.state != SessionState::Active && self.state != SessionState::Rekeying {
            return Err(SessionError::InvalidState.into());
        }

        let seq = SequenceNumber::new(self.send_seq.next());
        self.last_sent = Instant::now();

        let packet = TypedPacket::Data {
            session_id: self.session_id,
            sequence: seq,
            payload: payload.to_vec(),
        };

        PacketCodec::encode(&packet, Some(&self.cipher))
    }

    /// Decrypt an incoming wire-format packet and update replay window.
    pub fn decrypt_packet(&mut self, raw_bytes: &[u8]) -> Result<TypedPacket, HvpnError> {
        if self.state != SessionState::Active && self.state != SessionState::Rekeying {
            return Err(SessionError::InvalidState.into());
        }

        let packet = PacketCodec::decode(
            raw_bytes,
            Some(&self.cipher),
            Some(&mut self.replay_window),
        )?;

        self.last_recv = Instant::now();
        Ok(packet)
    }

    /// Generate an encrypted keepalive ping packet.
    pub fn generate_keepalive(&mut self) -> Result<Vec<u8>, HvpnError> {
        let seq = SequenceNumber::new(self.send_seq.next());
        self.last_sent = Instant::now();

        let packet = TypedPacket::Keepalive {
            session_id: self.session_id,
            sequence: seq,
        };

        PacketCodec::encode(&packet, Some(&self.cipher))
    }

    /// Generate an encrypted close packet.
    pub fn generate_close(&mut self) -> Result<Vec<u8>, HvpnError> {
        let seq = SequenceNumber::new(self.send_seq.next());
        self.last_sent = Instant::now();
        self.state = SessionState::Closed;

        let packet = TypedPacket::Close {
            session_id: self.session_id,
            sequence: seq,
        };

        PacketCodec::encode(&packet, Some(&self.cipher))
    }

    /// True if no packet has been received within `timeout`.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_recv.elapsed() > timeout
    }

    /// True if no packet has been sent within `keepalive_interval`.
    pub fn needs_keepalive(&self, keepalive_interval: Duration) -> bool {
        self.last_sent.elapsed() >= keepalive_interval
    }

    /// Check if session requires rekeying ($2^{60}$ sequence threshold or > 1 hour duration).
    pub fn needs_rekey(&self) -> bool {
        self.send_seq.needs_rekey() || self.created_at.elapsed() >= Duration::from_secs(3600)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Session Manager
// ──────────────────────────────────────────────────────────────────────────────

/// Concurrent registry of active sessions indexed by `SessionId`.
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    peer_to_session: HashMap<PeerId, SessionId>,
    max_clients: usize,
}

impl SessionManager {
    pub fn new(max_clients: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            peer_to_session: HashMap::new(),
            max_clients,
        }
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Insert or replace an active session.
    pub fn insert(&mut self, session: Session) -> Result<(), SessionError> {
        if self.sessions.len() >= self.max_clients && !self.sessions.contains_key(&session.session_id) {
            return Err(SessionError::LimitReached);
        }

        let sid = session.session_id;
        let pid = session.peer_id.clone();

        self.peer_to_session.insert(pid, sid);
        self.sessions.insert(sid, session);
        Ok(())
    }

    pub fn get(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub fn get_mut(&mut self, session_id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    pub fn get_by_peer(&self, peer_id: &PeerId) -> Option<&Session> {
        self.peer_to_session
            .get(peer_id)
            .and_then(|sid| self.sessions.get(sid))
    }

    pub fn remove(&mut self, session_id: &SessionId) -> Option<Session> {
        if let Some(session) = self.sessions.remove(session_id) {
            self.peer_to_session.remove(&session.peer_id);
            Some(session)
        } else {
            None
        }
    }

    /// Scan and remove all sessions that have exceeded the idle `timeout`.
    pub fn clean_expired(&mut self, timeout: Duration) -> Vec<SessionId> {
        let mut expired = Vec::new();
        for (sid, sess) in &self.sessions {
            if sess.is_expired(timeout) {
                expired.push(*sid);
            }
        }

        for sid in &expired {
            self.remove(sid);
        }

        expired
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

    fn make_test_session_pair() -> (Session, Session) {
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

        let c_cipher = SessionCipher::from_handshake(c_hs).unwrap();
        let s_cipher = SessionCipher::from_handshake(s_hs).unwrap();

        let sid = SessionId::new(424242);
        let mut s_pub = [0u8; 32];
        s_pub.copy_from_slice(&s_keys.public);
        let mut c_pub = [0u8; 32];
        c_pub.copy_from_slice(&c_keys.public);

        let client_sess = Session::new(sid, PeerId::from_bytes(s_pub), c_cipher);
        let server_sess = Session::new(sid, PeerId::from_bytes(c_pub), s_cipher);

        (client_sess, server_sess)
    }

    #[test]
    fn test_session_encrypt_decrypt_lifecycle() {
        let (mut client, mut server) = make_test_session_pair();
        assert_eq!(client.state(), SessionState::Active);

        let ip_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let wire_bytes = client.encrypt_data(ip_payload).unwrap();

        let received_pkt = server.decrypt_packet(&wire_bytes).unwrap();
        match received_pkt {
            TypedPacket::Data {
                session_id,
                sequence,
                payload,
            } => {
                assert_eq!(session_id, client.session_id);
                assert_eq!(sequence.as_u64(), 0);
                assert_eq!(payload, ip_payload);
            }
            _ => panic!("Expected TypedPacket::Data"),
        }
    }

    #[test]
    fn test_session_keepalive_generation() {
        let (mut client, mut server) = make_test_session_pair();

        let keepalive_wire = client.generate_keepalive().unwrap();
        let decoded = server.decrypt_packet(&keepalive_wire).unwrap();

        assert!(matches!(decoded, TypedPacket::Keepalive { .. }));
    }

    #[test]
    fn test_session_manager_concurrency_and_eviction() {
        let mut mgr = SessionManager::new(2);

        let (sess1, _) = make_test_session_pair();
        let sid1 = sess1.session_id;
        mgr.insert(sess1).unwrap();
        assert_eq!(mgr.count(), 1);

        let mut sess2 = make_test_session_pair().0;
        let sid2 = SessionId::new(99999);
        sess2.session_id = sid2;
        sess2.peer_id = PeerId::from_bytes([77u8; 32]);
        mgr.insert(sess2).unwrap();
        assert_eq!(mgr.count(), 2);

        // Third session exceeds max_clients limit
        let mut sess3 = make_test_session_pair().0;
        sess3.session_id = SessionId::new(88888);
        sess3.peer_id = PeerId::from_bytes([88u8; 32]);
        assert_eq!(mgr.insert(sess3), Err(SessionError::LimitReached));

        // Removal
        assert!(mgr.remove(&sid1).is_some());
        assert_eq!(mgr.count(), 1);
    }
}

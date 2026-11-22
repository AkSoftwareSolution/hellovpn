//! hello-server — Concurrent HelloVPN server implementation.
//!
//! # Architecture
//! The server daemon acts as the central hub:
//! 1. Receives incoming UDP datagrams:
//!    - Dispatches Noise IK handshakes to [`HandshakeResponder`], validating against peer allow-lists.
//!    - Decapsulates authenticated [`TypedPacket::Data`] packets, verifies AEAD and replay window,
//!      and injects plaintext IP packets into the [`TunDevice`].
//!    - Responds to keepalives and terminates closed sessions.
//! 2. Receives outbound IP packets from the [`TunDevice`]:
//!    - Extracts destination IPv4 address.
//!    - Routes packet to the corresponding client session.
//!    - Encapsulates and encrypts via [`Session::encrypt_data`].
//!    - Transmits encrypted UDP datagram to client endpoint.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hello_config::ServerConfig;
use hello_core::{HvpnError, SessionError, SessionId};
use hello_handshake::{AllowListValidator, HandshakeResponder};
use hello_packet::TypedPacket;
use hello_protocol::{Packet, PacketType};
use hello_session::{Session, SessionManager};
use hello_transport::UdpTransport;
use hello_tun::TunDevice;

pub struct VpnServer<T: TunDevice> {
    config: ServerConfig,
    responder: HandshakeResponder<AllowListValidator>,
    sessions: SessionManager,
    session_endpoints: HashMap<SessionId, SocketAddr>,
    ip_to_session: HashMap<Ipv4Addr, SessionId>,
    peer_to_ip: HashMap<[u8; 32], Ipv4Addr>,
    transport: UdpTransport,
    tun: Arc<T>,
}

impl<T: TunDevice> VpnServer<T> {
    /// Create a new VPN server instance.
    pub fn new(
        config: ServerConfig,
        server_private_key: [u8; 32],
        transport: UdpTransport,
        tun: Arc<T>,
    ) -> Result<Self, HvpnError> {
        let mut allowed_keys = Vec::new();
        let mut peer_to_ip = HashMap::new();

        for peer in &config.peers {
            if let Ok(pub_bytes) = peer.public_key_bytes() {
                allowed_keys.push(pub_bytes);
                // Parse the first assigned IP
                if let Some(ip_str) = peer.allowed_ips.first() {
                    let clean_ip = ip_str.split('/').next().unwrap_or(ip_str);
                    if let Ok(ip) = clean_ip.parse::<Ipv4Addr>() {
                        peer_to_ip.insert(pub_bytes, ip);
                    }
                }
            }
        }

        let validator = AllowListValidator::new(allowed_keys);
        let responder = HandshakeResponder::new(server_private_key, validator);
        let sessions = SessionManager::new(config.limits.max_clients);

        Ok(Self {
            config,
            responder,
            sessions,
            session_endpoints: HashMap::new(),
            ip_to_session: HashMap::new(),
            peer_to_ip,
            transport,
            tun,
        })
    }

    /// Process a datagram received from the network.
    pub async fn handle_inbound_datagram(
        &mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(), HvpnError> {
        let raw_packet = Packet::decode(data)?;

        match raw_packet.packet_type {
            PacketType::Handshake => {
                tracing::info!(from = %from, "Received client handshake initiation");
                let (handshake_res, resp_pkt) = self.responder.process_initiation(&raw_packet)?;

                let sid = handshake_res.session_id;
                let pid = handshake_res.peer_id.clone();
                let pub_key = *pid.as_bytes();

                // Map client VPN IP if configured
                if let Some(&client_ip) = self.peer_to_ip.get(&pub_key) {
                    self.ip_to_session.insert(client_ip, sid);
                    tracing::info!(peer = %pid, %client_ip, %sid, "Associated client VPN IP");
                }

                let new_session = Session::new(sid, pid, handshake_res.cipher);
                self.sessions.insert(new_session)?;
                self.session_endpoints.insert(sid, from);

                // Send Message 2 response packet
                let resp_bytes = resp_pkt.encode()?;
                self.transport.send_to(&resp_bytes, from).await?;
                tracing::info!(to = %from, %sid, "Sent handshake response Message 2");
            }
            PacketType::Data => {
                let sid = SessionId::new(raw_packet.session_id);
                if let Some(session) = self.sessions.get_mut(&sid) {
                    // Update endpoint on roaming
                    self.session_endpoints.insert(sid, from);

                    let typed = session.decrypt_packet(data)?;
                    if let TypedPacket::Data { payload, .. } = typed {
                        // Forward unencapsulated IP packet into kernel TUN device
                        self.tun.write_packet(&payload).await?;
                    }
                } else {
                    return Err(SessionError::NotFound(sid.as_u64()).into());
                }
            }
            PacketType::Keepalive => {
                let sid = SessionId::new(raw_packet.session_id);
                if let Some(session) = self.sessions.get_mut(&sid) {
                    self.session_endpoints.insert(sid, from);
                    let _ = session.decrypt_packet(data)?;
                }
            }
            PacketType::Close => {
                let sid = SessionId::new(raw_packet.session_id);
                tracing::info!(%sid, "Client sent close notification");
                self.remove_session(&sid);
            }
            PacketType::Hello => {
                // Handled for capability probing
            }
        }

        Ok(())
    }

    /// Process an outbound IP packet read from the TUN interface.
    pub async fn handle_outbound_ip_packet(&mut self, packet: &[u8]) -> Result<(), HvpnError> {
        if packet.len() < 20 {
            return Ok(()); // Invalid IPv4 header length
        }

        // IPv4 destination address is at offset 16..20
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        if let Some(&sid) = self.ip_to_session.get(&dst_ip) {
            if let Some(endpoint) = self.session_endpoints.get(&sid).copied() {
                if let Some(session) = self.sessions.get_mut(&sid) {
                    let wire_bytes = session.encrypt_data(packet)?;
                    self.transport.send_to(&wire_bytes, endpoint).await?;
                }
            }
        }

        Ok(())
    }

    /// Evict inactive sessions exceeding timeout.
    pub fn clean_expired_sessions(&mut self) -> Vec<SessionId> {
        let timeout = Duration::from_secs(self.config.limits.session_timeout_secs);
        let expired = self.sessions.clean_expired(timeout);
        for sid in &expired {
            self.session_endpoints.remove(sid);
            self.ip_to_session.retain(|_, s| s != sid);
            tracing::info!(%sid, "Evicted expired VPN session");
        }
        expired
    }

    pub fn remove_session(&mut self, sid: &SessionId) {
        self.sessions.remove(sid);
        self.session_endpoints.remove(sid);
        self.ip_to_session.retain(|_, s| s != sid);
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.count()
    }

    /// Read an incoming datagram from the network transport and process it.
    pub async fn recv_and_process(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HvpnError> {
        let (n, from) = self.transport.recv_from(buf).await?;
        self.handle_inbound_datagram(&buf[..n], from).await?;
        Ok((n, from))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hello_config::ServerConfig;
    use hello_handshake::HandshakeInitiator;
    use hello_protocol::handshake::generate_static_keypair;
    use hello_tun::MockTun;

    async fn build_test_server(server_priv: [u8; 32], client_pub: [u8; 32]) -> (VpnServer<MockTun>, Arc<MockTun>) {
        use base64::Engine;
        let config_str = format!(
            r#"
[server]
listen = "127.0.0.1"
port = 0
transport = ["udp"]

[keys]
private_key_file = "/dummy.key"

[network]
tun_name = "hvpn_test"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1"]

[[peers]]
name = "test-client"
public_key = "{}"
allowed_ips = ["10.10.0.2/32"]
"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_pub)
        );

        let config = ServerConfig::from_str(&config_str).unwrap();
        let mock_tun = Arc::new(MockTun::new("hvpn_test", 1420));
        let loopback = "127.0.0.1:0".parse().unwrap();
        let transport = UdpTransport::bind(loopback).await.unwrap();

        let server = VpnServer::new(config, server_priv, transport, mock_tun.clone()).unwrap();
        (server, mock_tun)
    }

    #[tokio::test]
    async fn test_server_handshake_and_packet_routing() {
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

        let (mut server, mock_tun) = build_test_server(server_priv, client_pub).await;

        let client_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_socket_addr = client_transport.local_addr().unwrap();

        // 1. Client sends handshake init
        let initiator = HandshakeInitiator::new(server_pub, client_priv);
        let (initiator_state, msg1_pkt) = initiator.start().unwrap();
        let msg1_wire = msg1_pkt.encode().unwrap();

        server
            .handle_inbound_datagram(&msg1_wire, client_socket_addr)
            .await
            .unwrap();

        assert_eq!(server.active_session_count(), 1);

        // 2. Client receives Message 2 and completes handshake
        let mut resp_buf = vec![0u8; 1500];
        let n_resp = client_transport.recv(&mut resp_buf).await.unwrap();
        let resp_pkt = Packet::decode(&resp_buf[..n_resp]).unwrap();

        let client_res = HandshakeInitiator::complete(initiator_state, &resp_pkt).unwrap();
        let mut client_sess = Session::new(client_res.session_id, client_res.peer_id, client_res.cipher);

        // 3. Client sends encrypted Data packet
        // Simulated IP packet: From 10.10.0.2 to 8.8.8.8
        let mut ip_packet = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00];
        ip_packet.extend_from_slice(&[10, 10, 0, 2]); // src
        ip_packet.extend_from_slice(&[8, 8, 8, 8]); // dst

        let enc_data = client_sess.encrypt_data(&ip_packet).unwrap();
        server
            .handle_inbound_datagram(&enc_data, client_socket_addr)
            .await
            .unwrap();

        // The decapsulated IP packet should now appear in the kernel TUN
        let injected_to_tun = mock_tun.pop_to_kernel().await.unwrap();
        assert_eq!(injected_to_tun, ip_packet);
    }
}

//! hello-client — Linux VPN client daemon and tunnel manager.
//!
//! # Architecture
//! The client daemon manages the outbound tunnel:
//! 1. Resolves server address and binds a local UDP transport socket.
//! 2. Negotiates the 1-RTT Noise IK handshake using [`HandshakeInitiator`].
//! 3. Configures local virtual interface ([`TunDevice`]) with assigned VPN IP.
//! 4. Installs routes ([`RouteManager`]) and fail-safe kill switch.
//! 5. Bi-directional packet loop:
//!    - Outbound: Kernel IP packet -> AEAD encrypt with monotonic sequence number -> UDP socket.
//!    - Inbound: Encrypted UDP datagram -> AEAD decrypt & replay check -> Kernel TUN device.
//!    - Heartbeat: Keepalive packets every 25 seconds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hello_config::ClientConfig;
use hello_core::{HvpnError, SessionError};
use hello_handshake::{HandshakeInitiator, InitiatorState};
use hello_packet::TypedPacket;
use hello_protocol::{Packet, PacketType};
use hello_routing::RouteManager;
use hello_session::Session;
use hello_transport::UdpTransport;
use hello_tun::TunDevice;

pub struct VpnClient<T: TunDevice> {
    config: ClientConfig,
    client_private_key: [u8; 32],
    server_endpoint: SocketAddr,
    transport: UdpTransport,
    tun: Arc<T>,
    route_manager: RouteManager,
    session: Option<Session>,
    initiator_state: Option<InitiatorState>,
}

impl<T: TunDevice> VpnClient<T> {
    pub fn new(
        config: ClientConfig,
        client_private_key: [u8; 32],
        server_endpoint: SocketAddr,
        transport: UdpTransport,
        tun: Arc<T>,
        route_manager: RouteManager,
    ) -> Self {
        Self {
            config,
            client_private_key,
            server_endpoint,
            transport,
            tun,
            route_manager,
            session: None,
            initiator_state: None,
        }
    }

    /// Begin the Noise IK handshake by sending Message 1 to the server.
    pub async fn start_handshake(&mut self) -> Result<(), HvpnError> {
        let server_pub = self.config.server_public_key_bytes()?;
        let initiator = HandshakeInitiator::new(server_pub, self.client_private_key);

        let (state, msg1_pkt) = initiator.start()?;
        let msg1_wire = msg1_pkt.encode()?;

        self.transport.send_to(&msg1_wire, self.server_endpoint).await?;
        self.initiator_state = Some(state);
        tracing::info!(to = %self.server_endpoint, "Transmitted handshake initiation Message 1");
        Ok(())
    }

    /// Process a response datagram from the server.
    pub async fn handle_inbound_datagram(&mut self, data: &[u8]) -> Result<(), HvpnError> {
        // If still in handshake phase, check for Handshake packet
        if let Some(state) = self.initiator_state.take() {
            let raw_pkt = Packet::decode(data)?;
            if raw_pkt.packet_type == PacketType::Handshake {
                let res = HandshakeInitiator::complete(state, &raw_pkt)?;
                let session = Session::new(res.session_id, res.peer_id, res.cipher);
                self.session = Some(session);

                // Configure interface and routes
                let dev_name = self.tun.name();
                self.route_manager
                    .setup_interface(dev_name, &self.config.network.ipv4, self.tun.mtu())
                    .await?;

                for route in &self.config.network.routes {
                    self.route_manager.add_route(route, dev_name).await?;
                }

                tracing::info!(session_id = %res.session_id, "VPN connection established and tunnel active");
                return Ok(());
            } else {
                // Restore initiator state if unexpected packet arrived
                self.initiator_state = Some(state);
            }
        }

        // Active session data handling
        if let Some(session) = self.session.as_mut() {
            let typed = session.decrypt_packet(data)?;
            match typed {
                TypedPacket::Data { payload, .. } => {
                    self.tun.write_packet(&payload).await?;
                }
                TypedPacket::Keepalive { .. } => {
                    tracing::trace!("Received keepalive ping from server");
                }
                TypedPacket::Close { .. } => {
                    tracing::warn!("Server sent close packet, disconnecting");
                    self.disconnect().await?;
                }
                _ => {}
            }
        } else {
            return Err(SessionError::InvalidState.into());
        }

        Ok(())
    }

    /// Encrypt and transmit an outbound IP packet from the local TUN interface.
    pub async fn handle_outbound_ip_packet(&mut self, packet: &[u8]) -> Result<(), HvpnError> {
        if let Some(session) = self.session.as_mut() {
            let wire_bytes = session.encrypt_data(packet)?;
            self.transport.send_to(&wire_bytes, self.server_endpoint).await?;
            Ok(())
        } else {
            Err(SessionError::InvalidState.into())
        }
    }

    /// Check if keepalive interval elapsed and send keepalive ping.
    pub async fn send_keepalive_if_needed(&mut self) -> Result<(), HvpnError> {
        let interval = Duration::from_secs(self.config.client.keepalive);
        if let Some(session) = self.session.as_mut() {
            if session.needs_keepalive(interval) {
                let keepalive_wire = session.generate_keepalive()?;
                self.transport
                    .send_to(&keepalive_wire, self.server_endpoint)
                    .await?;
                tracing::trace!("Sent keepalive to server");
            }
        }
        Ok(())
    }

    /// Disconnect session and restore routing.
    pub async fn disconnect(&mut self) -> Result<(), HvpnError> {
        if let Some(mut session) = self.session.take() {
            if let Ok(close_pkt) = session.generate_close() {
                let _ = self.transport.send_to(&close_pkt, self.server_endpoint).await;
            }
        }
        self.route_manager.cleanup().await?;
        tracing::info!("VPN client disconnected cleanly");
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hello_config::ClientConfig;
    use hello_protocol::handshake::generate_static_keypair;
    use hello_tun::MockTun;

    async fn build_test_client(
        client_priv: [u8; 32],
        client_pub: [u8; 32],
        server_pub: [u8; 32],
        server_endpoint: SocketAddr,
    ) -> (VpnClient<MockTun>, Arc<MockTun>) {
        use base64::Engine;
        let c_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_pub);
        let s_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub);

        let config_str = format!(
            r#"
protocol = "hellovpn"
version = 1

[connection]
server = "127.0.0.1"
port = {}
transport = "udp"

[security]
handshake = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
server_public_key = "{}"
client_public_key = "{}"

[network]
ipv4 = "10.10.0.2/24"
dns = ["1.1.1.1"]
routes = ["0.0.0.0/0"]
mtu = 1420

[client]
name = "test-client"
keepalive = 25
"#,
            server_endpoint.port(),
            s_b64,
            c_b64
        );

        let config = ClientConfig::from_str(&config_str).unwrap();
        let mock_tun = Arc::new(MockTun::new("hvpn_client_test", 1420));
        let loopback = "127.0.0.1:0".parse().unwrap();
        let transport = UdpTransport::bind(loopback).await.unwrap();
        let route_mgr = RouteManager::new_dry_run();

        let client = VpnClient::new(
            config,
            client_priv,
            server_endpoint,
            transport,
            mock_tun.clone(),
            route_mgr,
        );

        (client, mock_tun)
    }

    #[tokio::test]
    async fn test_client_handshake_and_tun_forwarding() {
        let server_keys = generate_static_keypair().unwrap();
        let client_keys = generate_static_keypair().unwrap();

        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_keys.public);

        let mut client_priv = [0u8; 32];
        client_priv.copy_from_slice(&client_keys.private);
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&client_keys.public);

        let server_endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let (mut client, _mock_tun) =
            build_test_client(client_priv, client_pub, server_pub, server_endpoint).await;

        assert!(!client.is_connected());

        // Start handshake
        client.start_handshake().await.unwrap();
        assert!(client.initiator_state.is_some());
    }
}

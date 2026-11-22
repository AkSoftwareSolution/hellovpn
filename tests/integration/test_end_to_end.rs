use std::sync::Arc;
use base64::Engine;

use hello_config::{ClientConfig, ServerConfig};
use hello_client::VpnClient;
use hello_protocol::handshake::generate_static_keypair;
use hello_routing::RouteManager;
use hello_server::VpnServer;
use hello_transport::UdpTransport;
use hello_tun::MockTun;

#[tokio::test]
async fn test_end_to_end_handshake_and_bidirectional_tunnel() {
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

    let s_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub);
    let c_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_pub);

    // 1. Create Server
    let server_config_str = format!(
        r#"
[server]
listen = "127.0.0.1"
port = 0
transport = ["udp"]

[keys]
private_key_file = "/dummy.key"

[network]
tun_name = "hvpn_srv_tun"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1"]

[[peers]]
name = "alice"
public_key = "{}"
allowed_ips = ["10.10.0.2/32"]
"#,
        c_pub_b64
    );

    let server_config = ServerConfig::from_str(&server_config_str).unwrap();
    let server_tun = Arc::new(MockTun::new("hvpn_srv_tun", 1420));
    let server_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let server_endpoint = server_transport.local_addr().unwrap();

    let mut server = VpnServer::new(
        server_config,
        server_priv,
        server_transport,
        server_tun.clone(),
    )
    .unwrap();

    // 2. Create Client
    let client_config_str = format!(
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
name = "alice-laptop"
keepalive = 25
"#,
        server_endpoint.port(),
        s_pub_b64,
        c_pub_b64
    );

    let client_config = ClientConfig::from_str(&client_config_str).unwrap();
    let client_tun = Arc::new(MockTun::new("hvpn_clt_tun", 1420));
    let client_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let client_endpoint = client_transport.local_addr().unwrap();
    let client_route_mgr = RouteManager::new_dry_run();

    let mut client = VpnClient::new(
        client_config,
        client_priv,
        server_endpoint,
        client_transport.clone(),
        client_tun.clone(),
        client_route_mgr,
    );

    // 3. Initiate Handshake (Client -> Server)
    client.start_handshake().await.unwrap();

    // Server receives Message 1 from client
    let mut wire_buf = vec![0u8; 1500];
    let (_n1, from) = server.recv_and_process(&mut wire_buf).await.unwrap();
    assert_eq!(from, client_endpoint);

    // Client receives Message 2 from server
    let mut client_buf = vec![0u8; 1500];
    let n2 = client_transport.recv(&mut client_buf).await.unwrap();
    client.handle_inbound_datagram(&client_buf[..n2]).await.unwrap();
    assert!(client.is_connected());

    // 4. Test Client -> Server tunnel transmission
    // Outbound IP packet from client: 10.10.0.2 -> 1.1.1.1
    let mut client_ip_packet = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00];
    client_ip_packet.extend_from_slice(&[10, 10, 0, 2]); // src
    client_ip_packet.extend_from_slice(&[1, 1, 1, 1]); // dst
    client_ip_packet.extend_from_slice(b"DNS query packet payload");

    client.handle_outbound_ip_packet(&client_ip_packet).await.unwrap();

    // Server receives encrypted packet and writes to server TUN
    let (n3, _) = server.recv_and_process(&mut wire_buf).await.unwrap();
    assert!(n3 > 0);

    let server_tun_pkt = server_tun.pop_to_kernel().await.unwrap();
    assert_eq!(server_tun_pkt, client_ip_packet);

    // 5. Test Server -> Client tunnel transmission (Return traffic)
    // Server routes back to 10.10.0.2
    let mut server_reply = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00];
    server_reply.extend_from_slice(&[1, 1, 1, 1]); // src
    server_reply.extend_from_slice(&[10, 10, 0, 2]); // dst
    server_reply.extend_from_slice(b"DNS response packet payload");

    server.handle_outbound_ip_packet(&server_reply).await.unwrap();

    let n4 = client_transport.recv(&mut client_buf).await.unwrap();
    client.handle_inbound_datagram(&client_buf[..n4]).await.unwrap();

    let client_tun_pkt = client_tun.pop_to_kernel().await.unwrap();
    assert_eq!(client_tun_pkt, server_reply);
}

#[tokio::test]
async fn test_unauthorized_client_handshake_rejected() {
    let server_keys = generate_static_keypair().unwrap();
    let attacker_keys = generate_static_keypair().unwrap();

    let mut server_priv = [0u8; 32];
    server_priv.copy_from_slice(&server_keys.private);
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&server_keys.public);

    let mut attacker_priv = [0u8; 32];
    attacker_priv.copy_from_slice(&attacker_keys.private);
    let mut attacker_pub = [0u8; 32];
    attacker_pub.copy_from_slice(&attacker_keys.public);

    let s_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub);
    let att_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attacker_pub);

    // Server only authorizes alice, not attacker
    let server_config_str = format!(
        r#"
[server]
listen = "127.0.0.1"
port = 0
transport = ["udp"]

[keys]
private_key_file = "/dummy.key"

[network]
tun_name = "hvpn_srv_tun2"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1"]

[[peers]]
name = "alice"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
allowed_ips = ["10.10.0.2/32"]
"#
    );

    let server_config = ServerConfig::from_str(&server_config_str).unwrap();
    let server_tun = Arc::new(MockTun::new("hvpn_srv_tun2", 1420));
    let server_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let server_endpoint = server_transport.local_addr().unwrap();

    let mut server = VpnServer::new(
        server_config,
        server_priv,
        server_transport,
        server_tun,
    )
    .unwrap();

    let attacker_config_str = format!(
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
ipv4 = "10.10.0.3/24"
dns = ["1.1.1.1"]
routes = ["0.0.0.0/0"]
mtu = 1420

[client]
name = "attacker"
keepalive = 25
"#,
        server_endpoint.port(),
        s_pub_b64,
        att_pub_b64
    );

    let attacker_config = ClientConfig::from_str(&attacker_config_str).unwrap();
    let attacker_tun = Arc::new(MockTun::new("hvpn_att_tun", 1420));
    let attacker_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut attacker_client = VpnClient::new(
        attacker_config,
        attacker_priv,
        server_endpoint,
        attacker_transport,
        attacker_tun,
        RouteManager::new_dry_run(),
    );

    attacker_client.start_handshake().await.unwrap();

    let mut wire_buf = vec![0u8; 1500];
    let result = server.recv_and_process(&mut wire_buf).await;

    assert!(result.is_err(), "Server must reject unauthorized client handshake");
    assert_eq!(server.active_session_count(), 0);
}

#[tokio::test]
async fn test_client_rejects_impostor_server_handshake() {
    let legit_server_keys = generate_static_keypair().unwrap();
    let impostor_server_keys = generate_static_keypair().unwrap();
    let client_keys = generate_static_keypair().unwrap();

    let mut legit_server_pub = [0u8; 32];
    legit_server_pub.copy_from_slice(&legit_server_keys.public);

    let mut impostor_server_priv = [0u8; 32];
    impostor_server_priv.copy_from_slice(&impostor_server_keys.private);

    let mut client_priv = [0u8; 32];
    client_priv.copy_from_slice(&client_keys.private);
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&client_keys.public);

    let legit_s_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(legit_server_pub);
    let c_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_pub);

    // Impostor server config (it knows client, but uses impostor private key)
    let impostor_config_str = format!(
        r#"
[server]
listen = "127.0.0.1"
port = 0
transport = ["udp"]

[keys]
private_key_file = "/dummy.key"

[network]
tun_name = "hvpn_imp_tun"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1"]

[[peers]]
name = "alice"
public_key = "{}"
allowed_ips = ["10.10.0.2/32"]
"#,
        c_pub_b64
    );

    let impostor_config = ServerConfig::from_str(&impostor_config_str).unwrap();
    let impostor_tun = Arc::new(MockTun::new("hvpn_imp_tun", 1420));
    let impostor_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let impostor_endpoint = impostor_transport.local_addr().unwrap();

    let mut impostor_server = VpnServer::new(
        impostor_config,
        impostor_server_priv,
        impostor_transport,
        impostor_tun,
    )
    .unwrap();

    // Client is configured expecting the legitimate server public key
    let client_config_str = format!(
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
name = "alice"
keepalive = 25
"#,
        impostor_endpoint.port(),
        legit_s_pub_b64,
        c_pub_b64
    );

    let client_config = ClientConfig::from_str(&client_config_str).unwrap();
    let client_tun = Arc::new(MockTun::new("hvpn_clt_tun2", 1420));
    let client_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut client = VpnClient::new(
        client_config,
        client_priv,
        impostor_endpoint,
        client_transport.clone(),
        client_tun,
        RouteManager::new_dry_run(),
    );

    // Client initiates handshake
    client.start_handshake().await.unwrap();

    // Impostor server receives Message 1, but cannot decrypt it because it lacks the legit server private key
    let mut wire_buf = vec![0u8; 1500];
    let impostor_res = impostor_server.recv_and_process(&mut wire_buf).await;
    assert!(
        impostor_res.is_err(),
        "Impostor server must fail to decrypt Message 1 encrypted with legit server key"
    );

    // If the impostor sends a forged or arbitrary response packet back to the client:
    let forged_response = hello_protocol::Packet {
        packet_type: hello_protocol::PacketType::Handshake,
        flags: 0,
        session_id: 0,
        sequence: 1,
        payload: vec![0xAA; 48],
    }
    .encode()
    .unwrap();

    let client_res = client.handle_inbound_datagram(&forged_response).await;

    // Handshake must fail at client
    assert!(client_res.is_err(), "Client must reject response from impostor server");
    assert!(!client.is_connected(), "Client must not be connected to impostor");
}

#[tokio::test]
async fn test_corrupted_handshake_response_packet_rejected() {
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

    let s_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub);
    let c_pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_pub);

    let server_config_str = format!(
        r#"
[server]
listen = "127.0.0.1"
port = 0
transport = ["udp"]

[keys]
private_key_file = "/dummy.key"

[network]
tun_name = "hvpn_srv_corrupt"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1"]

[[peers]]
name = "alice"
public_key = "{}"
allowed_ips = ["10.10.0.2/32"]
"#,
        c_pub_b64
    );

    let server_config = ServerConfig::from_str(&server_config_str).unwrap();
    let server_tun = Arc::new(MockTun::new("hvpn_srv_corrupt", 1420));
    let server_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let server_endpoint = server_transport.local_addr().unwrap();

    let mut server = VpnServer::new(
        server_config,
        server_priv,
        server_transport,
        server_tun,
    )
    .unwrap();

    let client_config_str = format!(
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
name = "alice"
keepalive = 25
"#,
        server_endpoint.port(),
        s_pub_b64,
        c_pub_b64
    );

    let client_config = ClientConfig::from_str(&client_config_str).unwrap();
    let client_tun = Arc::new(MockTun::new("hvpn_clt_corrupt", 1420));
    let client_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut client = VpnClient::new(
        client_config,
        client_priv,
        server_endpoint,
        client_transport.clone(),
        client_tun,
        RouteManager::new_dry_run(),
    );

    client.start_handshake().await.unwrap();

    let mut wire_buf = vec![0u8; 1500];
    let (_n, _) = server.recv_and_process(&mut wire_buf).await.unwrap();

    let mut client_buf = vec![0u8; 1500];
    let n2 = client_transport.recv(&mut client_buf).await.unwrap();

    // Corrupt payload of Message 2
    if n2 > 30 {
        client_buf[28] ^= 0xff;
    }

    let result = client.handle_inbound_datagram(&client_buf[..n2]).await;
    assert!(result.is_err(), "Client must reject corrupted Message 2 datagram");
    assert!(!client.is_connected());
}

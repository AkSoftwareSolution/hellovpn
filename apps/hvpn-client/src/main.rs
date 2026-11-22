use clap::Parser;
use hello_client::VpnClient;
use hello_config::ClientConfig;
use hello_crypto::KeyPair;
use hello_routing::RouteManager;
use hello_transport::UdpTransport;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "hvpn-client", about = "HelloVPN Daemon Client")]
struct Args {
    #[arg(short, long, default_value = "client.hvpn")]
    config: String,
    #[arg(short, long)]
    key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!(config = %args.config, "Loading HelloVPN Client configuration");
    let client_config = ClientConfig::from_file(&args.config)?;

    let key_path_str = args
        .key
        .as_ref()
        .or(client_config.security.private_key_file.as_ref())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Client private key file must be specified via --key or in .hvpn config",
            )
        })?;

    let keypair = KeyPair::load_from_two_line_file(Path::new(key_path_str))?;

    let server_addr: SocketAddr = format!(
        "{}:{}",
        client_config.connection.server, client_config.connection.port
    )
    .parse()?;

    let local_bind: SocketAddr = "0.0.0.0:0".parse()?;
    let transport = UdpTransport::connect(local_bind, server_addr).await?;

    #[cfg(target_os = "linux")]
    let tun = Arc::new(hello_tun::LinuxTun::create(
        "hvpn0",
        client_config.network.mtu,
    )?);

    #[cfg(not(target_os = "linux"))]
    let tun = Arc::new(hello_tun::MockTun::new(
        "hvpn0",
        client_config.network.mtu,
    ));

    let route_mgr = RouteManager::new();

    let mut client = VpnClient::new(
        client_config,
        *keypair.private_bytes(),
        server_addr,
        transport,
        tun,
        route_mgr,
    );

    tracing::info!("Initiating handshake with server...");
    client.start_handshake().await?;

    tokio::signal::ctrl_c().await?;
    tracing::info!("Disconnecting client...");
    client.disconnect().await?;

    Ok(())
}

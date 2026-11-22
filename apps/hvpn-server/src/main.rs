use clap::Parser;
use hello_config::ServerConfig;
use hello_crypto::KeyPair;
use hello_server::VpnServer;
use hello_transport::UdpTransport;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "hvpn-server", about = "HelloVPN Daemon Server")]
struct Args {
    #[arg(short, long, default_value = "/etc/hvpn/server.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!(config = %args.config, "Initializing HelloVPN Server");

    let server_config = ServerConfig::from_file(&args.config)?;
    let key_path = Path::new(&server_config.keys.private_key_file);
    let keypair = KeyPair::load_from_two_line_file(key_path)?;

    let bind_addr: SocketAddr = format!("{}:{}", server_config.server.listen, server_config.server.port).parse()?;
    let transport = UdpTransport::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "Bound UDP socket");

    #[cfg(target_os = "linux")]
    let tun = Arc::new(hello_tun::LinuxTun::create(
        &server_config.network.tun_name,
        server_config.network.mtu,
    )?);

    #[cfg(not(target_os = "linux"))]
    let tun = Arc::new(hello_tun::MockTun::new(
        &server_config.network.tun_name,
        server_config.network.mtu,
    ));

    let _server = VpnServer::new(
        server_config,
        *keypair.private_bytes(),
        transport,
        tun,
    )?;

    tracing::info!("HelloVPN server active and waiting for connections");

    tokio::signal::ctrl_c().await?;
    tracing::info!("Received shutdown signal, terminating server");

    Ok(())
}

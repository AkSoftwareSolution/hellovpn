//! hello-cli — Command line parsing and dispatch for HelloVPN.

use std::path::Path;
use clap::{Parser, Subcommand};
use hello_core::HvpnError;
use hello_crypto::KeyPair;

#[derive(Parser, Debug)]
#[command(
    name = "hvpn",
    version = "0.1.0",
    about = "HelloVPN (HVPN) - High-Performance Secure VPN Protocol"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Server lifecycle management commands
    Server {
        #[command(subcommand)]
        action: ServerCommands,
    },
    /// Client connection and configuration commands
    Client {
        #[command(subcommand)]
        action: ClientCommands,
    },
    /// Cryptographic key generation and inspection
    Key {
        #[command(subcommand)]
        action: KeyCommands,
    },
    /// Display HelloVPN protocol version and build details
    Version,
}

#[derive(Subcommand, Debug)]
pub enum ServerCommands {
    /// Install server configuration and systemd service files
    Install {
        #[arg(short, long, default_value = "/etc/hvpn/server.toml")]
        config: String,
    },
    /// Start the HelloVPN server daemon
    Start {
        #[arg(short, long, default_value = "/etc/hvpn/server.toml")]
        config: String,
    },
    /// Stop running server daemon
    Stop,
    /// Query server status and connected peer list
    Status,
}

#[derive(Subcommand, Debug)]
pub enum ClientCommands {
    /// Generate a fresh `.hvpn` client configuration file
    GenerateConfig {
        #[arg(short, long)]
        server: String,
        #[arg(short, long, default_value_t = 51820)]
        port: u16,
        #[arg(short, long)]
        server_key: String,
        #[arg(short, long, default_value = "client.hvpn")]
        out: String,
    },
    /// Connect to a VPN server using an `.hvpn` configuration
    Connect {
        #[arg(short, long, default_value = "client.hvpn")]
        config: String,
    },
    /// Terminate active VPN connection
    Disconnect,
    /// Show client connection metrics and link status
    Status,
}

#[derive(Subcommand, Debug)]
pub enum KeyCommands {
    /// Generate a fresh X25519 static keypair
    Generate {
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Display the public key derived from a key file
    Show {
        #[arg(short, long)]
        key_file: String,
    },
}

impl Cli {
    /// Execute the parsed CLI command.
    pub async fn run(self) -> Result<(), HvpnError> {
        match self.command {
            Commands::Version => {
                println!("HelloVPN (HVPN)");
                println!("Protocol Version: HVPN/1 (0x01)");
                println!("Handshake: Noise_IK_25519_ChaChaPoly_BLAKE2s");
                println!("Cipher: ChaCha20-Poly1305 (16-byte AEAD tag)");
                println!("CLI Version: 0.1.0");
                Ok(())
            }
            Commands::Key { action } => match action {
                KeyCommands::Generate { out } => {
                    let keypair = KeyPair::generate()?;
                    let pub_b64 = keypair.public.to_base64();

                    println!("Generated fresh X25519 static keypair:");
                    println!("Public Key (share with server):  {pub_b64}");

                    if let Some(out_path) = out {
                        let path = Path::new(&out_path);
                        keypair.save_to_file(path)?;
                        println!("Private key stored securely at: {out_path} (mode 0600)");
                    } else {
                        println!("Warning: No output path specified; private key was zeroized on drop.");
                    }
                    Ok(())
                }
                KeyCommands::Show { key_file } => {
                    let path = Path::new(&key_file);
                    let keypair = KeyPair::load_from_two_line_file(path)?;
                    println!("Public Key: {}", keypair.public.to_base64());
                    Ok(())
                }
            },
            Commands::Client { action } => match action {
                ClientCommands::GenerateConfig {
                    server,
                    port,
                    server_key,
                    out,
                } => {
                    let kp = KeyPair::generate()?;
                    let client_pub = kp.public.to_base64();

                    let template = format!(
                        r#"protocol = "hellovpn"
version = 1

[connection]
server = "{server}"
port = {port}
transport = "udp"

[security]
handshake = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
server_public_key = "{server_key}"
client_public_key = "{client_pub}"

[network]
ipv4 = "10.10.0.2/24"
dns = ["1.1.1.1", "1.0.0.1"]
routes = ["0.0.0.0/0"]
mtu = 1420

[client]
name = "my-device"
keepalive = 25
"#
                    );

                    std::fs::write(&out, template)?;
                    println!("Generated client configuration file: {out}");
                    println!("Client Public Key to register on server: {client_pub}");
                    Ok(())
                }
                ClientCommands::Connect { config } => {
                    println!("Connecting using configuration: {config}...");
                    Ok(())
                }
                ClientCommands::Disconnect => {
                    println!("Disconnecting HelloVPN client...");
                    Ok(())
                }
                ClientCommands::Status => {
                    println!("HelloVPN Client: Disconnected");
                    Ok(())
                }
            },
            Commands::Server { action } => match action {
                ServerCommands::Install { config } => {
                    println!("Installing HelloVPN server configuration at {config}...");
                    Ok(())
                }
                ServerCommands::Start { config } => {
                    println!("Starting HelloVPN server daemon with {config}...");
                    Ok(())
                }
                ServerCommands::Stop => {
                    println!("Stopping HelloVPN server daemon...");
                    Ok(())
                }
                ServerCommands::Status => {
                    println!("HelloVPN Server: Inactive");
                    Ok(())
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::try_parse_from(["hvpn", "version"]).unwrap();
        assert!(matches!(cli.command, Commands::Version));

        let key_gen = Cli::try_parse_from(["hvpn", "key", "generate"]).unwrap();
        assert!(matches!(key_gen.command, Commands::Key { .. }));
    }
}

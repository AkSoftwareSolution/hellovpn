//! Server `.toml` configuration.

use serde::{Deserialize, Serialize};
use hello_core::ConfigError;
use crate::decode_public_key;

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerNetworkConfig {
    /// TUN interface name.
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// IPv4 pool CIDR for client allocation (e.g. "10.10.0.0/24").
    pub ipv4_pool: String,
    /// MTU for the TUN interface.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// DNS servers pushed to clients.
    pub dns: Vec<String>,
}

fn default_tun_name() -> String { "hvpn0".to_string() }
fn default_mtu()      -> u16    { 1420 }

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKeysConfig {
    /// Path to the server's X25519 private key file (chmod 600, root only).
    pub private_key_file: String,
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLimitsConfig {
    /// Maximum concurrent VPN clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
    /// Handshake timeout in seconds.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    /// Session idle timeout in seconds.
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,
    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    /// Rate limit: max handshake attempts per minute per source IP.
    #[serde(default = "default_rate_limit")]
    pub max_handshakes_per_min_per_ip: u32,
}

fn default_max_clients()        -> usize { 100 }
fn default_handshake_timeout()  -> u64   { 10 }
fn default_session_timeout()    -> u64   { 90 }
fn default_keepalive()          -> u64   { 25 }
fn default_rate_limit()         -> u32   { 5 }

impl Default for ServerLimitsConfig {
    fn default() -> Self {
        Self {
            max_clients: default_max_clients(),
            handshake_timeout_secs: default_handshake_timeout(),
            session_timeout_secs: default_session_timeout(),
            keepalive_secs: default_keepalive(),
            max_handshakes_per_min_per_ip: default_rate_limit(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────

/// A registered VPN peer (client) entry in the server allow-list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Human-readable name for logging.
    pub name: String,
    /// Client's static X25519 public key (base64url, 32 bytes).
    pub public_key: String,
    /// CIDRs this peer is allowed to route.
    pub allowed_ips: Vec<String>,
}

impl PeerConfig {
    pub fn public_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        decode_public_key(&self.public_key)
            .map_err(|_| ConfigError::InvalidKey(format!("peer {:?}: bad public_key", self.name)))
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerListenConfig {
    /// Bind address (default "0.0.0.0").
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Bind port (default 51820).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Enabled transports.
    #[serde(default = "default_transport")]
    pub transport: Vec<String>,
}

fn default_listen()    -> String       { "0.0.0.0".to_string() }
fn default_port()      -> u16          { 51820 }
fn default_transport() -> Vec<String>  { vec!["udp".to_string()] }

// ──────────────────────────────────────────────────────────────────────────────

/// Top-level server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerListenConfig,
    pub keys: ServerKeysConfig,
    pub network: ServerNetworkConfig,
    #[serde(default)]
    pub limits: ServerLimitsConfig,
    #[serde(default, rename = "peers")]
    pub peers: Vec<PeerConfig>,
}

impl ServerConfig {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_str(&raw)
    }

    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: ServerConfig = toml::from_str(s)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.keys.private_key_file.is_empty() {
            return Err(ConfigError::MissingField("server.keys.private_key_file"));
        }
        for peer in &self.peers {
            peer.public_key_bytes()?;
        }
        Ok(())
    }

    /// Find a peer by their public key bytes.
    pub fn find_peer_by_key(&self, key: &[u8; 32]) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| {
            p.public_key_bytes().ok().as_ref() == Some(key)
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn dummy_key() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32])
    }

    fn valid_toml() -> String {
        format!(r#"
[server]
listen = "0.0.0.0"
port = 51820
transport = ["udp"]

[keys]
private_key_file = "/etc/hvpn/server.key"

[network]
tun_name = "hvpn0"
ipv4_pool = "10.10.0.0/24"
mtu = 1420
dns = ["1.1.1.1"]

[[peers]]
name = "alice"
public_key = "{key}"
allowed_ips = ["10.10.0.2/32"]
"#, key = dummy_key())
    }

    #[test]
    fn parse_server_config() {
        let cfg = ServerConfig::from_str(&valid_toml()).unwrap();
        assert_eq!(cfg.server.port, 51820);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].name, "alice");
    }

    #[test]
    fn find_peer_by_key() {
        let cfg = ServerConfig::from_str(&valid_toml()).unwrap();
        let found = cfg.find_peer_by_key(&[1u8; 32]);
        assert!(found.is_some());
        let missing = cfg.find_peer_by_key(&[99u8; 32]);
        assert!(missing.is_none());
    }

    #[test]
    fn reject_bad_peer_key() {
        let bad = valid_toml().replace(
            &dummy_key(), "not_valid!!!"
        );
        assert!(ServerConfig::from_str(&bad).is_err());
    }
}

//! Client `.hvpn` configuration.

use serde::{Deserialize, Serialize};
use hello_core::ConfigError;
use crate::decode_public_key;

/// Transport protocol preference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    Udp,
    Tcp,
}

impl Default for TransportMode {
    fn default() -> Self { Self::Udp }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Server hostname or IP address.
    pub server: String,
    /// Server port (default 51820).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Primary transport protocol.
    #[serde(default)]
    pub transport: TransportMode,
}

fn default_port() -> u16 { 51820 }

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Must be "Noise_IK_25519_ChaChaPoly_BLAKE2s"
    #[serde(default = "default_handshake")]
    pub handshake: String,
    /// Server's static X25519 public key (base64url, 32 bytes).
    pub server_public_key: String,
    /// Client's public key (base64url, 32 bytes) — for registration purposes.
    pub client_public_key: String,
    /// Path to the client's private key file (chmod 600).
    /// If None, the OS keychain is used (platform-dependent).
    pub private_key_file: Option<String>,
}

fn default_handshake() -> String {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".to_string()
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// VPN IPv4 address and prefix length (e.g. "10.10.0.2/24").
    pub ipv4: String,
    /// VPN IPv6 address (optional).
    pub ipv6: Option<String>,
    /// DNS servers to configure inside the tunnel.
    pub dns: Vec<String>,
    /// Routes to push through the tunnel.
    /// "0.0.0.0/0" for full-tunnel mode; specific CIDRs for split-tunnel.
    #[serde(default = "default_routes")]
    pub routes: Vec<String>,
    /// MTU for the TUN interface.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_routes() -> Vec<String> { vec!["0.0.0.0/0".to_string()] }
fn default_mtu()    -> u16         { 1420 }

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Human-readable device name (sent to server for logging).
    pub name: String,
    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive: u64,
}

fn default_keepalive() -> u64 { 25 }

// ──────────────────────────────────────────────────────────────────────────────

/// Top-level client configuration, as parsed from a `.hvpn` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub protocol: String,
    pub version: u32,
    pub connection: ConnectionConfig,
    pub security: SecurityConfig,
    pub network: NetworkConfig,
    pub client: ClientIdentity,
}

impl ClientConfig {
    /// Parse from a `.hvpn` file (TOML format).
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_str(&raw)
    }

    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: ClientConfig = toml::from_str(s)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate all fields, returning the first error encountered.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.protocol != "hellovpn" {
            return Err(ConfigError::Parse(format!(
                "unknown protocol {:?}; expected \"hellovpn\"",
                self.protocol
            )));
        }
        if self.version != 1 {
            return Err(ConfigError::VersionMismatch(self.version));
        }
        if self.connection.server.is_empty() {
            return Err(ConfigError::MissingField("connection.server"));
        }
        // Validate server public key
        decode_public_key(&self.security.server_public_key)
            .map_err(|_| ConfigError::InvalidKey("security.server_public_key".into()))?;
        decode_public_key(&self.security.client_public_key)
            .map_err(|_| ConfigError::InvalidKey("security.client_public_key".into()))?;
        if self.security.handshake != "Noise_IK_25519_ChaChaPoly_BLAKE2s" {
            return Err(ConfigError::Parse(format!(
                "unsupported handshake {:?}", self.security.handshake
            )));
        }
        Ok(())
    }

    /// Serialise to TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Decoded server public key bytes.
    pub fn server_public_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        decode_public_key(&self.security.server_public_key)
    }

    /// Decoded client public key bytes.
    pub fn client_public_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        decode_public_key(&self.security.client_public_key)
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
        // 32 zero bytes in base64url
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])
    }

    fn valid_toml() -> String {
        format!(r#"
protocol = "hellovpn"
version = 1

[connection]
server = "vpn.example.com"
port = 51820
transport = "udp"

[security]
handshake = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
server_public_key = "{key}"
client_public_key = "{key}"

[network]
ipv4 = "10.10.0.2/24"
dns = ["1.1.1.1"]
routes = ["0.0.0.0/0"]
mtu = 1420

[client]
name = "test-device"
keepalive = 25
"#, key = dummy_key())
    }

    #[test]
    fn parse_valid_config() {
        let cfg = ClientConfig::from_str(&valid_toml()).unwrap();
        assert_eq!(cfg.connection.server, "vpn.example.com");
        assert_eq!(cfg.connection.port, 51820);
        assert_eq!(cfg.network.mtu, 1420);
    }

    #[test]
    fn reject_wrong_protocol() {
        let bad = valid_toml().replace("hellovpn", "openvpn");
        assert!(ClientConfig::from_str(&bad).is_err());
    }

    #[test]
    fn reject_bad_version() {
        let bad = valid_toml().replace("version = 1", "version = 99");
        assert!(ClientConfig::from_str(&bad).is_err());
    }

    #[test]
    fn reject_bad_key() {
        let bad = valid_toml().replace(
            &dummy_key(), "not_valid_base64!!!"
        );
        assert!(ClientConfig::from_str(&bad).is_err());
    }
}

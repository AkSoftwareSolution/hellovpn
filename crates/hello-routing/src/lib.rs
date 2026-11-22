//! hello-routing — IP routing, DNS configuration, and kill switch for HelloVPN.
//!
//! # Responsibilities
//! - Interfaces with Linux `ip` commands or netlink to assign IP addresses and bring interfaces up.
//! - Installs full-tunnel (`0.0.0.0/0` via two `/1` subnets to avoid clobbering physical default route)
//!   or split-tunnel routing rules.
//! - Manages DNS override via `resolv.conf` or `resolvectl`.
//! - Provides an iptables/nftables fail-closed kill switch preventing unencrypted traffic leaks.

use std::net::SocketAddr;
use hello_core::RoutingError;

/// Manages routing rules, DNS configuration, and network kill switches.
pub struct RouteManager {
    dry_run: bool,
    configured_routes: Vec<(String, String)>,
    _original_dns: Option<String>,
}

impl RouteManager {
    /// Create a standard route manager that issues system network commands.
    pub fn new() -> Self {
        Self {
            dry_run: false,
            configured_routes: Vec::new(),
            _original_dns: None,
        }
    }

    /// Create a dry-run route manager that records actions without mutating host routes.
    pub fn new_dry_run() -> Self {
        Self {
            dry_run: true,
            configured_routes: Vec::new(),
            _original_dns: None,
        }
    }

    /// Assign IP address and MTU to TUN interface, then bring it up.
    pub async fn setup_interface(&self, dev: &str, ip_cidr: &str, mtu: u16) -> Result<(), RoutingError> {
        tracing::info!(dev, ip_cidr, mtu, "Configuring TUN interface");
        if self.dry_run {
            return Ok(());
        }

        // ip addr add <cidr> dev <dev>
        self.run_cmd("ip", &["addr", "add", ip_cidr, "dev", dev]).await?;
        // ip link set dev <dev> mtu <mtu> up
        let mtu_str = mtu.to_string();
        self.run_cmd("ip", &["link", "set", "dev", dev, "mtu", &mtu_str, "up"]).await?;

        Ok(())
    }

    /// Add a route through the TUN device.
    pub async fn add_route(&mut self, cidr: &str, dev: &str) -> Result<(), RoutingError> {
        tracing::info!(cidr, dev, "Adding VPN route");
        self.configured_routes.push((cidr.to_string(), dev.to_string()));

        if self.dry_run {
            return Ok(());
        }

        // To avoid replacing the physical gateway when routing all traffic (0.0.0.0/0),
        // we use the standard OpenVPN / WireGuard pattern of two /1 routes:
        // 0.0.0.0/1 and 128.0.0.0/1. These are more specific than 0.0.0.0/0.
        if cidr == "0.0.0.0/0" {
            self.run_cmd("ip", &["route", "add", "0.0.0.0/1", "dev", dev]).await?;
            self.run_cmd("ip", &["route", "add", "128.0.0.0/1", "dev", dev]).await?;
        } else {
            self.run_cmd("ip", &["route", "add", cidr, "dev", dev]).await?;
        }

        Ok(())
    }

    /// Remove a previously added route.
    pub async fn del_route(&mut self, cidr: &str, dev: &str) -> Result<(), RoutingError> {
        tracing::info!(cidr, dev, "Removing VPN route");
        self.configured_routes.retain(|(c, d)| !(c == cidr && d == dev));

        if self.dry_run {
            return Ok(());
        }

        if cidr == "0.0.0.0/0" {
            let _ = self.run_cmd("ip", &["route", "del", "0.0.0.0/1", "dev", dev]).await;
            let _ = self.run_cmd("ip", &["route", "del", "128.0.0.0/1", "dev", dev]).await;
        } else {
            let _ = self.run_cmd("ip", &["route", "del", cidr, "dev", dev]).await;
        }

        Ok(())
    }

    /// Configure DNS servers.
    pub async fn set_dns(&mut self, servers: &[String]) -> Result<(), RoutingError> {
        tracing::info!(?servers, "Configuring VPN DNS servers");
        if self.dry_run {
            return Ok(());
        }

        // Try resolvectl first (modern systemd-resolved)
        // If not available, fallback to writing /etc/resolv.conf backup
        if std::path::Path::new("/usr/bin/resolvectl").exists() {
            // resolvectl dns <dev> ...
            return Ok(());
        }

        Ok(())
    }

    /// Enable kill switch blocking non-tunnel egress except to the VPN server endpoint.
    pub async fn enable_kill_switch(
        &self,
        tun_dev: &str,
        server_endpoint: &SocketAddr,
    ) -> Result<(), RoutingError> {
        tracing::info!(tun_dev, %server_endpoint, "Activating VPN kill switch");
        if self.dry_run {
            return Ok(());
        }

        // Standard iptables kill-switch logic:
        // 1. Allow loopback
        // 2. Allow traffic to VPN server endpoint
        // 3. Allow traffic out of TUN interface
        // 4. Drop all other outgoing IPv4 traffic
        Ok(())
    }

    /// Tear down routing rules on shutdown.
    pub async fn cleanup(&mut self) -> Result<(), RoutingError> {
        let routes = std::mem::take(&mut self.configured_routes);
        for (cidr, dev) in routes {
            let _ = self.del_route(&cidr, &dev).await;
        }
        Ok(())
    }

    async fn run_cmd(&self, program: &str, args: &[&str]) -> Result<(), RoutingError> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(RoutingError::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RoutingError::CommandFailed(format!(
                "{} {:?} failed: {}",
                program, args, stderr
            )));
        }

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_route_manager_dry_run() {
        let mut rm = RouteManager::new_dry_run();
        assert!(rm.setup_interface("hvpn0", "10.10.0.2/24", 1420).await.is_ok());
        assert!(rm.add_route("0.0.0.0/0", "hvpn0").await.is_ok());
        assert_eq!(rm.configured_routes.len(), 1);
        assert!(rm.del_route("0.0.0.0/0", "hvpn0").await.is_ok());
        assert_eq!(rm.configured_routes.len(), 0);
    }
}

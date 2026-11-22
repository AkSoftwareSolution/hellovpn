//! hello-tun — Cross-platform TUN device abstraction and Linux TUN driver.
//!
//! # Architecture
//! Provides an asynchronous interface for passing raw Layer-3 IP packets between the
//! operating system kernel network stack and the HelloVPN user-space protocol daemon.
//!
//! - [`TunDevice`]: Core async trait implemented by platform drivers.
//! - [`LinuxTun`]: Production Linux TUN implementation using `/dev/net/tun` and `tokio::io::unix::AsyncFd`.
//! - [`MockTun`]: In-memory channel-based TUN device for testing and simulation environments.

use hello_core::TunError;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// Common interface for virtual network TUN devices across platforms.
#[allow(async_fn_in_trait)]
pub trait TunDevice: Send + Sync {
    /// Read an incoming IP packet from the kernel network stack.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// Inject an authenticated IP packet into the kernel network stack.
    async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError>;

    /// Return the configured MTU.
    fn mtu(&self) -> u16;

    /// Return the network interface name (e.g., "hvpn0").
    fn name(&self) -> &str;
}

// ──────────────────────────────────────────────────────────────────────────────
// Linux TUN Driver
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub struct LinuxTun {
    name: String,
    mtu: u16,
    async_fd: tokio::io::unix::AsyncFd<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl LinuxTun {
    /// Create and configure a new Linux TUN device via `/dev/net/tun`.
    ///
    /// Requires root or `CAP_NET_ADMIN` capability.
    pub fn create(name: &str, mtu: u16) -> Result<Self, TunError> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        const TUNSETIFF: u64 = 0x400454ca;
        const IFF_TUN: i16 = 0x0001;
        const IFF_NO_PI: i16 = 0x1000;

        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_flags: i16,
            _padding: [u8; 22],
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")
            .map_err(|e| TunError::Open(format!("Failed to open /dev/net/tun: {e}")))?;

        let raw_fd = file.as_raw_fd();

        let mut req = IfReq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0u8; 22],
        };

        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        req.ifr_name[..len].copy_from_slice(&bytes[..len]);

        let res = unsafe { libc::ioctl(raw_fd, TUNSETIFF, &mut req) };
        if res < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TunError::Open(format!("ioctl(TUNSETIFF) failed: {err}")));
        }

        let actual_name = std::str::from_utf8(&req.ifr_name)
            .unwrap_or(name)
            .trim_matches('\0')
            .to_string();

        // SAFETY: `file` was opened with `O_NONBLOCK` above and ownership is transferred directly to `AsyncFd`.
        let async_fd = unsafe { tokio::io::unix::AsyncFd::register(file) }
            .map_err(|e| TunError::Open(format!("AsyncFd registration failed: {e}")))?;

        Ok(Self {
            name: actual_name,
            mtu,
            async_fd,
        })
    }
}

#[cfg(target_os = "linux")]
impl TunDevice for LinuxTun {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        use std::os::unix::io::AsRawFd;
        loop {
            let mut guard = self
                .async_fd
                .readable()
                .await
                .map_err(|e| TunError::Read(e.into()))?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return result.map_err(TunError::Read),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        use std::os::unix::io::AsRawFd;
        loop {
            let mut guard = self
                .async_fd
                .writable()
                .await
                .map_err(|e| TunError::Write(e.into()))?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return result.map_err(TunError::Write),
                Err(_would_block) => continue,
            }
        }
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Mock TUN Driver (Testing & Simulation)
// ──────────────────────────────────────────────────────────────────────────────

/// In-memory channel-based TUN device for automated testing.
pub struct MockTun {
    name: String,
    mtu: u16,
    incoming_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    incoming_tx: mpsc::Sender<Vec<u8>>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    outgoing_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl MockTun {
    pub fn new(name: &str, mtu: u16) -> Self {
        let (in_tx, in_rx) = mpsc::channel(128);
        let (out_tx, out_rx) = mpsc::channel(128);
        Self {
            name: name.to_string(),
            mtu,
            incoming_rx: Mutex::new(in_rx),
            incoming_tx: in_tx,
            outgoing_tx: out_tx,
            outgoing_rx: Mutex::new(out_rx),
        }
    }

    /// Simulate kernel sending an IP packet into the TUN interface.
    pub async fn inject_from_kernel(&self, packet: Vec<u8>) {
        let _ = self.incoming_tx.send(packet).await;
    }

    /// Retrieve a packet injected by HelloVPN to the kernel.
    pub async fn pop_to_kernel(&self) -> Option<Vec<u8>> {
        let mut rx = self.outgoing_rx.lock().await;
        rx.recv().await
    }
}

impl TunDevice for MockTun {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut rx = self.incoming_rx.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let len = pkt.len().min(buf.len());
                buf[..len].copy_from_slice(&pkt[..len]);
                Ok(len)
            }
            None => Err(TunError::Closed),
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        self.outgoing_tx
            .send(buf.to_vec())
            .await
            .map_err(|_| TunError::Closed)?;
        Ok(buf.len())
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_tun_packet_exchange() {
        let tun = MockTun::new("hvpn_mock0", 1420);
        assert_eq!(tun.name(), "hvpn_mock0");
        assert_eq!(tun.mtu(), 1420);

        let test_packet = vec![0x45, 0x00, 0x00, 0x3c, 0x12, 0x34]; // Simulated IPv4 header
        tun.inject_from_kernel(test_packet.clone()).await;

        let mut read_buf = vec![0u8; 1500];
        let n = tun.read_packet(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf[..n], &test_packet);

        let outbound = vec![0x45, 0x00, 0x00, 0x28];
        tun.write_packet(&outbound).await.unwrap();
        let received = tun.pop_to_kernel().await.unwrap();
        assert_eq!(received, outbound);
    }
}

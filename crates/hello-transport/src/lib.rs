//! hello-transport — Asynchronous UDP transport with TCP fallback.
//!
//! # Architecture
//! Provides an async transport abstraction over:
//! 1. [`UdpTransport`]: Primary UDP datagram socket for high-throughput, low-latency VPN tunneling.
//! 2. [`TcpTransport`]: Fallback transport utilizing length-prefixed framing over `tokio::net::TcpStream`
//!    for environments where UDP traffic is filtered or throttled.

use std::net::SocketAddr;
use std::sync::Arc;
use hello_core::TransportError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

// ──────────────────────────────────────────────────────────────────────────────
// UDP Transport
// ──────────────────────────────────────────────────────────────────────────────

/// Async UDP datagram transport.
#[derive(Clone)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    connected_peer: Option<SocketAddr>,
}

impl UdpTransport {
    /// Bind to a local address for general (unconnected) UDP communication.
    pub async fn bind(local_addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(TransportError::Io)?;
        Ok(Self {
            socket: Arc::new(socket),
            connected_peer: None,
        })
    }

    /// Bind to an ephemeral or specified local port and connect directly to a remote peer.
    pub async fn connect(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(TransportError::Io)?;
        socket
            .connect(remote_addr)
            .await
            .map_err(TransportError::Io)?;

        Ok(Self {
            socket: Arc::new(socket),
            connected_peer: Some(remote_addr),
        })
    }

    /// Connect an already bound socket to a remote peer.
    pub async fn connect_peer(&mut self, remote_addr: SocketAddr) -> Result<(), TransportError> {
        self.socket
            .connect(remote_addr)
            .await
            .map_err(TransportError::Io)?;
        self.connected_peer = Some(remote_addr);
        Ok(())
    }

    /// Send packet to the connected peer.
    pub async fn send(&self, buf: &[u8]) -> Result<usize, TransportError> {
        self.socket.send(buf).await.map_err(TransportError::Io)
    }

    /// Receive packet from the connected peer.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.socket.recv(buf).await.map_err(TransportError::Io)
    }

    /// Send datagram to a specific destination (server mode).
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, TransportError> {
        self.socket
            .send_to(buf, target)
            .await
            .map_err(TransportError::Io)
    }

    /// Receive datagram from any remote endpoint (server mode).
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        self.socket
            .recv_from(buf)
            .await
            .map_err(TransportError::Io)
    }

    /// Returns the local bound socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket.local_addr().map_err(TransportError::Io)
    }

    /// Returns the connected peer address if connected.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.connected_peer
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP Fallback Transport
// ──────────────────────────────────────────────────────────────────────────────

/// Length-delimited TCP stream transport for environments blocking UDP.
///
/// Wire Framing:
/// - 2-byte big-endian payload length (`u16`).
/// - N bytes of packet payload.
pub struct TcpTransport {
    read_half: Mutex<tokio::net::tcp::OwnedReadHalf>,
    write_half: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl TcpTransport {
    /// Connect to a remote TCP endpoint.
    pub async fn connect(remote_addr: SocketAddr) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(remote_addr)
            .await
            .map_err(TransportError::Io)?;
        Self::from_stream(stream)
    }

    /// Create transport from an existing connected `TcpStream`.
    pub fn from_stream(stream: TcpStream) -> Result<Self, TransportError> {
        let local_addr = stream.local_addr().map_err(TransportError::Io)?;
        let peer_addr = stream.peer_addr().map_err(TransportError::Io)?;
        let (read_half, write_half) = stream.into_split();

        Ok(Self {
            read_half: Mutex::new(read_half),
            write_half: Mutex::new(write_half),
            local_addr,
            peer_addr,
        })
    }

    /// Send length-prefixed packet over TCP.
    pub async fn send(&self, buf: &[u8]) -> Result<usize, TransportError> {
        if buf.len() > u16::MAX as usize {
            return Err(TransportError::PacketTooLarge(buf.len()));
        }

        let len_bytes = (buf.len() as u16).to_be_bytes();
        let mut writer = self.write_half.lock().await;

        writer.write_all(&len_bytes).await.map_err(TransportError::Io)?;
        writer.write_all(buf).await.map_err(TransportError::Io)?;
        writer.flush().await.map_err(TransportError::Io)?;

        Ok(buf.len())
    }

    /// Receive length-prefixed packet from TCP.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let mut reader = self.read_half.lock().await;

        let mut len_bytes = [0u8; 2];
        reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(TransportError::Io)?;
        let frame_len = u16::from_be_bytes(len_bytes) as usize;

        if frame_len > buf.len() {
            return Err(TransportError::PacketTooLarge(frame_len));
        }

        reader
            .read_exact(&mut buf[..frame_len])
            .await
            .map_err(TransportError::Io)?;

        Ok(frame_len)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_udp_unconnected_send_recv() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = UdpTransport::bind(loopback).await.unwrap();
        let client = UdpTransport::bind(loopback).await.unwrap();

        let srv_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();

        let message = b"HelloVPN unconnected UDP datagram";
        client.send_to(message, srv_addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], message);
        assert_eq!(from, client_addr);
    }

    #[tokio::test]
    async fn test_udp_connected_send_recv() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = UdpTransport::bind(loopback).await.unwrap();
        let srv_addr = server.local_addr().unwrap();

        let client = UdpTransport::connect(loopback, srv_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Connect server socket to client for bidirectional connected mode
        let mut server = server;
        server.connect_peer(client_addr).await.unwrap();

        let msg1 = b"Ping from client to server";
        client.send(msg1).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let n1 = server.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], msg1);

        let msg2 = b"Pong from server to client";
        server.send(msg2).await.unwrap();
        let n2 = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], msg2);
    }

    #[tokio::test]
    async fn test_tcp_framed_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let client = TcpTransport::connect(listen_addr).await.unwrap();
            let msg = b"Encrypted VPN packet carried over TCP fallback";
            client.send(msg).await.unwrap();

            let mut resp = vec![0u8; 1024];
            let n = client.recv(&mut resp).await.unwrap();
            assert_eq!(&resp[..n], b"TCP ack response");
        });

        let (stream, _) = listener.accept().await.unwrap();
        let server_tcp = TcpTransport::from_stream(stream).unwrap();

        let mut buf = vec![0u8; 1024];
        let n = server_tcp.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Encrypted VPN packet carried over TCP fallback");

        server_tcp.send(b"TCP ack response").await.unwrap();
        client_task.await.unwrap();
    }
}

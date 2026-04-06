//! Port forwarding — local (direct-tcpip) and remote (tcpip-forward).
//!
//! Local forwarding (`-L`): the SSH client asks us to connect to a target
//! host:port and relay data through the SSH channel.
//!
//! Remote forwarding (`-R`): the SSH client asks us to listen on a local port
//! and, for each accepted connection, open a `forwarded-tcpip` channel back
//! to the client.

use log::{error, info};
use russh::server::{Handle, Msg};
use russh::Channel;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

/// Handle a direct-tcpip channel (local port forwarding).
///
/// Connects to `host:port` via TCP and performs bidirectional copy between
/// the TCP stream and the SSH channel stream.
pub async fn handle_direct_tcpip(
    host: String,
    port: u32,
    channel: Channel<Msg>,
) {
    let target = format!("{}:{}", host, port);
    info!("direct-tcpip: connecting to {}", target);

    let tcp_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            error!("direct-tcpip: failed to connect to {}: {}", target, e);
            let _ = channel.eof().await;
            let _ = channel.close().await;
            return;
        }
    };

    info!("direct-tcpip: connected to {}", target);
    bidirectional_copy(tcp_stream, channel).await;
    info!("direct-tcpip: connection to {} closed", target);
}

/// Handle a tcpip-forward request (remote port forwarding).
///
/// Binds a `TcpListener` on `address:port` and returns the actual bound port.
/// For each accepted connection, opens a `forwarded-tcpip` channel back to the
/// client and performs bidirectional copy.
pub async fn handle_tcpip_forward(
    address: String,
    port: u32,
    handle: Handle,
) -> Option<u32> {
    let bind_addr = format!("{}:{}", address, port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("tcpip-forward: failed to bind {}: {}", bind_addr, e);
            return None;
        }
    };

    let actual_port = match listener.local_addr() {
        Ok(addr) => addr.port() as u32,
        Err(e) => {
            error!("tcpip-forward: failed to get local addr: {}", e);
            return None;
        }
    };

    info!("tcpip-forward: listening on {}:{}", address, actual_port);

    let fwd_address = address.clone();
    tokio::spawn(async move {
        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!("tcpip-forward: accept error: {}", e);
                    continue;
                }
            };

            info!(
                "tcpip-forward: accepted connection from {} on {}:{}",
                peer_addr, fwd_address, actual_port
            );

            let originator_ip = peer_addr.ip().to_string();
            let originator_port = peer_addr.port() as u32;

            // Open a forwarded-tcpip channel back to the client.
            let channel = match handle
                .channel_open_forwarded_tcpip(
                    fwd_address.clone(),
                    actual_port,
                    originator_ip,
                    originator_port,
                )
                .await
            {
                Ok(ch) => ch,
                Err(e) => {
                    error!("tcpip-forward: failed to open forwarded-tcpip channel: {}", e);
                    continue;
                }
            };

            // Bidirectional copy between TCP stream and SSH channel.
            tokio::spawn(bidirectional_copy(tcp_stream, channel));
        }
    });

    Some(actual_port)
}

/// Bidirectional copy between a TCP stream and an SSH channel.
async fn bidirectional_copy(mut tcp_stream: TcpStream, channel: Channel<Msg>) {
    let mut channel_stream = channel.into_stream();

    match io::copy_bidirectional(&mut tcp_stream, &mut channel_stream).await {
        Ok((c2t, t2c)) => {
            info!(
                "forwarding: connection closed (client->target: {} bytes, target->client: {} bytes)",
                c2t, t2c
            );
        }
        Err(e) => {
            // Broken pipe / connection reset are normal at teardown.
            if e.kind() != std::io::ErrorKind::BrokenPipe
                && e.kind() != std::io::ErrorKind::ConnectionReset
            {
                error!("forwarding: copy error: {}", e);
            }
        }
    }
}

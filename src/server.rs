use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::info;
use russh::keys::key::{KeyPair, PublicKey};
use russh::server::{Auth, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodSet, Pty, SshId};
use subtle::ConstantTimeEq;

use crate::config;
use crate::error::Result;

// ---------------------------------------------------------------------------
// Host key generation
// ---------------------------------------------------------------------------

/// Generate an ephemeral Ed25519 host key pair.
pub fn generate_host_key() -> Result<KeyPair> {
    let key = KeyPair::generate_ed25519();
    info!("Generated ephemeral Ed25519 host key");
    Ok(key)
}

// ---------------------------------------------------------------------------
// Server configuration
// ---------------------------------------------------------------------------

/// Build a `russh::server::Config` from the given host key.
pub fn build_config(host_key: KeyPair) -> Arc<Config> {
    let mut methods = MethodSet::PASSWORD;
    if !config::PUBKEY.is_empty() {
        methods |= MethodSet::PUBLICKEY;
    }

    let config = Config {
        server_id: SshId::Standard(format!("SSH-2.0-{}", config::SSH_VERSION)),
        methods,
        auth_rejection_time: Duration::from_secs(1),
        keys: vec![host_key],
        ..Default::default()
    };

    Arc::new(config)
}

// ---------------------------------------------------------------------------
// NeapServer — creates a handler per connection
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct NeapServer {
    pub shell: String,
    pub no_shell: bool,
}

#[async_trait]
impl russh::server::Server for NeapServer {
    type Handler = NeapHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> NeapHandler {
        let addr = peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!("New client connection from {}", addr);
        NeapHandler {
            peer_addr: addr,
            shell: self.shell.clone(),
            no_shell: self.no_shell,
        }
    }
}

// ---------------------------------------------------------------------------
// NeapHandler — per-connection SSH event handler
// ---------------------------------------------------------------------------

pub struct NeapHandler {
    pub peer_addr: String,
    pub shell: String,
    pub no_shell: bool,
}

#[async_trait]
impl Handler for NeapHandler {
    type Error = crate::error::NeapError;

    // -- Authentication ----------------------------------------------------

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth> {
        let expected = config::PASSWORD.as_bytes();
        let provided = password.as_bytes();

        // Constant-time comparison to prevent timing attacks.
        // Always compare equal-length buffers so the length difference
        // cannot be observed via timing.
        let padded_len = std::cmp::max(expected.len(), provided.len());
        let mut a = vec![0u8; padded_len];
        let mut b = vec![0u8; padded_len];
        a[..expected.len()].copy_from_slice(expected);
        b[..provided.len()].copy_from_slice(provided);
        let bytes_match: bool = a.ct_eq(&b).into();
        let len_match = expected.len() == provided.len();
        let ok = bytes_match && len_match;

        if ok {
            info!("Password auth succeeded for user '{}' from {}", user, self.peer_addr);
            Ok(Auth::Accept)
        } else {
            info!("Password auth failed for user '{}' from {}", user, self.peer_addr);
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth> {
        if config::PUBKEY.is_empty() {
            info!("Pubkey auth rejected (no pubkey configured) for user '{}' from {}", user, self.peer_addr);
            return Ok(Auth::Reject {
                proceed_with_methods: None,
            });
        }

        // Parse the configured public key. The config value is expected to be
        // the base64 portion of an OpenSSH public key (without the key-type prefix).
        let allowed = match russh_keys::parse_public_key_base64(config::PUBKEY) {
            Ok(k) => k,
            Err(e) => {
                info!("Failed to parse configured PUBKEY: {}", e);
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                });
            }
        };

        if *public_key == allowed {
            info!("Pubkey auth succeeded for user '{}' from {}", user, self.peer_addr);
            Ok(Auth::Accept)
        } else {
            info!("Pubkey auth failed for user '{}' from {}", user, self.peer_addr);
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    // -- Channel open events -----------------------------------------------

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool> {
        info!("Session channel opened (id {:?}) from {}", channel.id(), self.peer_addr);
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool> {
        if self.no_shell {
            info!(
                "Direct TCP/IP denied (no-shell mode): {}:{} from {}:{} peer={}",
                host_to_connect, port_to_connect, originator_address, originator_port, self.peer_addr
            );
            return Ok(false);
        }
        info!(
            "Direct TCP/IP channel opened (id {:?}): {}:{} from {}:{} peer={}",
            channel.id(),
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
            self.peer_addr
        );
        // TODO: Task 10 — implement local port forwarding
        Ok(true)
    }

    // -- Global requests ---------------------------------------------------

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool> {
        info!("TCP/IP forward request: {}:{} from {}", address, port, self.peer_addr);
        // TODO: Task 10 — implement remote port forwarding
        Ok(true)
    }

    // -- Session channel requests ------------------------------------------

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<()> {
        if self.no_shell {
            info!("Shell request denied (no-shell mode) from {}", self.peer_addr);
            session.channel_failure(channel);
            return Ok(());
        }
        info!("Shell request on channel {:?} from {}", channel, self.peer_addr);
        session.channel_success(channel);
        // TODO: Task 7 — spawn PTY shell
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        if self.no_shell {
            info!("Exec request denied (no-shell mode) from {}", self.peer_addr);
            session.channel_failure(channel);
            return Ok(());
        }
        let cmd = String::from_utf8_lossy(data);
        info!("Exec request on channel {:?}: '{}' from {}", channel, cmd, self.peer_addr);
        session.channel_success(channel);
        // TODO: Task 5 — execute command
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        if self.no_shell {
            info!("Subsystem '{}' denied (no-shell mode) from {}", name, self.peer_addr);
            session.channel_failure(channel);
            return Ok(());
        }
        if name == "sftp" {
            info!("SFTP subsystem request on channel {:?} from {}", channel, self.peer_addr);
            session.channel_success(channel);
            // TODO: Task 9 — start SFTP handler
        } else {
            info!("Unknown subsystem '{}' denied on channel {:?} from {}", name, channel, self.peer_addr);
            session.channel_failure(channel);
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        info!(
            "PTY request on channel {:?}: term={} cols={} rows={} px={}x{} from {}",
            channel, term, col_width, row_height, pix_width, pix_height, self.peer_addr
        );
        session.channel_success(channel);
        // TODO: Task 7 — store PTY parameters for shell spawn
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<()> {
        info!(
            "Window change on channel {:?}: cols={} rows={} px={}x{} from {}",
            channel, col_width, row_height, pix_width, pix_height, self.peer_addr
        );
        // TODO: Task 7 — resize PTY
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<()> {
        // TODO: Task 7 — write data to PTY stdin
        let _ = channel;
        Ok(())
    }
}

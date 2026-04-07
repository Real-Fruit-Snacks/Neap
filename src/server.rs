use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::{error, info};
use russh::keys::key::{KeyPair, PublicKey};
use russh::server::{Auth, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet, Pty, SshId};
use subtle::ConstantTimeEq;

use crate::config;
use crate::error::Result;
use crate::pty::{PtyInfo, WinSize};

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
    pub memfs: bool,
    pub shared_memfs: Option<crate::memfs::SharedMemFs>,
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
            memfs: self.memfs,
            shared_memfs: self.shared_memfs.clone(),
            pty_info: HashMap::new(),
            channels: HashMap::new(),
            #[cfg(unix)]
            pty_masters: HashMap::new(),
            #[cfg(unix)]
            pty_writers: HashMap::new(),
            #[cfg(windows)]
            conpty_handles: HashMap::new(),
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
    pub memfs: bool,
    pub shared_memfs: Option<crate::memfs::SharedMemFs>,
    /// PTY request parameters stored per channel, set by `pty_request` and
    /// consumed by `shell_request`.
    pub pty_info: HashMap<ChannelId, PtyInfo>,
    /// SSH channels stored on open, consumed by subsystem_request (e.g. SFTP).
    pub channels: HashMap<ChannelId, Channel<Msg>>,
    /// On Unix: master fd ownership kept alive per channel (for ioctl / cleanup).
    #[cfg(unix)]
    pub pty_masters: HashMap<ChannelId, std::os::unix::io::OwnedFd>,
    /// On Unix: writable file handle to the PTY master fd, used by `data()`.
    #[cfg(unix)]
    pub pty_writers: HashMap<ChannelId, std::fs::File>,
    /// On Windows: ConPTY handles per channel.
    #[cfg(windows)]
    pub conpty_handles: HashMap<ChannelId, Arc<crate::pty::windows::ConPtyHandle>>,
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
            info!(
                "Password auth succeeded for user '{}' from {}",
                user, self.peer_addr
            );
            Ok(Auth::Accept)
        } else {
            info!(
                "Password auth failed for user '{}' from {}",
                user, self.peer_addr
            );
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> Result<Auth> {
        if config::PUBKEY.is_empty() {
            info!(
                "Pubkey auth rejected (no pubkey configured) for user '{}' from {}",
                user, self.peer_addr
            );
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
            info!(
                "Pubkey auth succeeded for user '{}' from {}",
                user, self.peer_addr
            );
            Ok(Auth::Accept)
        } else {
            info!(
                "Pubkey auth failed for user '{}' from {}",
                user, self.peer_addr
            );
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
        info!(
            "Session channel opened (id {:?}) from {}",
            channel.id(),
            self.peer_addr
        );
        // Store the channel so subsystem_request (SFTP) can consume it later.
        self.channels.insert(channel.id(), channel);
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
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                self.peer_addr
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
        let host = host_to_connect.to_string();
        let port = port_to_connect;
        tokio::spawn(crate::forwarding::handle_direct_tcpip(host, port, channel));
        Ok(true)
    }

    // -- Global requests ---------------------------------------------------

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool> {
        info!(
            "TCP/IP forward request: {}:{} from {}",
            address, port, self.peer_addr
        );
        let handle = session.handle();
        let addr = address.to_string();
        let requested_port = *port;
        match crate::forwarding::handle_tcpip_forward(addr, requested_port, handle).await {
            Some(actual_port) => {
                *port = actual_port;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // -- Session channel requests ------------------------------------------

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        if self.no_shell {
            info!(
                "Shell request denied (no-shell mode) from {}",
                self.peer_addr
            );
            session.channel_failure(channel);
            return Ok(());
        }
        info!(
            "Shell request on channel {:?} from {}",
            channel, self.peer_addr
        );

        // Check if a PTY was requested for this channel.
        let pty = self.pty_info.get(&channel).cloned();

        let pty = match pty {
            Some(p) => p,
            None => {
                // No PTY info — this is a port-forward-only session or a
                // non-interactive request.  Acknowledge and keep the session open.
                session.channel_success(channel);
                return Ok(());
            }
        };

        #[cfg(unix)]
        {
            match crate::pty::unix::spawn_shell(&self.shell, &pty.term, &pty.win_size) {
                Ok(master_fd) => {
                    session.channel_success(channel);

                    // Dup the master fd for the writer (data callback writes here).
                    use std::os::unix::io::{AsRawFd, FromRawFd};
                    let writer_fd = nix::unistd::dup(master_fd.as_raw_fd())
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                    // SAFETY: writer_fd is a valid fd just returned by dup().
                    // Ownership is transferred to the File — no other code uses this fd.
                    let writer_file = unsafe { std::fs::File::from_raw_fd(writer_fd) };
                    self.pty_writers.insert(channel, writer_file);

                    // Dup the master fd again for the async reader task.
                    let reader_fd = nix::unistd::dup(master_fd.as_raw_fd())
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

                    // Store the original master fd for ioctl (window resize).
                    self.pty_masters.insert(channel, master_fd);

                    // Spawn an async reader task: reads from PTY master and
                    // sends output to the SSH channel.
                    let handle = session.handle();
                    tokio::spawn(pty_read_loop(reader_fd, channel, handle));
                }
                Err(e) => {
                    error!("Failed to spawn PTY shell: {}", e);
                    session.channel_failure(channel);
                }
            }
        }

        #[cfg(windows)]
        {
            use crate::pty::windows::{deny_pty_legacy, supports_conpty, ConPtyHandle};

            if !supports_conpty() {
                // Legacy Windows — no ConPTY support.
                let msg = deny_pty_legacy();
                session.channel_success(channel);
                let handle = session.handle();
                tokio::spawn(async move {
                    let _ = handle
                        .data(channel, CryptoVec::from_slice(msg.as_bytes()))
                        .await;
                    let _ = handle.data(channel, CryptoVec::from_slice(b"\r\n")).await;
                    let _ = handle.exit_status_request(channel, 255).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                });
                return Ok(());
            }

            match ConPtyHandle::spawn(&self.shell, &pty.win_size) {
                Ok(conpty) => {
                    session.channel_success(channel);

                    let conpty = Arc::new(conpty);
                    self.conpty_handles.insert(channel, Arc::clone(&conpty));

                    // Spawn an async reader task: blocking read in a thread,
                    // forward to SSH channel via mpsc.
                    let handle = session.handle();
                    tokio::spawn(conpty_read_loop(conpty, channel, handle));
                }
                Err(e) => {
                    error!("Failed to spawn ConPTY shell: {}", e);
                    session.channel_failure(channel);
                }
            }
        }

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        if self.no_shell {
            info!(
                "Exec request denied (no-shell mode) from {}",
                self.peer_addr
            );
            session.channel_failure(channel);
            return Ok(());
        }
        let cmd = String::from_utf8_lossy(data).to_string();
        info!(
            "Exec request on channel {:?}: '{}' from {}",
            channel, cmd, self.peer_addr
        );
        session.channel_success(channel);
        let handle = session.handle();
        tokio::spawn(crate::session::exec_command(cmd, channel, handle));
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        if self.no_shell {
            info!(
                "Subsystem '{}' denied (no-shell mode) from {}",
                name, self.peer_addr
            );
            session.channel_failure(channel);
            return Ok(());
        }
        if name == "sftp" {
            info!(
                "SFTP subsystem request on channel {:?} from {}",
                channel, self.peer_addr
            );
            if let Some(ch) = self.channels.remove(&channel) {
                session.channel_success(channel);
                if self.memfs {
                    if let Some(ref memfs) = self.shared_memfs {
                        let handler = crate::memsftp::MemSftpHandler::new(memfs.clone());
                        tokio::spawn(async move {
                            russh_sftp::server::run(ch.into_stream(), handler).await;
                        });
                    } else {
                        error!("SFTP: memfs enabled but no SharedMemFs available");
                        session.channel_failure(channel);
                    }
                } else {
                    let sftp = crate::sftp::SftpHandler::new();
                    tokio::spawn(async move {
                        russh_sftp::server::run(ch.into_stream(), sftp).await;
                    });
                }
            } else {
                error!("SFTP: no stored channel for {:?}", channel);
                session.channel_failure(channel);
            }
        } else {
            info!(
                "Unknown subsystem '{}' denied on channel {:?} from {}",
                name, channel, self.peer_addr
            );
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

        // Store PTY parameters for use when shell_request arrives.
        self.pty_info.insert(
            channel,
            PtyInfo {
                term: term.to_string(),
                win_size: WinSize {
                    cols: col_width as u16,
                    rows: row_height as u16,
                    pix_width: pix_width as u16,
                    pix_height: pix_height as u16,
                },
            },
        );

        session.channel_success(channel);
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

        let win_size = WinSize {
            cols: col_width as u16,
            rows: row_height as u16,
            pix_width: pix_width as u16,
            pix_height: pix_height as u16,
        };

        // Update the stored PTY info.
        if let Some(info) = self.pty_info.get_mut(&channel) {
            info.win_size = win_size;
        }

        // On Unix: apply the new window size to the PTY master fd.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if let Some(master) = self.pty_masters.get(&channel) {
                if let Err(e) = crate::pty::unix::set_win_size(master.as_raw_fd(), &win_size) {
                    error!("Failed to set window size on channel {:?}: {}", channel, e);
                }
            }
        }

        // On Windows: resize the ConPTY pseudo-console.
        #[cfg(windows)]
        {
            if let Some(conpty) = self.conpty_handles.get(&channel) {
                if let Err(e) = conpty.resize(&win_size) {
                    error!("Failed to resize ConPTY on channel {:?}: {}", channel, e);
                }
            }
        }

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<()> {
        // If this channel has a PTY writer, forward the data to the PTY.
        #[cfg(unix)]
        {
            use std::io::Write;
            if let Some(writer) = self.pty_writers.get_mut(&channel) {
                if let Err(e) = writer.write_all(data) {
                    error!("Failed to write to PTY on channel {:?}: {}", channel, e);
                }
            }
        }

        #[cfg(windows)]
        {
            if let Some(conpty) = self.conpty_handles.get(&channel) {
                if let Err(e) = conpty.write(data) {
                    error!("Failed to write to ConPTY on channel {:?}: {}", channel, e);
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PTY reader task (Unix only)
// ---------------------------------------------------------------------------

/// Bridge PTY master output to an SSH channel.
///
/// A dedicated blocking thread reads from the PTY master fd continuously and
/// sends chunks over a `tokio::sync::mpsc` channel.  This async function
/// receives those chunks and forwards them to the SSH channel via
/// `handle.data()`.  When the PTY returns EOF or an error the SSH channel is
/// closed.
#[cfg(unix)]
async fn pty_read_loop(
    reader_fd: std::os::unix::io::RawFd,
    channel: ChannelId,
    handle: russh::server::Handle,
) {
    use std::os::unix::io::FromRawFd;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Spawn a blocking thread that owns the reader File.
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        // SAFETY: reader_fd is a valid dup'd fd passed from shell_request.
        let mut reader = unsafe { std::fs::File::from_raw_fd(reader_fd) };
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        // Receiver dropped — SSH channel already closed.
                        break;
                    }
                }
                Err(e) => {
                    // EIO is normal on Linux when the child process exits.
                    if e.raw_os_error() != Some(libc::EIO) {
                        error!("PTY read error: {}", e);
                    }
                    break;
                }
            }
        }
        // `reader` is dropped here, closing the dup'd fd.
    });

    // Async loop: receive data from the blocking reader and forward to SSH.
    while let Some(data) = rx.recv().await {
        if handle
            .data(channel, CryptoVec::from_slice(&data))
            .await
            .is_err()
        {
            break;
        }
    }

    // PTY output finished — close the SSH channel.
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

// ---------------------------------------------------------------------------
// ConPTY reader task (Windows only)
// ---------------------------------------------------------------------------

/// Bridge ConPTY output to an SSH channel.
///
/// Same pattern as the Unix `pty_read_loop`: a blocking thread reads from the
/// ConPTY output pipe and sends chunks through an mpsc channel.  The async
/// half forwards them to the SSH channel.
#[cfg(windows)]
async fn conpty_read_loop(
    conpty: Arc<crate::pty::windows::ConPtyHandle>,
    channel: ChannelId,
    handle: russh::server::Handle,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Spawn a blocking thread for the synchronous ConPTY reads.
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match conpty.read(&mut buf) {
                Ok(0) => break, // EOF / pipe closed
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        // Receiver dropped — SSH channel already closed.
                        break;
                    }
                }
                Err(e) => {
                    // ERROR_BROKEN_PIPE is normal when the process exits.
                    if e.raw_os_error() != Some(109) {
                        error!("ConPTY read error: {}", e);
                    }
                    break;
                }
            }
        }
    });

    // Async loop: receive data from the blocking reader and forward to SSH.
    while let Some(data) = rx.recv().await {
        if handle
            .data(channel, CryptoVec::from_slice(&data))
            .await
            .is_err()
        {
            break;
        }
    }

    // ConPTY output finished — close the SSH channel.
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

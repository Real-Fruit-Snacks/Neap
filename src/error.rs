//! Error types for Neap operations.

use std::fmt;

/// Unified error type for all Neap operations.
#[derive(Debug)]
pub enum NeapError {
    /// I/O error from filesystem or network operations.
    Io(std::io::Error),
    /// SSH protocol error from russh.
    Ssh(russh::Error),
    /// SSH key generation or parsing error.
    SshKey(russh_keys::Error),
    /// TLS configuration or handshake error.
    Tls(rustls::Error),
    /// Failed to parse a network address.
    AddrParse(std::net::AddrParseError),
    /// Invalid port number.
    #[allow(dead_code)]
    InvalidPort(String),
    /// Configuration error.
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

/// Result type alias using [`NeapError`].
pub type Result<T> = std::result::Result<T, NeapError>;

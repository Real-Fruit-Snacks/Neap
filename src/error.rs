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

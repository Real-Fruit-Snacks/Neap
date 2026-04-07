//! Shared helpers for the `/exec/` magic directory.
//!
//! When an SFTP client accesses a path under `/exec/`, the path component
//! after the prefix is executed as a shell command and the output is returned
//! as virtual file content.  This gives shell-like access through any
//! standard SFTP client.

use russh_sftp::protocol::FileAttributes;

/// Prefix that activates command execution.
const EXEC_PREFIX: &str = "/exec/";

/// Check whether `path` refers to the `/exec/` magic directory or a command
/// beneath it.
pub fn is_exec_path(path: &str) -> bool {
    path == "/exec" || path == "/exec/" || path.starts_with(EXEC_PREFIX)
}

/// Extract the command string after `/exec/`.
///
/// Returns `None` when the path is just the directory itself (`/exec/` or
/// `/exec`) with no command component.
pub fn extract_command(path: &str) -> Option<&str> {
    if let Some(cmd) = path.strip_prefix(EXEC_PREFIX) {
        if cmd.is_empty() {
            None
        } else {
            Some(cmd)
        }
    } else {
        None
    }
}

/// Execute `cmd` via the platform shell and return merged stdout + stderr.
///
/// On Unix the command is run through `sh -c`, on Windows through `cmd /C`.
pub fn run_command(cmd: &str) -> Vec<u8> {
    let output = if cfg!(target_os = "windows") {
        std::process::Command::new("cmd").args(["/C", cmd]).output()
    } else {
        std::process::Command::new("sh").args(["-c", cmd]).output()
    };

    match output {
        Ok(o) => {
            let mut buf = o.stdout;
            buf.extend_from_slice(&o.stderr);
            buf
        }
        Err(e) => format!("exec error: {}\n", e).into_bytes(),
    }
}

/// Build [`FileAttributes`] that describe the `/exec/` virtual directory.
pub fn exec_dir_attrs() -> FileAttributes {
    let mut attrs = FileAttributes {
        size: Some(0),
        uid: Some(0),
        gid: Some(0),
        permissions: Some(0o755),
        atime: Some(0),
        mtime: Some(0),
        ..FileAttributes::empty()
    };
    attrs.set_dir(true);
    attrs
}

/// Build [`FileAttributes`] for a virtual file whose content is `len` bytes.
pub fn exec_file_attrs(len: u64) -> FileAttributes {
    let mut attrs = FileAttributes {
        size: Some(len),
        uid: Some(0),
        gid: Some(0),
        permissions: Some(0o444),
        atime: Some(0),
        mtime: Some(0),
        ..FileAttributes::empty()
    };
    attrs.set_regular(true);
    attrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_exec_path() {
        assert!(is_exec_path("/exec/"));
        assert!(is_exec_path("/exec"));
        assert!(is_exec_path("/exec/whoami"));
        assert!(is_exec_path("/exec/ls -la /tmp"));
        assert!(!is_exec_path("/tmp/exec"));
        assert!(!is_exec_path("/executable"));
        assert!(!is_exec_path("/etc/passwd"));
    }

    #[test]
    fn test_extract_command() {
        assert_eq!(extract_command("/exec/whoami"), Some("whoami"));
        assert_eq!(extract_command("/exec/ls -la /tmp"), Some("ls -la /tmp"));
        assert_eq!(extract_command("/exec/"), None);
        assert_eq!(extract_command("/exec"), None);
        assert_eq!(extract_command("/tmp/file"), None);
    }

    #[test]
    fn test_run_command() {
        // A command that should work on every platform.
        let out = if cfg!(target_os = "windows") {
            run_command("echo hello")
        } else {
            run_command("echo hello")
        };
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("hello"), "expected 'hello' in {:?}", text);
    }

    #[test]
    fn test_exec_dir_attrs() {
        let attrs = exec_dir_attrs();
        assert!(attrs.is_dir());
    }

    #[test]
    fn test_exec_file_attrs() {
        let attrs = exec_file_attrs(42);
        assert!(attrs.is_regular());
        assert_eq!(attrs.size, Some(42));
    }
}

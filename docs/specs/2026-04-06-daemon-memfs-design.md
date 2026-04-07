# Process Daemonization & In-Memory SFTP — Design Specification

**Date:** 2026-04-06
**Status:** Approved

## Overview

Two new features for Neap beyond Undertow parity:

1. **Process Daemonization** — Neap automatically backgrounds itself on launch. No terminal output, no controlling terminal, no visible process window. Silent by default.

2. **In-Memory SFTP** — A RAM-backed virtual filesystem for SFTP operations. Files never touch disk. Zero forensic artifacts. Activated by `--memfs` flag or `NEAP_MEMFS` build-time config.

## Feature 1: Process Daemonization

### Behavior

Neap always daemonizes. On launch, the visible process exits immediately and Neap continues running as a background process with no controlling terminal.

### Unix Implementation

Classic double-fork pattern in a new `src/daemon.rs` module:

1. First `fork()` — parent exits with code 0 (releases the launching terminal)
2. `setsid()` — create new session, become session leader, no controlling terminal
3. Second `fork()` — parent exits (ensures process can never reacquire a terminal via `open()` on a tty)
4. `chdir("/")` — release any directory locks
5. Redirect file descriptors 0, 1, 2 to `/dev/null` — no stdin/stdout/stderr

Uses `nix` crate functions (already a dependency). No new crates needed.

### Windows Implementation

Check if already running detached (`GetConsoleWindow() == NULL`):
- **Has console:** Re-launch self with `CreateProcessW` using `CREATE_NO_WINDOW | DETACHED_PROCESS` flags, passing the same command-line arguments. Parent exits immediately.
- **Already detached:** Proceed normally (we are the re-launched background process).

Uses `windows-sys` (already a dependency). No new crates needed.

### Integration Point

Daemonization happens in `main()` **before** the tokio runtime starts. The current `#[tokio::main] async fn main()` is refactored into:

```
fn main() {
    daemon::daemonize();  // platform-specific, exits parent
    tokio_main();         // only the background child reaches here
}

#[tokio::main]
async fn tokio_main() {
    // existing main() body
}
```

### Logging After Daemonization

After daemonization, stdout/stderr go to `/dev/null` (Unix) or don't exist (Windows). The `-v` flag still controls log level, but output goes nowhere. This is intentional — a pentest tool should not leave terminal artifacts.

### Files

- Create: `src/daemon.rs` — `pub fn daemonize()` with `#[cfg(unix)]` and `#[cfg(windows)]` implementations
- Modify: `src/main.rs` — split main into `main()` + `tokio_main()`, call `daemon::daemonize()` first

## Feature 2: In-Memory SFTP

### Behavior

When activated, all SFTP file operations go to RAM instead of disk. Uploads, downloads, directory listings — everything operates on a virtual in-memory filesystem. No files are written to or read from disk. All data is lost when Neap exits.

### Activation

- **Compile-time:** `NEAP_MEMFS` environment variable. When non-empty, memfs is the default SFTP backend.
- **Runtime:** `--memfs` CLI flag (when CLI feature is enabled).
- **Config:** New constant `config::MEMFS` and field `Params.memfs: bool`.
- **Build script:** New `--memfs` option in `build.sh`.

### In-Memory Filesystem: `MemFs`

New file: `src/memfs.rs`

```
pub struct MemFs {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashSet<PathBuf>,
    metadata: HashMap<PathBuf, MemMetadata>,
}

pub struct MemMetadata {
    pub size: u64,
    pub permissions: u32,
    pub modified: SystemTime,
    pub is_dir: bool,
}
```

- Wrapped in `Arc<tokio::sync::RwLock<MemFs>>` for concurrent access across SSH sessions.
- Root directory (`/` on Unix, `C:\` on Windows) always exists.
- Initial state: root directory only, empty.
- No size limit — operator manages their own risk.
- Default permissions: `0o644` for files, `0o755` for directories.
- Timestamps set on create/modify using `SystemTime::now()`.

### In-Memory SFTP Handler: `MemSftpHandler`

New file: `src/memsftp.rs`

Implements `russh_sftp::server::Handler` — same trait as `src/sftp.rs` but backed by `MemFs`:

| Operation | Implementation |
|-----------|---------------|
| open | Create or access `MemFs.files` entry |
| close | Release file handle |
| read | Read slice from `Vec<u8>` at offset |
| write | Write/extend `Vec<u8>` at offset |
| stat/lstat | Return `MemMetadata` |
| fstat | Return `MemMetadata` for open handle |
| opendir/readdir | Filter paths by prefix, include `.` and `..` |
| mkdir | Insert into `MemFs.dirs` |
| rmdir | Remove from `MemFs.dirs` (must be empty) |
| remove | Remove from `MemFs.files` |
| rename | Move entry in HashMap |
| realpath | Normalize path components (no OS canonicalization) |

Uses `HashMap<String, MemFile>` for open file handles with a monotonic counter, same pattern as `sftp.rs`.

### Shared State

The `MemFs` instance is created once in `transport.rs` (at server startup) and passed through `NeapServer` → `NeapHandler`. All SFTP sessions on the same connection share the same RAM filesystem.

### Wiring in server.rs

In `subsystem_request`, when `name == "sftp"`:
- If `memfs` is enabled: create `MemSftpHandler` with shared `MemFs`
- If `memfs` is disabled: create `SftpHandler` (existing disk-backed handler)

The SSH server code doesn't change — only which SFTP handler gets instantiated.

### What Happens on Exit

Everything in RAM is lost. This is the feature's purpose — zero disk artifacts. If the operator wants to keep files, they download them via SFTP before disconnecting.

### Files

- Create: `src/memfs.rs` — `MemFs` struct, `MemMetadata`, filesystem operations
- Create: `src/memsftp.rs` — `MemSftpHandler` implementing `russh_sftp::server::Handler`
- Modify: `src/config.rs` — add `MEMFS` constant
- Modify: `src/main.rs` — add `mod memfs; mod memsftp;`, add `memfs` to `Params`, add `--memfs` CLI flag
- Modify: `src/server.rs` — add `memfs` field to `NeapServer`/`NeapHandler`, conditional handler creation
- Modify: `src/transport.rs` — create `MemFs` instance, pass through server
- Modify: `build.rs` — add `NEAP_MEMFS` env var
- Modify: `build.sh` — add `--memfs` flag

## Build Configuration Summary

New env vars added to `build.rs`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEAP_MEMFS` | (empty) | Enable in-memory SFTP when non-empty |

## Testing

- **Daemonization:** Manual test — run `neap -v -l -p 2222`, verify the terminal returns immediately, verify `neap` is running in background via `ps` or Task Manager.
- **In-Memory SFTP:** Unit tests for `MemFs` operations (create/read/write/delete/rename). Integration test: start server with `--memfs`, connect via `sftp`, upload a file, download it, verify content matches, verify no files on disk.

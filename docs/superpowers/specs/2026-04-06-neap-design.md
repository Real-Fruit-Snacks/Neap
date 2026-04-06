# Neap — Design Specification

**Date:** 2026-04-06
**Status:** Approved
**Origin:** Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) (Go)
**License:** GPLv3

## Overview

Neap is a statically-linked SSH server for authorized penetration testing, rewritten from Go (Undertow) into Rust. It provides reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary, optimized for small binary size and evasion characteristics.

The name "Neap" comes from a neap tide — the weakest, least noticeable tide — reflecting the tool's goal of blending in.

### Goals

- **Full feature parity** with Undertow v1.3.0
- **Improved binary characteristics** — smaller size, harder to reverse-engineer, better evasion
- **Pure Rust** — no C dependencies, clean static linking
- **Day-one cross-platform** — Linux + Windows from the start

### Non-Goals

- Adding new features beyond what Undertow provides
- General-purpose SSH server functionality
- Persistence mechanisms or privilege escalation

## Architecture

### Approach

Async-first using `russh` (pure Rust SSH library) with `tokio` for async I/O. This provides:

- A proven SSH protocol implementation without C dependencies
- Natural concurrency for port forwarding and multiplexed sessions
- Clean static linking via musl (Linux) and mingw (Windows)
- Competitive or better binary size vs. Go

### Project Structure

```
neap/
├── Cargo.toml              # Single binary crate
├── build.rs                # Compile-time config injection (replaces Go ldflags)
├── build.sh                # Adapted from Undertow — handler gen, UX, engagement checklist
├── Makefile                # Cross-compilation targets (linux x86/x64, windows x86/x64)
├── src/
│   ├── main.rs             # Entry point, CLI parsing, mode selection
│   ├── config.rs           # Compile-time constants (password, host, port, etc.)
│   ├── server.rs           # SSH server setup, key generation, auth handlers
│   ├── session.rs          # Session dispatch — PTY vs command exec vs port-forward-only
│   ├── pty/
│   │   ├── mod.rs          # PTY trait abstraction
│   │   ├── unix.rs         # Linux PTY via nix crate
│   │   └── windows.rs      # Windows ConPTY via windows-sys crate
│   ├── transport.rs        # Connection modes — bind listener, reverse dial-home, TLS wrapping
│   ├── sftp.rs             # SFTP subsystem handler
│   ├── forwarding.rs       # Local, remote, and SOCKS5 dynamic port forwarding
│   └── info.rs             # Extra info channel (hostname, user, listening addr sent back home)
```

Single binary crate — no workspace. One output artifact per target.

## Dependencies

### Core

| Crate | Version | Purpose |
|-------|---------|---------|
| `russh` | 0.46 | SSH server & client protocol implementation |
| `russh-keys` | 0.46 | SSH key generation, parsing, auth |
| `russh-sftp` | 0.2 | SFTP subsystem (built on russh channels) |
| `tokio` | 1 (full features) | Async runtime |
| `tokio-rustls` | 0.26 | TLS wrapping (rustls-based, no OpenSSL) |
| `rustls` | 0.23 | TLS config — SNI spoofing, ALPN negotiation |
| `rcgen` | 0.13 | Self-signed certificate generation (ECDSA P-256) |
| `log` | 0.4 | Logging facade |
| `env_logger` | 0.11 | Stderr logging backend |
| `subtle` | 2.6 | Constant-time comparison for auth |

### Platform-Specific

| Crate | Platform | Purpose |
|-------|----------|---------|
| `nix` (features: term, pty, process) | Unix | PTY management, signals, ioctl |
| `windows-sys` (features: Win32_System_Console) | Windows | ConPTY API |

### Optional

| Crate | Feature Flag | Purpose |
|-------|-------------|---------|
| `clap` (derive) | `cli` (default) | Runtime CLI parsing, excluded with NOCLI |

### Excluded (and why)

- No `libssh2` — C dependency, hurts static linking
- No `openssl` / `native-tls` — replaced by pure-Rust rustls
- No `async-std` — tokio has better ecosystem support
- No dedicated SOCKS5 crate — SOCKS5 is handled client-side, server just accepts `direct-tcpip`

## Connection Modes & Transport

### Bind Mode

```
[Neap binary] --listen--> TCP socket on :PORT
                              |
                     (optional TLS wrapper)
                              |
                     russh Server::accept()
                              |
                     SSH session (PTY / exec / forwarding / SFTP)
```

`TcpListener::bind()` accept loop. Optionally wrap each accepted `TcpStream` in a `tokio_rustls::TlsAcceptor` before handing to russh.

### Reverse Mode

```
[Neap binary] --dial--> attacker SSH server (TCP or TLS+TCP)
                              |
                     authenticate as client with baked-in password
                              |
                     request remote port forward (tcpip-forward)
                              |
                     send extra info channel (hostname, user, bind addr)
                              |
                     listen on reverse-forwarded port
                              |
                     incoming connections on that port → russh Server
```

Steps:
1. Connect to attacker's SSH server as a **client** using `russh::client`
2. Request `tcpip-forward` to bind a port on the attacker's machine (port 0 = random allocation)
3. Open a custom `rs-info` channel to send back hostname/user/listening address (attacker rejects with `"th4nkz"` — same protocol as Undertow)
4. Each forwarded connection is handed to Neap's own SSH **server** instance

### TLS Wrapping

Wraps the SSH connection inside TLS to look like HTTPS on the wire:

- **Bind mode:** `TlsAcceptor` with self-signed cert (ECDSA P-256 via `rcgen`), ALPN set to `["h2", "http/1.1"]`, SNI from config
- **Reverse mode:** `TlsConnector` with `ServerName` set to the SNI spoof target (default `www.microsoft.com`), ALPN `["h2", "http/1.1"]`, certificate verification disabled
- SSH version banner set to `"OpenSSH_8.9"` — same spoofing as Undertow

### Key Generation

Ephemeral Ed25519 host key generated on startup via `russh_keys`. No key persistence — new key every launch, same as Undertow.

## SSH Session Handling

Three session types, dispatched on channel request type:

### 1. PTY Session

**Linux:**
- `nix::pty::openpty()` for master/slave file descriptors
- Fork child process, `setsid()` + `login_tty(slave_fd)`
- Exec configured shell (default `/bin/bash`)
- Set `TERM` env var from client PTY request, `HOME` from current user
- Bidirectional async copy: `master_fd ↔ SSH channel` via `tokio::io::unix::AsyncFd`
- Handle `window-change` requests via `TIOCSWINSZ` ioctl

**Windows (10+ build 17763+):**
- `CreatePseudoConsole` API for ConPTY
- Spawn `powershell.exe`
- Bidirectional pipe copy between ConPTY and SSH channel
- Handle `window-change` via `ResizePseudoConsole`

**Windows (older):**
- Deny PTY with message suggesting `ssh <opts> <ip> cmd`
- If shell is set to `ssh-shellhost.exe` path, launch it with `---pty cmd` flag (same as Undertow legacy fallback)

### 2. Command Execution

When no PTY is requested but a command is provided:
- `tokio::process::Command` to spawn the requested command
- Pipe stdin from SSH channel, stdout/stderr to SSH channel
- Await exit, return exit code via channel
- Handle session cancellation via `tokio::select!`

### 3. Port-Forward-Only

When no PTY and no command:
- Session stays open, awaiting session close signal
- Exists for clients that only need port forwarding

### Authentication

Two methods, checked in order:
1. **Public key** — if `authorizedKey` is set at compile time, compare marshalled key bytes (constant-time via `subtle` crate)
2. **Password** — constant-time comparison against baked-in password (via `subtle` crate)

All incoming usernames accepted (auth is password/key based, not username based) — same as Undertow.

## SFTP

Handled by `russh-sftp` as a subsystem on the `"sftp"` channel:

- Implement `SftpSession` trait to handle file operations (open, read, write, stat, readdir, mkdir, remove, rename, etc.)
- Backend: actual filesystem operations via `tokio::fs`
- Full read/write access, no sandboxing — this is a pentest tool
- Registered as subsystem handler for `"sftp"` in russh server config

## Port Forwarding

### Local Port Forwarding (`direct-tcpip`)

Client requests connection to `host:port` through SSH tunnel:
- Accept channel open (unless `-N` mode denies it)
- `TcpStream::connect(host, port)`
- `tokio::io::copy_bidirectional` between SSH channel and TCP stream

### Remote Port Forwarding (`tcpip-forward`)

Client requests Neap to listen on a port and forward connections back:
- `TcpListener::bind()` on requested address
- Each accepted connection opens a `forwarded-tcpip` channel back to client
- `tokio::io::copy_bidirectional` between TCP stream and SSH channel

### Dynamic Forwarding (SOCKS5)

SOCKS5 dynamic forwarding (`ssh -D`) is handled entirely by the SSH **client** — the client runs a local SOCKS5 proxy and translates each SOCKS5 CONNECT into a `direct-tcpip` channel open to the server. Neap's role is simply to accept those `direct-tcpip` requests (same as local port forwarding above). No SOCKS5 implementation is needed in the server.

### `-N` Mode (noShell)

Denies shell/exec/subsystem requests and local port forwarding. Only remote port forwarding remains functional. Use case: catching reverse connections without allowing shell access on the listener.

## Build System & Configuration

### Compile-Time Config via `build.rs`

`build.rs` reads environment variables and emits them as `cargo:rustc-env` directives. `config.rs` reads them via `env!()` macros.

| Env Variable | Default | Purpose |
|-------------|---------|---------|
| `NEAP_PASSWORD` | `letmeinbrudipls` | Auth password |
| `NEAP_PUBKEY` | (empty) | Authorized public key |
| `NEAP_SHELL` | `/bin/bash` | Default shell |
| `NEAP_LUSER` | `svc` | Username for reverse connections |
| `NEAP_LHOST` | (empty) | Target host (empty = bind mode) |
| `NEAP_LPORT` | `31337` | SSH port |
| `NEAP_BPORT` | `0` | Bind port after reverse connection (0 = random) |
| `NEAP_NOCLI` | (empty) | Disable CLI when set |
| `NEAP_TLS_WRAP` | (empty) | Enable TLS wrapping when set |
| `NEAP_TLS_SNI` | `www.microsoft.com` | SNI for TLS ClientHello |

### Cargo Feature Flags

```toml
[features]
default = ["cli"]
cli = ["dep:clap"]
```

When `NEAP_NOCLI` is set, `build.sh` passes `--no-default-features` to exclude clap (~200KB savings).

### Release Profile

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### Cross-Compilation Targets

| Target Triple | Output |
|--------------|--------|
| `x86_64-unknown-linux-musl` | `neap-linux-x64` |
| `i686-unknown-linux-musl` | `neap-linux-x86` |
| `x86_64-pc-windows-gnu` | `neap-windows-x64.exe` |
| `i686-pc-windows-gnu` | `neap-windows-x86.exe` |

### Binary Size Budget

| Technique | Estimated Savings |
|-----------|-------------------|
| `strip` symbols | 30-40% |
| `opt-level = "z"` | 10-15% |
| `lto = true` | 10-20% |
| `codegen-units = 1` | ~5% |
| `panic = "abort"` | 5-10% |
| UPX compression | 50-60% |

**Target: <2MB stripped, <1MB with UPX.**

### `build.sh`

Adapted from Undertow's `build.sh` with minimal changes:
- Replaces `go build -ldflags` with `cargo build --release --target <target>` + env vars
- Replaces `make` calls with cargo invocations
- Keeps all existing UX: argument parsing, address validation, password generation, handler script generation, colored output (Catppuccin Mocha), engagement checklist, dry-run mode, UPX compression

### Makefile

Thin wrapper around cargo:
- `make build` — all 4 targets + current platform
- `make compressed` — build then UPX each binary
- `make clean` — `rm -f bin/neap*`

## Error Handling

- **No panics in production paths.** All fallible operations use `Result<T>` with `?` propagation.
- **Custom `NeapError` enum** wraps error types from russh, I/O, TLS, etc.
- **Fail silently on sessions.** A broken connection logs (if verbose) and continues serving. One bad session never kills the server.
- **Startup failures are fatal.** Can't bind or dial home → `process::exit(1)` with log message.
- **No `.unwrap()` outside of tests.** Enforced by convention.

## Logging

- **Default (no `-v`):** All log output discarded. Zero output. Zero disk artifacts.
- **Verbose (`-v`):** Logs to stderr via `env_logger`:
  - Connection accepted/rejected
  - Auth success/failure with remote address
  - PTY/command/forwarding requests
  - Session start/end
  - TLS handshake events
- **No file logging.** No log files, no temp files, no disk artifacts.

## Graceful Shutdown

- `tokio::signal` to catch SIGTERM/SIGINT (Unix) / Ctrl+C (Windows)
- Close the listener, let active sessions drain for up to 5 seconds, then force exit
- In reverse mode, closing the SSH client connection tears down the remote port forward automatically

## Protocol Compatibility

Neap must be compatible with standard SSH clients and Undertow's own handler infrastructure:

- **SSH version banner:** `"OpenSSH_8.9"`
- **`rs-info` channel:** Same custom channel type, same `ExtraInfo` struct (CurrentUser, Hostname, ListeningAddress), same `"th4nkz"` rejection protocol
- **Handler scripts** generated by `build.sh` work identically — they start a listener and display connection info on callback
- **Interoperable:** Any standard SSH client (OpenSSH, PuTTY) connects to Neap the same way it connects to Undertow

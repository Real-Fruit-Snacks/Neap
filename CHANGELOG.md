# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-06

### Added
- Reverse shell (dial home to attacker infrastructure)
- Bind shell (listen on target for connections)
- Full PTY support (Linux via openpty, Windows via ConPTY)
- SFTP file transfer
- Local, remote, and dynamic (SOCKS5) port forwarding
- TLS wrapping with ALPN negotiation and SNI spoofing
- Password and public key authentication
- Build-time configuration via environment variables
- Optional CLI via clap (excluded with --no-default-features)
- Cross-platform support (Linux x86/x64, Windows x86/x64)
- Build script with handler generation and engagement checklist
- Graceful shutdown on SIGTERM/SIGINT/Ctrl+C

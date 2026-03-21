#!/bin/sh
set -eu

REPO="${REPO:-telemt/telemt}"
BIN_NAME="${BIN_NAME:-telemt}"
INSTALL_DIR="${INSTALL_DIR:-/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/telemt}"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/telemt.toml}"
WORK_DIR="${WORK_DIR:-/opt/telemt}"
TLS_DOMAIN="${TLS_DOMAIN:-petrovich.ru}"
SERVICE_NAME="telemt"
TEMP_DIR=""
SUDO=""
CONFIG_PARENT_DIR=""
SERVICE_START_FAILED=0

ACTION="install"
TARGET_VERSION="${VERSION:-latest}"

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) ACTION="help"; shift ;;
        uninstall|--uninstall)
            if [ "$ACTION" != "purge" ]; then ACTION="uninstall"; fi
            shift ;;
        purge|--purge) ACTION="purge"; shift ;;
        install|--install) ACTION="install"; shift ;;
        -*) printf '[ERROR] Unknown option: %s\n' "$1" >&2; exit 1 ;;
        *)
            if [ "$ACTION" = "install" ]; then TARGET_VERSION="$1"
            else printf '[WARNING] Ignoring extra argument: %s\n' "$1" >&2; fi
            shift ;;
    esac
done

say() {
    if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
        printf '\n'
    else
        printf '[INFO] %s\n' "$*"
    fi
}
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

write_root() { $SUDO sh -c 'cat > "$1"' _ "$1"; }

cleanup() {
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

show_help() {
    say "Usage: $0 [ <version> | install | uninstall | purge | --help ]"
    say "  <version>    Install specific version (e.g. 3.3.15, default: latest)"
    say "  install      Install the latest version"
    say "  uninstall    Remove the binary and service (keeps config and user)"
    say "  purge        Remove everything including configuration, data, and user"
    exit 0
}

check_os_entity() {
    if command -v getent >/dev/null 2>&1; then getent "$1" "$2" >/dev/null 2>&1
    else grep -q "^${2}:" "/etc/$1" 2>/dev/null; fi
}

normalize_path() {
    printf '%s\n' "$1" | tr -s '/' | sed 's|/$||; s|^$|/|'
}

get_realpath() {
    path_in="$1"
    case "$path_in" in /*) ;; *) path_in="$(pwd)/$path_in" ;; esac

    if command -v realpath >/dev/null 2>&1; then 
        if realpath_out="$(realpath -m "$path_in" 2>/dev/null)"; then
            printf '%s\n' "$realpath_out"
            return
        fi
    fi
    
    if command -v readlink >/dev/null 2>&1; then
        resolved_path="$(readlink -f "$path_in" 2>/dev/null || true)"
        if [ -n "$resolved_path" ]; then
            printf '%s\n' "$resolved_path"
            return
        fi
    fi

    d="${path_in%/*}"; b="${path_in##*/}"
    if [ -z "$d" ]; then d="/"; fi
    if [ "$d" = "$path_in" ]; then d="/"; b="$path_in"; fi

    if [ -d "$d" ]; then
        abs_d="$(cd "$d" >/dev/null 2>&1 && pwd || true)"
        if [ -n "$abs_d" ]; then
            if [ "$b" = "." ] || [ -z "$b" ]; then printf '%s\n' "$abs_d"
            elif [ "$abs_d" = "/" ]; then printf '/%s\n' "$b"
            else printf '%s/%s\n' "$abs_d" "$b"; fi
        else
            normalize_path "$path_in"
        fi
    else
        normalize_path "$path_in"
    fi
}

get_svc_mgr() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then echo "openrc"
    else echo "none"; fi
}

verify_common() {
    [ -n "$BIN_NAME" ] || die "BIN_NAME cannot be empty."
    [ -n "$INSTALL_DIR" ] || die "INSTALL_DIR cannot be empty."
    [ -n "$CONFIG_DIR" ] || die "CONFIG_DIR cannot be empty."
    [ -n "$CONFIG_FILE" ] || die "CONFIG_FILE cannot be empty."

    case "${INSTALL_DIR}${CONFIG_DIR}${WORK_DIR}${CONFIG_FILE}" in
        *[!a-zA-Z0-9_./-]*) die "Invalid characters in paths. Only alphanumeric, _, ., -, and / allowed." ;;
    esac

    case "$TARGET_VERSION" in *[!a-zA-Z0-9_.-]*) die "Invalid characters in version." ;; esac
    case "$BIN_NAME" in *[!a-zA-Z0-9_-]*) die "Invalid characters in BIN_NAME." ;; esac

    INSTALL_DIR="$(get_realpath "$INSTALL_DIR")"
    CONFIG_DIR="$(get_realpath "$CONFIG_DIR")"
    WORK_DIR="$(get_realpath "$WORK_DIR")"
    CONFIG_FILE="$(get_realpath "$CONFIG_FILE")"

    CONFIG_PARENT_DIR="${CONFIG_FILE%/*}"
    if [ -z "$CONFIG_PARENT_DIR" ]; then CONFIG_PARENT_DIR="/"; fi
    if [ "$CONFIG_PARENT_DIR" = "$CONFIG_FILE" ]; then CONFIG_PARENT_DIR="."; fi

    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    else
        command -v sudo >/dev/null 2>&1 || die "This script requires root or sudo. Neither found."
        SUDO="sudo"
        if ! sudo -n true 2>/dev/null; then
            if ! [ -t 0 ]; then
                die "sudo requires a password, but no TTY detected. Aborting to prevent hang."
            fi
        fi
    fi

    if [ -n "$SUDO" ]; then
        if $SUDO sh -c '[ -d "$1" ]' _ "$CONFIG_FILE"; then
            die "Safety check failed: CONFIG_FILE '$CONFIG_FILE' is a directory."
        fi
    elif [ -d "$CONFIG_FILE" ]; then
        die "Safety check failed: CONFIG_FILE '$CONFIG_FILE' is a directory."
    fi

    for path in "$CONFIG_DIR" "$CONFIG_PARENT_DIR" "$WORK_DIR"; do
        check_path="$(get_realpath "$path")"
        case "$check_path" in
            /|/bin|/sbin|/usr|/usr/bin|/usr/sbin|/usr/local|/usr/local/bin|/usr/local/sbin|/usr/local/etc|/usr/local/share|/etc|/var|/var/lib|/var/log|/var/run|/home|/root|/tmp|/lib|/lib64|/opt|/run|/boot|/dev|/sys|/proc)
                die "Safety check failed: '$path' (resolved to '$check_path') is a critical system directory." ;;
        esac
    done

    check_install_dir="$(get_realpath "$INSTALL_DIR")"
    case "$check_install_dir" in
        /|/etc|/var|/home|/root|/tmp|/usr|/usr/local|/opt|/boot|/dev|/sys|/proc|/run)
            die "Safety check failed: INSTALL_DIR '$INSTALL_DIR' is a critical system directory." ;;
    esac

    for cmd in id uname grep find rm chown chmod mv mktemp mkdir tr dd sed ps head sleep cat tar gzip rmdir; do
        command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
    done
}

verify_install_deps() {
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "Neither curl nor wget is installed."
    command -v cp >/dev/null 2>&1 || command -v install >/dev/null 2>&1 || die "Need cp or install"

    if ! command -v setcap >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            $SUDO apk add --no-cache libcap-utils >/dev/null 2>&1 || $SUDO apk add --no-cache libcap >/dev/null 2>&1 || true
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO apt-get update -q >/dev/null 2>&1 || true
            $SUDO apt-get install -y -q libcap2-bin >/dev/null 2>&1 || true
        elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y -q libcap >/dev/null 2>&1 || true
        elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y -q libcap >/dev/null 2>&1 || true
        fi
    fi
}

detect_arch() {
    sys_arch="$(uname -m)"
    case "$sys_arch" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) die "Unsupported architecture: $sys_arch" ;;
    esac
}

detect_libc() {
    for f in /lib/ld-musl-*.so.* /lib64/ld-musl-*.so.*; do
        if [ -e "$f" ]; then echo "musl"; return 0; fi
    done
    if grep -qE '^ID="?alpine"?' /etc/os-release 2>/dev/null; then echo "musl"; return 0; fi
    if command -v ldd >/dev/null 2>&1 && (ldd --version 2>&1 || true) | grep -qi musl; then echo "musl"; return 0; fi
    echo "gnu"
}

fetch_file() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    else wget -q -O "$2" "$1"; fi
}

ensure_user_group() {
    nologin_bin="$(command -v nologin 2>/dev/null || command -v false 2>/dev/null || echo /bin/false)"

    if ! check_os_entity group telemt; then
        if command -v groupadd >/dev/null 2>&1; then $SUDO groupadd -r telemt
        elif command -v addgroup >/dev/null 2>&1; then $SUDO addgroup -S telemt
        else die "Cannot create group"; fi
    fi

    if ! check_os_entity passwd telemt; then
        if command -v useradd >/dev/null 2>&1; then
            $SUDO useradd -r -g telemt -d "$WORK_DIR" -s "$nologin_bin" -c "Telemt Proxy" telemt
        elif command -v adduser >/dev/null 2>&1; then
            if adduser --help 2>&1 | grep -q -- '-S'; then
                $SUDO adduser -S -D -H -h "$WORK_DIR" -s "$nologin_bin" -G telemt telemt
            else
                $SUDO adduser --system --home "$WORK_DIR" --shell "$nologin_bin" --no-create-home --ingroup telemt --disabled-password telemt
            fi
        else die "Cannot create user"; fi
    fi
}

setup_dirs() {
    $SUDO mkdir -p "$WORK_DIR" "$CONFIG_DIR" "$CONFIG_PARENT_DIR" || die "Failed to create directories"
    
    $SUDO chown telemt:telemt "$WORK_DIR" && $SUDO chmod 750 "$WORK_DIR"
    $SUDO chown root:telemt "$CONFIG_DIR" && $SUDO chmod 750 "$CONFIG_DIR"
    
    if [ "$CONFIG_PARENT_DIR" != "$CONFIG_DIR" ] && [ "$CONFIG_PARENT_DIR" != "." ] && [ "$CONFIG_PARENT_DIR" != "/" ]; then
        $SUDO chown root:telemt "$CONFIG_PARENT_DIR" && $SUDO chmod 750 "$CONFIG_PARENT_DIR"
    fi
}

stop_service() {
    svc="$(get_svc_mgr)"
    if [ "$svc" = "systemd" ] && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        $SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    elif [ "$svc" = "openrc" ] && rc-service "$SERVICE_NAME" status >/dev/null 2>&1; then
        $SUDO rc-service "$SERVICE_NAME" stop 2>/dev/null || true
    fi
}

install_binary() {
    bin_src="$1"; bin_dst="$2"
    if [ -e "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR" ]; then
        die "'$INSTALL_DIR' is not a directory."
    fi

    $SUDO mkdir -p "$INSTALL_DIR" || die "Failed to create install directory"
    if command -v install >/dev/null 2>&1; then
        $SUDO install -m 0755 "$bin_src" "$bin_dst" || die "Failed to install binary"
    else
        $SUDO rm -f "$bin_dst" 2>/dev/null || true
        $SUDO cp "$bin_src" "$bin_dst" && $SUDO chmod 0755 "$bin_dst" || die "Failed to copy binary"
    fi

    $SUDO sh -c '[ -x "$1" ]' _ "$bin_dst" || die "Binary not executable: $bin_dst"

    if command -v setcap >/dev/null 2>&1; then
        $SUDO setcap cap_net_bind_service=+ep "$bin_dst" 2>/dev/null || true
    fi
}

generate_secret() {
    secret="$(command -v openssl >/dev/null 2>&1 && openssl rand -hex 16 2>/dev/null || true)"
    if [ -z "$secret" ] || [ "${#secret}" -ne 32 ]; then
        if command -v od >/dev/null 2>&1; then secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        elif command -v hexdump >/dev/null 2>&1; then secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | hexdump -e '1/1 "%02x"')"
        elif command -v xxd >/dev/null 2>&1; then secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd -p | tr -d '\n')"
        fi
    fi
    if [ "${#secret}" -eq 32 ]; then echo "$secret"; else return 1; fi
}

generate_config_content() {
    escaped_tls_domain="$(printf '%s\n' "$TLS_DOMAIN" | tr -d '[:cntrl:]' | sed 's/\\/\\\\/g; s/"/\\"/g')"

    cat <<EOF
[general]
use_middle_proxy = false

[general.modes]
classic = false
secure = false
tls = true

[server]
port = 443

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain = "${escaped_tls_domain}"

[access.users]
hello = "$1"
EOF
}

install_config() {
    if [ -n "$SUDO" ]; then
        if $SUDO sh -c '[ -f "$1" ]' _ "$CONFIG_FILE"; then
            say "  -> Config already exists at $CONFIG_FILE. Skipping creation."
            return 0
        fi
    elif [ -f "$CONFIG_FILE" ]; then
        say "  -> Config already exists at $CONFIG_FILE. Skipping creation."
        return 0
    fi

    toml_secret="$(generate_secret)" || die "Failed to generate secret."

    generate_config_content "$toml_secret" | write_root "$CONFIG_FILE" || die "Failed to install config"
    $SUDO chown root:telemt "$CONFIG_FILE" && $SUDO chmod 640 "$CONFIG_FILE"

    say "  -> Config created successfully."
    say "  -> Generated secret for default user 'hello': $toml_secret"
}

generate_systemd_content() {
    cat <<EOF
[Unit]
Description=Telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=$WORK_DIR
ExecStart="${INSTALL_DIR}/${BIN_NAME}" "${CONFIG_FILE}"
Restart=on-failure
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

generate_openrc_content() {
    cat <<EOF
#!/sbin/openrc-run
name="$SERVICE_NAME"
description="Telemt Proxy Service"
command="${INSTALL_DIR}/${BIN_NAME}"
command_args="${CONFIG_FILE}"
command_background=true
command_user="telemt:telemt"
pidfile="/run/\${RC_SVCNAME}.pid"
directory="${WORK_DIR}"
rc_ulimit="-n 65536"
depend() { need net; use logger; }
EOF
}

install_service() {
    svc="$(get_svc_mgr)"
    if [ "$svc" = "systemd" ]; then
        generate_systemd_content | write_root "/etc/systemd/system/${SERVICE_NAME}.service"
        $SUDO chown root:root "/etc/systemd/system/${SERVICE_NAME}.service" && $SUDO chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"

        $SUDO systemctl daemon-reload || true
        $SUDO systemctl enable "$SERVICE_NAME" || true
        
        if ! $SUDO systemctl start "$SERVICE_NAME"; then
            say "[WARNING] Failed to start service"
            SERVICE_START_FAILED=1
        fi
    elif [ "$svc" = "openrc" ]; then
        generate_openrc_content | write_root "/etc/init.d/${SERVICE_NAME}"
        $SUDO chown root:root "/etc/init.d/${SERVICE_NAME}" && $SUDO chmod 0755 "/etc/init.d/${SERVICE_NAME}"

        $SUDO rc-update add "$SERVICE_NAME" default 2>/dev/null || true
        
        if ! $SUDO rc-service "$SERVICE_NAME" start 2>/dev/null; then
            say "[WARNING] Failed to start service"
            SERVICE_START_FAILED=1
        fi
    else
        cmd="\"${INSTALL_DIR}/${BIN_NAME}\" \"${CONFIG_FILE}\""
        if [ -n "$SUDO" ]; then 
            say "  -> Service manager not found. Start manually: sudo -u telemt $cmd"
        else 
            say "  -> Service manager not found. Start manually: su -s /bin/sh telemt -c '$cmd'"
        fi
    fi
}

kill_user_procs() {
    if command -v pkill >/dev/null 2>&1; then
        $SUDO pkill -u telemt "$BIN_NAME" 2>/dev/null || true
        sleep 1
        $SUDO pkill -9 -u telemt "$BIN_NAME" 2>/dev/null || true
    else
        if command -v pgrep >/dev/null 2>&1; then
            pids="$(pgrep -u telemt 2>/dev/null || true)"
        else
            pids="$(ps -u telemt -o pid= 2>/dev/null || true)"
        fi
        
        if [ -n "$pids" ]; then
            for pid in $pids; do
                case "$pid" in ''|*[!0-9]*) continue ;; *) $SUDO kill "$pid" 2>/dev/null || true ;; esac
            done
            sleep 1
            for pid in $pids; do
                case "$pid" in ''|*[!0-9]*) continue ;; *) $SUDO kill -9 "$pid" 2>/dev/null || true ;; esac
            done
        fi
    fi
}

uninstall() {
    say "Starting uninstallation of $BIN_NAME..."

    say ">>> Stage 1: Stopping services"
    stop_service

    say ">>> Stage 2: Removing service configuration"
    svc="$(get_svc_mgr)"
    if [ "$svc" = "systemd" ]; then
        $SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        $SUDO systemctl daemon-reload 2>/dev/null || true
    elif [ "$svc" = "openrc" ]; then
        $SUDO rc-update del "$SERVICE_NAME" 2>/dev/null || true
        $SUDO rm -f "/etc/init.d/${SERVICE_NAME}"
    fi

    say ">>> Stage 3: Terminating user processes"
    kill_user_procs

    say ">>> Stage 4: Removing binary"
    $SUDO rm -f "${INSTALL_DIR}/${BIN_NAME}"

    if [ "$ACTION" = "purge" ]; then
        say ">>> Stage 5: Purging configuration, data, and user"
        $SUDO rm -rf "$CONFIG_DIR" "$WORK_DIR"
        $SUDO rm -f "$CONFIG_FILE"
        if [ "$CONFIG_PARENT_DIR" != "$CONFIG_DIR" ] && [ "$CONFIG_PARENT_DIR" != "." ] && [ "$CONFIG_PARENT_DIR" != "/" ]; then
            $SUDO rmdir "$CONFIG_PARENT_DIR" 2>/dev/null || true
        fi
        $SUDO userdel telemt 2>/dev/null || $SUDO deluser telemt 2>/dev/null || true
        $SUDO groupdel telemt 2>/dev/null || $SUDO delgroup telemt 2>/dev/null || true
    else
        say "Note: Configuration and user kept. Run with 'purge' to remove completely."
    fi
    
    printf '\n====================================================================\n'
    printf '                    UNINSTALLATION COMPLETE\n'
    printf '====================================================================\n\n'
    exit 0
}

case "$ACTION" in
    help) show_help ;;
    uninstall|purge) verify_common; uninstall ;;
    install)
        say "Starting installation of $BIN_NAME (Version: $TARGET_VERSION)"

        say ">>> Stage 1: Verifying environment and dependencies"
        verify_common; verify_install_deps

        if [ "$TARGET_VERSION" != "latest" ]; then 
            TARGET_VERSION="${TARGET_VERSION#v}"
        fi
        
        ARCH="$(detect_arch)"; LIBC="$(detect_libc)"
        FILE_NAME="${BIN_NAME}-${ARCH}-linux-${LIBC}.tar.gz"
        
        if [ "$TARGET_VERSION" = "latest" ]; then
            DL_URL="https://github.com/${REPO}/releases/latest/download/${FILE_NAME}"
        else 
            DL_URL="https://github.com/${REPO}/releases/download/${TARGET_VERSION}/${FILE_NAME}"
        fi

        say ">>> Stage 2: Downloading archive"
        TEMP_DIR="$(mktemp -d)" || die "Temp directory creation failed"
        if [ -z "$TEMP_DIR" ] || [ ! -d "$TEMP_DIR" ]; then
            die "Temp directory is invalid or was not created"
        fi

        fetch_file "$DL_URL" "${TEMP_DIR}/${FILE_NAME}" || die "Download failed"

        say ">>> Stage 3: Extracting archive"
        if ! gzip -dc "${TEMP_DIR}/${FILE_NAME}" | tar -xf - -C "$TEMP_DIR" 2>/dev/null; then
            die "Extraction failed (downloaded archive might be invalid or 404)."
        fi

        EXTRACTED_BIN="$(find "$TEMP_DIR" -type f -name "$BIN_NAME" -print 2>/dev/null | head -n 1 || true)"
        [ -n "$EXTRACTED_BIN" ] || die "Binary '$BIN_NAME' not found in archive"

        say ">>> Stage 4: Setting up environment (User, Group, Directories)"
        ensure_user_group; setup_dirs; stop_service
        
        say ">>> Stage 5: Installing binary"
        install_binary "$EXTRACTED_BIN" "${INSTALL_DIR}/${BIN_NAME}"
        
        say ">>> Stage 6: Generating configuration"
        install_config
        
        say ">>> Stage 7: Installing and starting service"
        install_service

        if [ "${SERVICE_START_FAILED:-0}" -eq 1 ]; then
            printf '\n====================================================================\n'
            printf '               INSTALLATION COMPLETED WITH WARNINGS\n'
            printf '====================================================================\n\n'
            printf 'The service was installed but failed to start automatically.\n'
            printf 'Please check the logs to determine the issue.\n\n'
        else
            printf '\n====================================================================\n'
            printf '                      INSTALLATION SUCCESS\n'
            printf '====================================================================\n\n'
        fi
        
        svc="$(get_svc_mgr)"
        if [ "$svc" = "systemd" ]; then
            printf 'To check the status of your proxy service, run:\n'
            printf '  systemctl status %s\n\n' "$SERVICE_NAME"
        elif [ "$svc" = "openrc" ]; then
            printf 'To check the status of your proxy service, run:\n'
            printf '  rc-service %s status\n\n' "$SERVICE_NAME"
        fi
        
        printf 'To get your user connection links (for Telegram), run:\n'
        if command -v jq >/dev/null 2>&1; then
            printf '  curl -s http://127.0.0.1:9091/v1/users | jq -r '\''.data[] | "User: \\(.username)\\n\\(.links.tls[0] // empty)\\n"'\''\n'
        else
            printf '  curl -s http://127.0.0.1:9091/v1/users\n'
            printf '  (Tip: Install '\''jq'\'' for a much cleaner output)\n'
        fi
        
        printf '\n====================================================================\n'
        ;;
esac

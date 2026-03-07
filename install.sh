#!/bin/sh
set -eu

REPO="${REPO:-telemt/telemt}"
BIN_NAME="${BIN_NAME:-telemt}"
VERSION="${1:-${VERSION:-latest}}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

say() {
    printf '%s\n' "$*"
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

detect_arch() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) printf 'x86_64\n' ;;
        aarch64|arm64) printf 'aarch64\n' ;;
        *) die "unsupported architecture: $arch" ;;
    esac
}

detect_libc() {
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -iq musl; then
        printf 'musl\n'
    else
        printf 'gnu\n'
    fi
}

fetch_to_stdout() {
    url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$url"
    else
        die "neither curl nor wget is installed"
    fi
}

install_binary() {
    src="$1"
    dst="$2"

    if [ -w "$INSTALL_DIR" ] || { [ ! -e "$INSTALL_DIR" ] && [ -w "$(dirname "$INSTALL_DIR")" ]; }; then
        mkdir -p "$INSTALL_DIR"
        install -m 0755 "$src" "$dst"
    elif command -v sudo >/dev/null 2>&1; then
        sudo mkdir -p "$INSTALL_DIR"
        sudo install -m 0755 "$src" "$dst"
    else
        die "cannot write to $INSTALL_DIR and sudo is not available"
    fi
}

need_cmd uname
need_cmd tar
need_cmd mktemp
need_cmd grep
need_cmd install

ARCH="$(detect_arch)"
LIBC="$(detect_libc)"

case "$VERSION" in
    latest)
        URL="https://github.com/$REPO/releases/latest/download/${BIN_NAME}-${ARCH}-linux-${LIBC}.tar.gz"
        ;;
    *)
        URL="https://github.com/$REPO/releases/download/${VERSION}/${BIN_NAME}-${ARCH}-linux-${LIBC}.tar.gz"
        ;;
esac

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

say "Installing $BIN_NAME ($VERSION) for $ARCH-linux-$LIBC..."
fetch_to_stdout "$URL" | tar -xzf - -C "$TMPDIR"

[ -f "$TMPDIR/$BIN_NAME" ] || die "archive did not contain $BIN_NAME"

install_binary "$TMPDIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

say "Installed: $INSTALL_DIR/$BIN_NAME"
"$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || true

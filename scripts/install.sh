#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${DESTDIR:-}/usr/local/bin"
SHARE_DIR="${DESTDIR:-}/usr/local/share/linspec"
TARGET="linspec"

if [ "$(id -u)" -ne 0 ] && [ -z "${DESTDIR:-}" ]; then
    echo "Warning: Installing to system directories requires root."
    echo "Run with sudo or set DESTDIR for a prefix-based install."
    echo ""
    echo "  sudo ./scripts/install.sh"
    echo "  DESTDIR=/tmp/stage ./scripts/install.sh"
    exit 1
fi

if [ ! -f "$TARGET" ]; then
    echo "Building LinSpec first..."
    make clean all
fi

install -m 0755 -d "$BIN_DIR"
install -m 0755 "$TARGET" "$BIN_DIR/$TARGET"
install -m 0755 -d "$SHARE_DIR/profiles"
cp -r profiles/* "$SHARE_DIR/profiles/" 2>/dev/null || true

echo "OK LinSpec installed."
echo "  Binary: $BIN_DIR/$TARGET"
echo "  Profiles: $SHARE_DIR/profiles/"

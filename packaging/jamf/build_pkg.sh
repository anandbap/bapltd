#!/usr/bin/env bash
# Builds macOS installer package (.pkg) for BAP Edge
set -e

ARCH="${1:-arm64}"
VERSION="${2:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/dist/darwin-$ARCH"
PKG_ROOT="$BUILD_DIR/pkg-root"
PKG_SCRIPTS="$BUILD_DIR/pkg-scripts"
OUTPUT_PKG="$ROOT_DIR/dist/bapedge-darwin-$ARCH-$VERSION.pkg"

echo ">>> Building macOS .pkg for architecture: $ARCH (Version: $VERSION)..."

rm -rf "$PKG_ROOT" "$PKG_SCRIPTS"
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/etc/bap"
mkdir -p "$PKG_SCRIPTS"

# Copy binary
cp "$BUILD_DIR/bapedge" "$PKG_ROOT/usr/local/bin/bapedge"
chmod 755 "$PKG_ROOT/usr/local/bin/bapedge"

# Copy default config and policies
if [ -f "$ROOT_DIR/bap-config.json" ]; then
    cp "$ROOT_DIR/bap-config.json" "$PKG_ROOT/etc/bap/bap-config.json"
fi
if [ -f "$ROOT_DIR/policy.cedar" ]; then
    cp "$ROOT_DIR/policy.cedar" "$PKG_ROOT/etc/bap/policy.cedar"
fi
if [ -f "$ROOT_DIR/schema.json" ]; then
    cp "$ROOT_DIR/schema.json" "$PKG_ROOT/etc/bap/schema.json"
fi

# Prepare scripts & daemon plist
cp "$SCRIPT_DIR/postinstall.sh" "$PKG_SCRIPTS/postinstall"
chmod 755 "$PKG_SCRIPTS/postinstall"
cp "$SCRIPT_DIR/com.bap.edge.plist" "$PKG_ROOT/tmp/com.bap.edge.plist"

if command -v pkgbuild &> /dev/null; then
    pkgbuild \
        --root "$PKG_ROOT" \
        --scripts "$PKG_SCRIPTS" \
        --identifier "com.bap.edge.pkg" \
        --version "$VERSION" \
        --install-location "/" \
        "$OUTPUT_PKG"
    echo ">>> Successfully built package: $OUTPUT_PKG"
else
    echo "pkgbuild not found (non-macOS host); creating staging archive instead."
    tar -czf "$OUTPUT_PKG.tar.gz" -C "$PKG_ROOT" .
fi

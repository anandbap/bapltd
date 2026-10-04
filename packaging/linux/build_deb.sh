#!/usr/bin/env bash
# Builds Debian package (.deb) for BAP Edge
set -e

ARCH="${1:-amd64}"
VERSION="${2:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/dist/linux-$ARCH"
PKG_DIR="$BUILD_DIR/deb-staging"
OUTPUT_DEB="$ROOT_DIR/dist/bapedge-linux-$ARCH-$VERSION.deb"

echo ">>> Building Linux .deb for architecture: $ARCH (Version: $VERSION)..."

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/local/bin"
mkdir -p "$PKG_DIR/etc/bap"
mkdir -p "$PKG_DIR/lib/systemd/system"

# Binaries & Configurations
cp "$BUILD_DIR/bapedge" "$PKG_DIR/usr/local/bin/bapedge"
chmod 755 "$PKG_DIR/usr/local/bin/bapedge"

if [ -f "$ROOT_DIR/bap-config.json" ]; then
    cp "$ROOT_DIR/bap-config.json" "$PKG_DIR/etc/bap/bap-config.json"
fi
if [ -f "$ROOT_DIR/policy.cedar" ]; then
    cp "$ROOT_DIR/policy.cedar" "$PKG_DIR/etc/bap/policy.cedar"
fi
if [ -f "$ROOT_DIR/schema.json" ]; then
    cp "$ROOT_DIR/schema.json" "$PKG_DIR/etc/bap/schema.json"
fi

cp "$SCRIPT_DIR/bapedge.service" "$PKG_DIR/lib/systemd/system/bapedge.service"

# Debian control file
cat <<EOF > "$PKG_DIR/DEBIAN/control"
Package: bapedge
Version: $VERSION
Architecture: $ARCH
Maintainer: BAP Security Inc. <security@bap.internal>
Description: Bounded Authority Plane Edge Execution Broker & Zero-Trust Daemon
 Section: admin
 Priority: optional
EOF

# Postinst script
cat <<'EOF' > "$PKG_DIR/DEBIAN/postinst"
#!/bin/sh
set -e
systemctl daemon-reload || true
systemctl enable bapedge.service || true
systemctl restart bapedge.service || true
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

if command -v dpkg-deb &> /dev/null; then
    dpkg-deb --build "$PKG_DIR" "$OUTPUT_DEB"
    echo ">>> Successfully built Debian package: $OUTPUT_DEB"
else
    echo "dpkg-deb not found; creating tarball archive instead."
    tar -czf "$OUTPUT_DEB.tar.gz" -C "$PKG_DIR" .
fi

#!/bin/sh
# Install mcp-azure-sql — downloads the latest release binary for your platform.
# Usage: curl -fsSL https://raw.githubusercontent.com/albahubio/mcp-azure-sql/main/install.sh | sh
set -e

REPO="albahubio/mcp-azure-sql"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Map OS names
case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  mingw* | msys* | cygwin*) OS="windows" ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

# Get latest release tag
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
if [ -z "$LATEST" ]; then
  echo "Could not determine latest version"
  exit 1
fi

# Build download URL
EXT="tar.gz"
if [ "$OS" = "windows" ]; then
  EXT="zip"
fi
URL="https://github.com/$REPO/releases/download/v${LATEST}/mcp-azure-sql_${OS}_${ARCH}.${EXT}"

echo "Installing mcp-azure-sql v${LATEST} (${OS}/${ARCH})..."
echo "  From: $URL"
echo "  To:   $INSTALL_DIR/mcp-azure-sql"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and extract
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if [ "$EXT" = "zip" ]; then
  curl -fsSL "$URL" -o "$TMPDIR/release.zip"
  unzip -q "$TMPDIR/release.zip" -d "$TMPDIR"
else
  curl -fsSL "$URL" | tar xz -C "$TMPDIR"
fi

# Install binary
cp "$TMPDIR/mcp-azure-sql" "$INSTALL_DIR/mcp-azure-sql"
chmod +x "$INSTALL_DIR/mcp-azure-sql"

echo ""
echo "Installed: $INSTALL_DIR/mcp-azure-sql"
"$INSTALL_DIR/mcp-azure-sql" --version
echo ""

# Check if install dir is in PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "Note: Add $INSTALL_DIR to your PATH if not already:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    ;;
esac

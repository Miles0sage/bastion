#!/bin/bash
# Bastion — One-line install script
# Usage: curl -fsSL https://raw.githubusercontent.com/Miles0sage/bastion/master/install.sh | bash
set -e

REPO="Miles0sage/bastion"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/opt/bastion"

echo "Installing Bastion — Personal Edge Platform"
echo ""

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

if [ "$OS" != "linux" ]; then
  echo "Bastion currently supports Linux only. Got: $OS"
  exit 1
fi

# Check for root
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (or with sudo)"
  exit 1
fi

# Download latest release (or build from source)
echo "Checking for pre-built binary..."
RELEASE_URL="https://github.com/$REPO/releases/latest/download/bastion-${OS}-${ARCH}"

if curl -fsSL --head "$RELEASE_URL" >/dev/null 2>&1; then
  echo "Downloading bastion..."
  curl -fsSL -o "$INSTALL_DIR/bastion" "$RELEASE_URL"
  chmod +x "$INSTALL_DIR/bastion"
else
  echo "No pre-built binary found. Building from source..."
  if ! command -v go &>/dev/null; then
    echo "Go not found. Install Go 1.21+ first: https://go.dev/dl/"
    exit 1
  fi
  TMPDIR=$(mktemp -d)
  git clone --depth 1 "https://github.com/$REPO.git" "$TMPDIR/bastion"
  cd "$TMPDIR/bastion"
  go build -o "$INSTALL_DIR/bastion" .
  rm -rf "$TMPDIR"
fi

echo "Installed: $(bastion version)"

# Create config directory
mkdir -p "$CONFIG_DIR"
cd "$CONFIG_DIR"

# Generate config if not exists
if [ ! -f bastion.json ]; then
  bastion init
  echo ""
  echo "Edit $CONFIG_DIR/bastion.json with your domain and services."
fi

# Create systemd service
if [ ! -f /etc/systemd/system/bastion.service ]; then
  cat > /etc/systemd/system/bastion.service << 'UNIT'
[Unit]
Description=Bastion Edge Platform
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/bastion
ExecStart=/usr/local/bin/bastion up
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  echo "Systemd service created."
fi

echo ""
echo "============================="
echo " Bastion installed!"
echo "============================="
echo ""
echo " 1. Edit config:    nano $CONFIG_DIR/bastion.json"
echo " 2. Start:          systemctl start bastion"
echo " 3. Enable on boot: systemctl enable bastion"
echo " 4. Dashboard:      http://YOUR-IP:9090"
echo ""
echo " Docs: https://github.com/$REPO"

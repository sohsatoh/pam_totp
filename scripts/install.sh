#!/bin/bash
set -e

# pam_totp installation script
# Run with: sudo ./scripts/install.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔══════════════════════════════════════════════════════╗"
echo "║           pam_totp Installation                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    exit 1
fi

# Build release if not already built
if [ ! -f "$PROJECT_DIR/.build/release/libpam_totp.dylib" ]; then
    echo -e "${YELLOW}Building release...${NC}"
    cd "$PROJECT_DIR"
    swift build -c release
fi

# Create installation directories
echo "Creating directories..."
mkdir -p /usr/local/lib/pam
mkdir -p /usr/local/bin
mkdir -p /usr/local/share/pam_totp

# Install PAM module
echo "Installing PAM module..."
cp "$PROJECT_DIR/.build/release/libpam_totp.dylib" /usr/local/lib/pam/
chmod 755 /usr/local/lib/pam/libpam_totp.dylib

# Install server
echo "Installing authentication server..."
cp "$PROJECT_DIR/.build/release/pam_totp-server" /usr/local/bin/
chmod 755 /usr/local/bin/pam_totp-server

# Install setup utility
echo "Installing setup utility..."
cp "$PROJECT_DIR/.build/release/pam_totp-setup" /usr/local/bin/
chmod 755 /usr/local/bin/pam_totp-setup

# Create LaunchDaemon for authentication server
echo "Creating LaunchDaemon..."
cat > /Library/LaunchDaemons/com.pam_totp.server.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pam_totp.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/pam_totp-server</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/pam_totp.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/pam_totp.err</string>
</dict>
</plist>
EOF

chmod 644 /Library/LaunchDaemons/com.pam_totp.server.plist

# Load the LaunchDaemon
echo "Starting authentication server..."
launchctl load /Library/LaunchDaemons/com.pam_totp.server.plist 2>/dev/null || true

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo ""
echo "1. Run setup for your user:"
echo "   $ pam_totp-setup"
echo ""
echo "2. (Optional) Enable for sudo - add this line to /etc/pam.d/sudo_local:"
echo "   auth sufficient /usr/local/lib/pam/libpam_totp.dylib"
echo ""
echo "   Example /etc/pam.d/sudo_local:"
echo "   auth       sufficient     /usr/local/lib/pam/libpam_totp.dylib"
echo "   auth       include        sudo_local"
echo "   auth       sufficient     pam_smartcard.so"
echo "   ..."
echo ""
echo -e "${YELLOW}⚠️  Warning: Test carefully before relying on this for authentication!${NC}"
echo ""

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
echo "║           pam_totp Installation                      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    exit 1
fi

# Build release if not already built
if [ ! -f "$PROJECT_DIR/.build/arm64-apple-macosx/release/libpam_totp.dylib" ]; then
    echo -e "${YELLOW}Building release...${NC}"
    cd "$PROJECT_DIR"
    swift build -c release
fi

# Create installation directories
echo "Creating directories..."
mkdir -p /usr/local/lib/pam
mkdir -p /usr/local/bin
mkdir -p /var/run/pam_totp
chmod 700 /var/run/pam_totp

# Install PAM module
echo "Installing PAM module..."
cp "$PROJECT_DIR/.build/arm64-apple-macosx/release/libpam_totp.dylib" /usr/local/lib/pam/
chmod 755 /usr/local/lib/pam/libpam_totp.dylib

# Install setup utility
echo "Installing setup utility..."
cp "$PROJECT_DIR/.build/arm64-apple-macosx/release/pam_totp-setup" /usr/local/bin/
chmod 755 /usr/local/bin/pam_totp-setup

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo ""
echo "1. Run setup for your user (requires sudo):"
echo "   $ sudo pam_totp-setup"
echo "   $ sudo pam_totp-setup [username]  # for specific user"
echo ""
echo "2. (Optional) Enable for sudo - add this line to the beginning of /etc/pam.d/sudo_local:"
echo "   auth sufficient /usr/local/lib/pam/libpam_totp.dylib"
echo ""
echo "   Example /etc/pam.d/sudo_local configuration:"
echo "   auth       sufficient     /usr/local/lib/pam/libpam_totp.dylib"
echo "   auth       sufficient     pam_smartcard.so"
echo "   auth       required       pam_opendirectory.so"
echo ""
echo -e "${YELLOW}⚠️  Important security notes:${NC}"
echo "   • Keep a root session open when modifying PAM configuration"
echo "   • Test authentication in a separate terminal before closing root session"
echo "   • QR codes are only displayed during initial setup (pam_totp-setup)"
echo "   • Setup requires sudo privileges to prevent privilege escalation attacks"
echo ""
echo -e "${GREEN}Terminal-only TOTP authentication is now ready to use!${NC}"
echo ""

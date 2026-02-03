#!/bin/bash
set -e

# pam_totp uninstallation script
# Run with: sudo ./scripts/uninstall.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔══════════════════════════════════════════════════════╗"
echo "║           pam_totp Uninstallation                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}Warning: This will remove pam_totp from your system.${NC}"
echo "TOTP secrets will NOT be removed from keychain."
echo ""
read -p "Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Cancelled."
    exit 0
fi

# Remove files
echo "Removing files..."
rm -f /usr/local/lib/pam/libpam_totp.dylib
rm -f /usr/local/bin/pam_totp-setup
rm -rf /var/run/pam_totp

echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"
echo ""
echo -e "${YELLOW}Important reminders:${NC}"
echo "• Remove pam_totp configuration from /etc/pam.d/* files"
echo "• To remove TOTP secrets from keychain:"
echo "  $ security delete-generic-password -s com.sohsatoh.pam_totp"
echo ""

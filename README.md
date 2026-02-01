# pam_totp

A secure PAM authentication module for macOS that provides TOTP-based two-factor authentication using QR codes displayed directly in the terminal.

## Features

- Terminal-only authentication flow (no web browser required)
- TOTP-based two-factor authentication
- Secure QR code display in terminal
- Integration with standard TOTP apps (Google Authenticator, Authy, etc.)
- Enhanced security with replay attack prevention
- Designed for sudo and terminal environments

## Requirements

- macOS 13.0 or later
- Swift 5.9 or later
- Xcode Command Line Tools
- libqrencode (installed automatically)

## Installation

```bash
git clone https://github.com/sohsatoh/pam_totp.git
cd pam_totp
swift build -c release
sudo ./scripts/install.sh
```

The following files are installed:

- `/usr/local/lib/pam/libpam_totp.dylib`
- `/usr/local/bin/pam_totp-setup`

## Usage

### Setup TOTP Authentication

```bash
pam_totp-setup [username]
```

If no username is provided, the current user will be configured. The setup utility will:

1. Generate a secure TOTP secret
2. Display a QR code in the terminal
3. Store the secret securely in macOS Keychain
4. Verify the setup by requesting a TOTP code

Scan the QR code with your TOTP authenticator app.

### PAM Configuration

Add the following line to the beginning of `/etc/pam.d/sudo_local`:

```
auth sufficient /usr/local/lib/pam/libpam_totp.dylib
```

Complete example configuration:

```
auth       sufficient     /usr/local/lib/pam/libpam_totp.dylib
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

Warning: Keep a root session open in another terminal before modifying PAM configuration to avoid being locked out.

## How It Works

```
PAM Module               Terminal                Smartphone
    │                        │                       │
    │ 1. Load TOTP secret    │                       │
    │ 2. Display QR code     │                       │
    │ ───────────────────────→                       │
    │                        │                       │
    │                        │   3. Scan QR code     │
    │                        │ ─────────────────────→│
    │                        │                       │
    │ 4. Prompt for code     │                       │
    │ ───────────────────────→                       │
    │                        │                       │
    │                        │   5. Enter TOTP code  │
    │ ←───────────────────────                       │
    │                        │                       │
    │ 6. Verify code         │                       │
    ▼                        │                       │
PAM_SUCCESS / PAM_AUTH_ERR   │                       │
```

Authentication flow:

1. PAM module loads the TOTP secret from Keychain
2. A QR code is displayed directly in the terminal (setup only)
3. User scans the QR code with their TOTP app (one-time setup)
4. User enters the 6-digit TOTP code at the prompt
5. PAM module verifies the code and allows/denies access

## Directory Structure

```
src/
├── pam_module/   PAM authentication module
├── setup/        Setup and configuration utility
└── shared/       Shared components (TOTP, QRCode, Keychain)
```

## Security Features

- TOTP secrets stored securely in macOS Keychain with restricted access
- Replay attack prevention using used code tracking
- Constant-time comparison to prevent timing attacks
- Session-only attempt limits (maximum 10 attempts)
- Secure memory handling with explicit cleanup
- No network communication required
- QR codes only displayed during setup (never during sudo authentication)

## Uninstallation

```bash
sudo ./scripts/uninstall.sh
```

To remove TOTP secrets from Keychain:

```bash
# Remove specific user
security delete-generic-password -a USERNAME -s com.pam_totp

# Remove all pam_totp entries
security delete-generic-password -s com.pam_totp
```

## Development

```bash
# Build
swift build

# Test
swift test

# Build for release
swift build -c release
```

## Troubleshooting

### Authentication Fails

- Verify TOTP secret is properly stored: `security find-generic-password -s com.pam_totp`
- Check system time synchronization on both devices
- Ensure TOTP app is configured correctly
- Try generating a new TOTP secret with `pam_totp-setup`

### PAM Configuration Issues

- Test PAM configuration in a separate terminal session
- Check `/var/log/system.log` for PAM-related errors
- Verify library path: `/usr/local/lib/pam/libpam_totp.dylib`

## Limitations

- macOS only
- Terminal-based authentication only (not compatible with GUI login)
- Requires TOTP app on smartphone or other device

## License

MIT

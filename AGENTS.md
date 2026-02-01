# AGENTS.md

This file documents the AI agents and development context for the pam_totp project.

## Project Overview

pam_totp is a PAM (Pluggable Authentication Module) for macOS that provides TOTP-based two-factor authentication using QR codes displayed in the terminal. The project was developed with security and simplicity as primary concerns.

## Development Context

### Original Requirements

The project began with requirements for FIDO Cross-Device Authentication (CDA) as the primary goal, with TOTP as a fallback option. After analysis of available libraries and implementation complexity, the TOTP approach was selected for its practicality and security.

### Architecture Evolution

**Phase 1: HTTP Server Architecture**
- Initial implementation used a local HTTP server approach
- PAM module would communicate with a web server via IPC
- Users would authenticate through a web interface
- Multiple security vulnerabilities were identified in this approach

**Phase 2: Terminal-Only Architecture (Current)**
- Complete architectural redesign eliminating the HTTP server
- QR codes are displayed directly in the terminal
- TOTP codes are entered directly via PAM conversation API
- Significantly reduced attack surface and improved security

### Security Analysis

A comprehensive security review identified 15 potential vulnerabilities in the original HTTP server implementation. The terminal-only redesign resolved 11 of these issues, including all critical and high-priority vulnerabilities:

**Resolved Critical Issues:**
- HTTP server without authentication
- CSRF attack vulnerabilities  
- Process communication flaws
- Session enumeration attacks
- Predictable SessionID generation

**Resolved Medium Issues:**
- TOTP timing attacks (constant-time comparison)
- Replay attacks (used code tracking)
- Excessive Keychain permissions
- Sensitive memory handling
- Race conditions
- Username injection vulnerabilities

## Technical Decisions

### TOTP Implementation
- Uses RFC 6238 compliant TOTP with SHA-1 (for compatibility)
- 6-digit codes with 30-second time windows
- Base32 encoding for QR code compatibility
- Replay attack prevention through used code tracking

### Security Measures
- TOTP secrets stored in macOS Keychain with WhenUnlockedThisDeviceOnly access
- Maximum 10 authentication attempts per session
- Constant-time string comparison to prevent timing attacks
- Secure memory cleanup using memset_s for sensitive data
- No network communication required

### PAM Integration
- Direct integration using PAM conversation API
- Proper error handling and cleanup
- Thread-safe implementation
- Compatible with sudo and other PAM-enabled services

## Code Structure

### Core Components

**PAMShared Module** (`src/shared/`):
- TOTP.swift: RFC 6238 compliant TOTP implementation
- Keychain.swift: Secure credential storage
- QRCode.swift: Terminal QR code generation using libqrencode
- Session.swift: Simplified session management (terminal-only)

**PAM Module** (`src/pam_module/`):
- pam_totp.swift: Main PAM authentication module

**Setup Utility** (`src/setup/`):
- main.swift: User-friendly TOTP configuration tool

### Dependencies
- libqrencode: QR code generation
- Security framework: Keychain access
- CryptoKit: HMAC and cryptographic operations
- PAM headers: System authentication integration

## Testing Strategy

The project includes comprehensive unit tests covering:
- TOTP generation and verification (RFC test vectors)
- Base32 encoding/decoding
- Keychain operations
- QR code generation
- Replay attack prevention

## Development Guidelines

### Security First
- All security-related changes require careful review
- Sensitive data must be explicitly cleared from memory
- Timing attacks must be considered in cryptographic operations
- Principle of least privilege applies to all system access

### Simplicity
- Prefer simple, auditable code over complex optimizations
- Minimize dependencies and attack surface
- Clear separation of concerns between components

### macOS Integration
- Follow Apple security guidelines
- Use system frameworks appropriately
- Respect macOS security boundaries and permissions

## Future Considerations

### Potential Enhancements
- Support for other TOTP parameters (SHA-256, 8-digit codes)
- Integration with hardware security keys
- Enhanced error reporting and logging

### FIDO Cross-Device Authentication
If FIDO CDA becomes more mature and practical for PAM-level implementation, the current TOTP system could be extended or replaced. However, the terminal-only architecture provides a solid foundation that could accommodate future authentication methods.

## Build and Release

### Build Process
```bash
swift build -c release
```

### Installation
Installation scripts handle:
- Copying PAM module to system location
- Installing setup utility
- Configuring appropriate permissions
- Installing required dependencies (libqrencode)

### Compatibility
- macOS 13.0 or later
- Swift 5.9 or later
- Compatible with Apple Silicon and Intel Macs

## Documentation Standards

- All public APIs must be documented
- Security-relevant code requires detailed comments
- README.md should reflect current architecture accurately
- Changes to authentication flow require documentation updates

This project demonstrates how security requirements can drive architectural decisions that ultimately result in simpler, more maintainable code.
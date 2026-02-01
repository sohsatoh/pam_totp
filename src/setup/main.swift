import Foundation
import PAMShared

/// Setup utility for pam_totp
@main
struct Setup {
    static func main() {
        print("""
        ╔══════════════════════════════════════════════════════╗
        ║            pam_totp Setup Utility                    ║
        ║                                                      ║
        ║  This will configure TOTP authentication for your   ║
        ║  user account.                                       ║
        ╚══════════════════════════════════════════════════════╝
        """)
        
        // Security check: Require sudo for setup to prevent privilege escalation
        guard getuid() == 0 else {
            print("""
            
            ❌ Error: This setup utility must be run with sudo privileges
            
            Reason: To prevent security vulnerabilities where an attacker could
            reset TOTP authentication and gain unauthorized sudo access.
            
            Usage: sudo pam_totp-setup [username]
            
            """)
            exit(1)
        }
        
        // Get target username from command line argument or current user
        let targetUsername: String
        if CommandLine.argc > 1 {
            targetUsername = CommandLine.arguments[1]
        } else {
            guard let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"] else {
                print("Error: Could not determine target username. Please specify: sudo pam_totp-setup <username>")
                exit(1)
            }
            targetUsername = sudoUser
        }
        
        print("\nConfiguring TOTP for user: \(targetUsername)")
        
        // Security: Additional confirmation for existing users
        if Keychain.hasSecret(for: targetUsername) {
            print("\n⚠️  TOTP is already configured for user '\(targetUsername)'.")
            print("⚠️  Reconfiguring will invalidate existing TOTP tokens.")
            print("⚠️  This action requires administrator confirmation.")
            print("")
            print("Are you sure you want to reconfigure TOTP for '\(targetUsername)'? (yes/N): ", terminator: "")
            
            guard let response = readLine()?.lowercased(), response == "yes" else {
                print("Cancelled for security.")
                exit(0)
            }
            
            print("Administrator confirmed reconfiguration.")
        }
        
        // Generate new secret
        let secret = TOTP.generateSecret()
        let base32Secret = TOTP.base32Encode(secret)
        
        // Create otpauth URI for QR code
        let issuer = "pam_totp"
        let otpauthURL = "otpauth://totp/\(issuer):\(targetUsername)?secret=\(base32Secret)&issuer=\(issuer)&algorithm=SHA1&digits=6&period=30"
        
        print("\n" + String(repeating: "─", count: 56))
        print("\n📱 Scan this QR code with your authenticator app:\n")
        
        // Display QR code
        if let qrCode = QRCode.renderToTerminal(from: otpauthURL, invert: true) {
            print(qrCode)
        } else {
            print("(QR code generation failed)")
        }
        
        print("\n" + String(repeating: "─", count: 56))
        print("\n📝 Or manually enter this secret key:")
        print("\n   \(formatSecret(base32Secret))\n")
        print(String(repeating: "─", count: 56))
        
        // Verify setup
        print("\n🔐 Enter the 6-digit code from your authenticator to verify: ", terminator: "")
        
        guard let code = readLine(), code.count == 6 else {
            print("Invalid code. Setup cancelled.")
            exit(1)
        }
        
        let totp = TOTP(secret: secret)
        guard totp.verify(code) else {
            print("\n❌ Invalid code. Please try setup again.")
            exit(1)
        }
        
        // Save secret to keychain
        do {
            try Keychain.saveSecret(secret, for: targetUsername)
            print("\n✅ TOTP configured successfully for user '\(targetUsername)'!")
            print("\nYou can now use pam_totp for authentication.")
            print("\nTo enable, add this line to /etc/pam.d/sudo_local:")
            print("  auth sufficient /usr/local/lib/pam/libpam_totp.dylib")
        } catch {
            print("\n❌ Failed to save secret: \(error.localizedDescription)")
            exit(1)
        }
    }
    
    static func formatSecret(_ secret: String) -> String {
        // Format as groups of 4 characters
        var result = ""
        for (index, char) in secret.enumerated() {
            if index > 0 && index % 4 == 0 {
                result += " "
            }
            result.append(char)
        }
        return result
    }
}

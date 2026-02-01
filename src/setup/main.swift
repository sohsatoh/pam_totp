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
        
        // Get current username
        guard let username = ProcessInfo.processInfo.environment["USER"] else {
            print("Error: Could not determine username")
            exit(1)
        }
        
        print("\nConfiguring TOTP for user: \(username)")
        
        // Check if already configured
        if Keychain.hasSecret(for: username) {
            print("\n⚠️  TOTP is already configured for this user.")
            print("Do you want to reconfigure? (y/N): ", terminator: "")
            
            guard let response = readLine()?.lowercased(), response == "y" || response == "yes" else {
                print("Cancelled.")
                exit(0)
            }
        }
        
        // Generate new secret
        let secret = TOTP.generateSecret()
        let base32Secret = TOTP.base32Encode(secret)
        
        // Create otpauth URI for QR code
        let issuer = "pam_totp"
        let otpauthURL = "otpauth://totp/\(issuer):\(username)?secret=\(base32Secret)&issuer=\(issuer)&algorithm=SHA1&digits=6&period=30"
        
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
            try Keychain.saveSecret(secret, for: username)
            print("\n✅ TOTP configured successfully!")
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

import Foundation
import Crypto

/// Simple data structure for PAM authentication
public struct AuthSession: Codable {
    // Note: In terminal-only mode, complex session management is not needed
    // This is kept for potential future use
}

/// Authentication result enumeration
public enum AuthResult: Codable {
    case pending
    case approved
    case denied
    case expired
}

import Foundation
import Security

/// Keychain wrapper for secure storage of TOTP secrets
public struct Keychain {
    
    public static let service = "com.sohsatoh.pam_totp"
    
    /// Save TOTP secret for a user with access control
    public static func saveSecret(_ secret: Data, for username: String) throws {
        // Try with access control first
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [], // No additional constraints
            &error
        )
        
        if let access = access {
            // Use access control (production path)
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: username,
                kSecValueData as String: secret,
                kSecAttrAccessControl as String: access,
                kSecAttrSynchronizable as String: false
            ]
            
            SecItemDelete(query as CFDictionary)
            
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                // Fallback for testing environments
                if status == errSecMissingEntitlement {
                    return try saveSecretWithoutAccessControl(secret, for: username)
                }
                throw KeychainError.saveFailed(status)
            }
        } else {
            // Fallback if access control creation fails
            return try saveSecretWithoutAccessControl(secret, for: username)
        }
    }
    
    /// Fallback method for environments without access control support
    private static func saveSecretWithoutAccessControl(_ secret: Data, for username: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: username,
            kSecValueData as String: secret,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
    
    /// Load TOTP secret for a user
    public static func loadSecret(for username: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: username,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.loadFailed(status)
        }
        
        return data
    }
    
    /// Delete TOTP secret for a user
    public static func deleteSecret(for username: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: username
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
    
    /// Check if secret exists for a user
    public static func hasSecret(for username: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: username
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    public enum KeychainError: Error, LocalizedError {
        case saveFailed(OSStatus)
        case loadFailed(OSStatus)
        case deleteFailed(OSStatus)
        case accessControlFailed(Error)
        
        public var errorDescription: String? {
            switch self {
            case .saveFailed(let status):
                return "Failed to save to keychain: \(status)"
            case .loadFailed(let status):
                return "Failed to load from keychain: \(status)"
            case .deleteFailed(let status):
                return "Failed to delete from keychain: \(status)"
            case .accessControlFailed(let error):
                return "Failed to create access control: \(error.localizedDescription)"
            }
        }
    }
}

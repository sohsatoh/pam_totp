import Foundation
import Crypto

/// TOTP (Time-based One-Time Password) implementation per RFC 6238
public struct TOTP {
    public let secret: Data
    public let digits: Int
    public let period: TimeInterval
    public let algorithm: Algorithm
    
    public enum Algorithm {
        case sha1
        case sha256
        case sha512
    }
    
    public init(secret: Data, digits: Int = 6, period: TimeInterval = 30, algorithm: Algorithm = .sha1) {
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
    }
    
    /// Generate TOTP code for the current time
    public func generate(at date: Date = Date()) -> String {
        let counter = UInt64(date.timeIntervalSince1970 / period)
        return generateHOTP(counter: counter)
    }
    
    /// Verify a TOTP code with a time window, constant-time comparison, and replay protection
    /// - Parameters:
    ///   - code: The TOTP code to verify (must be 6 digits)
    ///   - date: The date to verify against (defaults to current time)
    ///   - window: Time window for verification (0 = exact time only, 1 = ±30s)
    ///   - username: Username for replay protection (required for security)
    /// - Returns: true if code is valid and not replayed, false otherwise
    public func verify(_ code: String, at date: Date = Date(), window: Int = 0, username: String? = nil) -> Bool {
        // Constant-time input validation (prevent timing attacks)
        let isValidLength = constantTimeEqual(code.count, 6)
        let isAllDigits = code.utf8.allSatisfy { $0 >= 48 && $0 <= 57 } // '0'...'9'
        
        guard isValidLength && isAllDigits else {
            // Perform dummy computation to maintain constant time
            _ = generateHOTP(counter: 0)
            return false
        }
        
        let counter = Int64(date.timeIntervalSince1970 / period)
        var foundMatch = false
        var matchingCounter: UInt64 = 0
        
        // Check all time windows (constant-time - don't early exit)
        for offset in -window...window {
            let checkCounter = UInt64(max(0, counter + Int64(offset)))
            let expectedCode = generateHOTP(counter: checkCounter)
            
            if constantTimeCompare(code, expectedCode) {
                foundMatch = true
                matchingCounter = checkCounter
            }
        }
        
        guard foundMatch else {
            return false
        }
        
        // Check for replay attack with persistent storage
        if let username = username {
            return !Self.isCodeUsed(username: username, counter: matchingCounter) &&
                   Self.markCodeAsUsed(username: username, counter: matchingCounter)
        }
        
        return true
    }
    
    // MARK: - Persistent Replay Protection
    
    private static let defaultUsedCodesDirectory = "/var/run/pam_totp"
    private static var usedCodesDirectory: String {
        // Allow override for testing
        if let testDir = ProcessInfo.processInfo.environment["PAM_TOTP_TEST_DIR"] {
            return testDir
        }
        return defaultUsedCodesDirectory
    }
    private static let filePermissions: mode_t = 0o700
    
    /// Check if a code has been used (persistent across processes)
    private static func isCodeUsed(username: String, counter: UInt64) -> Bool {
        let filename = "\(usedCodesDirectory)/\(username.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? username)"
        
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: filename)),
              let content = String(data: data, encoding: .utf8) else {
            return false
        }
        
        let usedCounters = Set(content.split(separator: "\n").compactMap { UInt64($0) })
        return usedCounters.contains(counter)
    }
    
    /// Mark a code as used (persistent across processes)
    private static func markCodeAsUsed(username: String, counter: UInt64) -> Bool {
        // Create directory if needed
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: usedCodesDirectory) {
            do {
                try fileManager.createDirectory(atPath: usedCodesDirectory, 
                                               withIntermediateDirectories: true)
                // Set secure permissions (only root can access)
                chmod(usedCodesDirectory, filePermissions)
            } catch {
                return false
            }
        }
        
        let filename = "\(usedCodesDirectory)/\(username.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? username)"
        let url = URL(fileURLWithPath: filename)
        
        // Load existing codes
        var usedCounters: Set<UInt64> = []
        if let data = try? Data(contentsOf: url),
           let content = String(data: data, encoding: .utf8) {
            usedCounters = Set(content.split(separator: "\n").compactMap { UInt64($0) })
        }
        
        // Clean old codes (older than 5 minutes)
        let cutoffCounter = UInt64(max(0, Int64(counter) - 10)) // 10 periods = 5 minutes
        usedCounters = usedCounters.filter { $0 >= cutoffCounter }
        
        // Add new code
        usedCounters.insert(counter)
        
        // Write back
        let content = usedCounters.sorted().map { String($0) }.joined(separator: "\n")
        do {
            try content.write(to: url, atomically: true, encoding: .utf8)
            chmod(filename, 0o600) // Only owner can read/write
            return true
        } catch {
            return false
        }
    }
    
    /// Constant-time integer equality check
    private func constantTimeEqual(_ a: Int, _ b: Int) -> Bool {
        var result: Int = 0
        result |= a ^ b
        return result == 0
    }
    
    /// Constant-time string comparison to prevent timing attacks
    private func constantTimeCompare(_ a: String, _ b: String) -> Bool {
        let aData = Data(a.utf8)
        let bData = Data(b.utf8)
        
        // Always compare 6 bytes (pad if needed) to maintain constant time
        var aPadded = aData
        var bPadded = bData
        
        while aPadded.count < 6 { aPadded.append(0) }
        while bPadded.count < 6 { bPadded.append(0) }
        
        aPadded = Data(aPadded.prefix(6))
        bPadded = Data(bPadded.prefix(6))
        
        var result: UInt8 = 0
        for i in 0..<6 {
            result |= aPadded[i] ^ bPadded[i]
        }
        
        return result == 0
    }
    
    /// Clean up old used codes to prevent memory growth
    private static func cleanupOldUsedCodes() {
        // This function is now handled in markCodeAsUsed()
        // Kept for backward compatibility
    }
    
    private func generateHOTP(counter: UInt64) -> String {
        var counterBigEndian = counter.bigEndian
        let counterData = Data(bytes: &counterBigEndian, count: 8)
        
        let hmac: Data
        switch algorithm {
        case .sha1:
            let key = SymmetricKey(data: secret)
            var h = HMAC<Insecure.SHA1>(key: key)
            h.update(data: counterData)
            hmac = Data(h.finalize())
        case .sha256:
            let key = SymmetricKey(data: secret)
            var h = HMAC<SHA256>(key: key)
            h.update(data: counterData)
            hmac = Data(h.finalize())
        case .sha512:
            let key = SymmetricKey(data: secret)
            var h = HMAC<SHA512>(key: key)
            h.update(data: counterData)
            hmac = Data(h.finalize())
        }
        
        let offset = Int(hmac[hmac.count - 1] & 0x0f)
        let truncatedHash = hmac.withUnsafeBytes { ptr -> UInt32 in
            let bytes = ptr.baseAddress!.advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            return (UInt32(bytes[0] & 0x7f) << 24) |
                   (UInt32(bytes[1]) << 16) |
                   (UInt32(bytes[2]) << 8) |
                   UInt32(bytes[3])
        }
        
        let code = truncatedHash % UInt32(pow(10, Double(digits)))
        return String(format: "%0\(digits)d", code)
    }
    
    /// Generate a new random secret with secure memory handling
    public static func generateSecret(length: Int = 20) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        let result = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        guard result == errSecSuccess else {
            // Zero the buffer before failing
            memset_s(&bytes, bytes.count, 0, bytes.count)
            fatalError("Failed to generate cryptographically secure random secret")
        }
        
        defer {
            // Zero the temporary buffer
            memset_s(&bytes, bytes.count, 0, bytes.count)
        }
        
        return Data(bytes)
    }
    
    /// Convert secret to Base32 for QR code
    public static func base32Encode(_ data: Data) -> String {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result = ""
        var buffer = 0
        var bitsLeft = 0
        
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                let index = (buffer >> (bitsLeft - 5)) & 0x1f
                result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
                bitsLeft -= 5
            }
        }
        
        if bitsLeft > 0 {
            let index = (buffer << (5 - bitsLeft)) & 0x1f
            result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
        }
        
        // Add padding
        while result.count % 8 != 0 {
            result.append("=")
        }
        
        return result
    }
    
    /// Decode Base32 secret
    public static func base32Decode(_ string: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let input = string.uppercased().filter { $0 != "=" }
        
        var result = [UInt8]()
        var buffer = 0
        var bitsLeft = 0
        
        for char in input {
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            let value = alphabet.distance(from: alphabet.startIndex, to: index)
            buffer = (buffer << 5) | value
            bitsLeft += 5
            
            if bitsLeft >= 8 {
                result.append(UInt8((buffer >> (bitsLeft - 8)) & 0xff))
                bitsLeft -= 8
            }
        }
        
        return Data(result)
    }
}

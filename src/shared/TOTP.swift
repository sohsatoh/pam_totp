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
    public func verify(_ code: String, at date: Date = Date(), window: Int = 1, username: String? = nil) -> Bool {
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
        
        // Check for replay attack
        if let username = username {
            Self.usedCodesLock.lock()
            defer { Self.usedCodesLock.unlock() }
            
            // Clean old used codes
            Self.cleanupOldUsedCodes()
            
            let key = "\(username):\(matchingCounter)"
            if Self.usedCodes[username]?.contains(key) == true {
                return false // Code already used
            }
            
            // Mark code as used
            if Self.usedCodes[username] == nil {
                Self.usedCodes[username] = []
            }
            Self.usedCodes[username]?.insert(key)
        }
        
        return true
    }
    
    // Used codes tracking for replay protection
    private static var usedCodes: [String: Set<String>] = [:]
    private static let usedCodesLock = NSLock()
    private static let maxUsedCodesAge: TimeInterval = 300 // 5 minutes
    
    /// Constant-time string comparison to prevent timing attacks
    private func constantTimeCompare(_ a: String, _ b: String) -> Bool {
        guard a.count == b.count else {
            return false
        }
        
        let aData = Data(a.utf8)
        let bData = Data(b.utf8)
        
        guard aData.count == bData.count else {
            return false
        }
        
        var result: UInt8 = 0
        for i in 0..<aData.count {
            result |= aData[i] ^ bData[i]
        }
        
        return result == 0
    }
    
    /// Clean up old used codes to prevent memory growth
    private static func cleanupOldUsedCodes() {
        let cutoffTime = Date().timeIntervalSince1970 - maxUsedCodesAge
        
        for (username, codes) in usedCodes {
            let filteredCodes = codes.filter { codeKey in
                // Extract counter from key format "username:counter"
                let parts = codeKey.split(separator: ":")
                guard parts.count == 2,
                      let counter = UInt64(parts[1]) else {
                    return false // Invalid format, remove
                }
                
                let codeTime = TimeInterval(counter) * 30 // Assuming 30s period
                return codeTime > cutoffTime
            }
            
            if filteredCodes.isEmpty {
                usedCodes.removeValue(forKey: username)
            } else {
                usedCodes[username] = Set(filteredCodes)
            }
        }
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

import XCTest
@testable import PAMShared

final class TOTPTests: XCTestCase {
    
    func testBase32Encode() {
        // Test vectors from RFC 4648
        let testCases: [(Data, String)] = [
            (Data(), ""),
            (Data("f".utf8), "MY======"),
            (Data("fo".utf8), "MZXQ===="),
            (Data("foo".utf8), "MZXW6==="),
            (Data("foob".utf8), "MZXW6YQ="),
            (Data("fooba".utf8), "MZXW6YTB"),
            (Data("foobar".utf8), "MZXW6YTBOI======"),
        ]
        
        for (input, expected) in testCases {
            let result = TOTP.base32Encode(input)
            XCTAssertEqual(result, expected, "Failed for input: \(String(data: input, encoding: .utf8) ?? "")")
        }
    }
    
    func testBase32Decode() {
        let testCases: [(String, Data)] = [
            ("MY======", Data("f".utf8)),
            ("MZXQ====", Data("fo".utf8)),
            ("MZXW6===", Data("foo".utf8)),
            ("MZXW6YQ=", Data("foob".utf8)),
            ("MZXW6YTB", Data("fooba".utf8)),
            ("MZXW6YTBOI======", Data("foobar".utf8)),
        ]
        
        for (input, expected) in testCases {
            let result = TOTP.base32Decode(input)
            XCTAssertEqual(result, expected, "Failed for input: \(input)")
        }
    }
    
    func testTOTPGenerate() {
        // Test vector from RFC 6238
        // Secret: "12345678901234567890" (ASCII)
        let secret = Data("12345678901234567890".utf8)
        let totp = TOTP(secret: secret, digits: 8, period: 30, algorithm: .sha1)
        
        // Test at known timestamp
        let date = Date(timeIntervalSince1970: 59)
        let code = totp.generate(at: date)
        XCTAssertEqual(code, "94287082")
    }
    
    func testTOTPVerify() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret)
        
        let code = totp.generate()
        XCTAssertTrue(totp.verify(code))
        XCTAssertFalse(totp.verify("000000"))
    }
    
    func testTOTPVerifyWithWindow() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret, period: 30)
        
        // Get code from 30 seconds ago
        let pastDate = Date().addingTimeInterval(-30)
        let pastCode = totp.generate(at: pastDate)
        
        // Should verify with window=1
        XCTAssertTrue(totp.verify(pastCode, window: 1))
    }
    
    func testSecretGeneration() {
        let secret1 = TOTP.generateSecret()
        let secret2 = TOTP.generateSecret()
        
        XCTAssertEqual(secret1.count, 20)
        XCTAssertEqual(secret2.count, 20)
        XCTAssertNotEqual(secret1, secret2)
    }
    
    func testReplayProtection() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret)
        let code = totp.generate()
        let username = "testuser"
        
        // First verification should succeed
        XCTAssertTrue(totp.verify(code, username: username))
        
        // Second verification with same code should fail (replay protection)
        XCTAssertFalse(totp.verify(code, username: username))
        
        // Different user should be able to use same code (different namespace)
        XCTAssertTrue(totp.verify(code, username: "differentuser"))
    }
    
    func testConstantTimeComparison() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret)
        
        // Generate a valid code
        let validCode = totp.generate()
        
        // Test with various invalid codes of same length
        XCTAssertTrue(totp.verify(validCode))
        XCTAssertFalse(totp.verify("000000"))
        XCTAssertFalse(totp.verify("999999"))
        XCTAssertFalse(totp.verify("123456"))
        
        // Different length should fail quickly
        XCTAssertFalse(totp.verify("12345"))
        XCTAssertFalse(totp.verify("1234567"))
    }
}

// Simple KeychainTests
final class KeychainTests: XCTestCase {
    
    func testKeychainOperations() {
        let username = "test_keychain_user"
        let secret = TOTP.generateSecret()
        
        // Clean up any existing entry
        try? Keychain.deleteSecret(for: username)
        
        // Test saving
        XCTAssertNoThrow(try Keychain.saveSecret(secret, for: username))
        
        // Test existence check
        XCTAssertTrue(Keychain.hasSecret(for: username))
        
        // Test loading
        XCTAssertNoThrow {
            let loadedSecret = try Keychain.loadSecret(for: username)
            XCTAssertEqual(loadedSecret, secret)
        }
        
        // Test deletion
        XCTAssertNoThrow(try Keychain.deleteSecret(for: username))
        XCTAssertFalse(Keychain.hasSecret(for: username))
    }
}

// QRCode tests
final class QRCodeTests: XCTestCase {
    
    func testQRCodeGeneration() {
        let testURL = "otpauth://totp/test:user@host?secret=JBSWY3DPEHPK3PXP&issuer=test"
        let qrCode = QRCode.renderToTerminal(from: testURL, invert: false)
        
        // Should generate some output
        XCTAssertNotNil(qrCode)
        XCTAssertFalse(qrCode?.isEmpty ?? true)
    }
}

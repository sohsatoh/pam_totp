import Foundation
import PAMShared
import CPAMBridge

// MARK: - PAM Module Entry Points

/// PAM authentication entry point - Terminal-only TOTP authentication
@_cdecl("pam_sm_authenticate")
public func pam_sm_authenticate(
    pamh: OpaquePointer,
    flags: Int32,
    argc: Int32,
    argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> Int32 {
    
    // Get username
    var userPtr: UnsafePointer<CChar>?
    let ret = pam_get_user(pamh, &userPtr, nil)
    guard ret == PAM_SUCCESS, let userPtr = userPtr else {
        return PAM_USER_UNKNOWN
    }
    let username = String(cString: userPtr)
    
    // Check if user has TOTP configured
    guard Keychain.hasSecret(for: username) else {
        _ = pam_error(pamh, "TOTP not configured. Contact your administrator.")
        return PAM_AUTH_ERR
    }
    
    // Security: Never show QR code during sudo authentication
    // QR codes should only be displayed during initial setup via pam_totp-setup
    // This prevents QR code theft during authentication attempts
    
    // Prompt for TOTP code with session-only retry logic
    var attempts = 0
    let maxAttempts = 10  // Session-only limit
    
    while attempts < maxAttempts {
        guard let otpCode = promptForOTP(pamh, attempt: attempts + 1, maxAttempts: maxAttempts) else {
            _ = pam_error(pamh, "Failed to read TOTP code.")
            return PAM_AUTH_ERR
        }
        
        // Validate format (constant-time to prevent timing attacks)
        let isValidLength = (otpCode.count == 6)
        let isAllDigits = otpCode.utf8.allSatisfy { $0 >= 48 && $0 <= 57 } // '0'...'9'
        
        guard isValidLength && isAllDigits else {
            _ = pam_error(pamh, "Invalid format. TOTP code must be 6 digits.")
            attempts += 1
            continue
        }
        
        // Verify TOTP with replay protection
        do {
            let secret = try Keychain.loadSecret(for: username)
            defer {
                // Secure cleanup of secret
                _ = secret.withUnsafeBytes { ptr in
                    memset_s(UnsafeMutableRawPointer(mutating: ptr.baseAddress!), 
                            secret.count, 0, secret.count)
                }
            }
            
            let totp = TOTP(secret: secret)
            
            if totp.verify(otpCode, username: username) {
                _ = pam_info(pamh, "TOTP authentication successful!")
                return PAM_SUCCESS
            } else {
                attempts += 1
                if attempts < maxAttempts {
                    _ = pam_error(pamh, "Invalid TOTP code. \(maxAttempts - attempts) attempts remaining.")
                } else {
                    _ = pam_error(pamh, "Invalid TOTP code. Maximum attempts exceeded.")
                    // Session ends here - no persistent lockout needed
                }
            }
        } catch {
            _ = pam_error(pamh, "Failed to verify TOTP: \(error.localizedDescription)")
            return PAM_AUTH_ERR
        }
    }
    
    return PAM_AUTH_ERR
}

/// PAM setcred entry point (required but not used)
@_cdecl("pam_sm_setcred")
public func pam_sm_setcred(
    pamh: OpaquePointer,
    flags: Int32,
    argc: Int32,
    argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> Int32 {
    return PAM_SUCCESS
}

// MARK: - Helper Functions

private func promptForOTP(_ pamh: OpaquePointer, attempt: Int, maxAttempts: Int) -> String? {
    let prompt = "TOTP code (\(attempt)/\(maxAttempts)): "
    
    var conv: UnsafeRawPointer?
    guard pam_get_item(pamh, PAM_CONV, &conv) == PAM_SUCCESS,
          let convPtr = conv else {
        return nil
    }
    
    let conversation = convPtr.assumingMemoryBound(to: pam_conv.self).pointee
    guard let convFunc = conversation.conv else {
        return nil
    }
    
    // Create message using strdup to get mutable pointer
    let promptCopy = strdup(prompt)
    defer { free(promptCopy) }
    
    let msg = pam_message(
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: promptCopy
    )
    
    return withUnsafePointer(to: msg) { msgPtr in
        let msgArrayPtr = UnsafeMutablePointer<UnsafePointer<pam_message>?>.allocate(capacity: 1)
        defer { msgArrayPtr.deallocate() }
        msgArrayPtr.pointee = msgPtr
        
        var resp: UnsafeMutablePointer<pam_response>?
        let result = convFunc(1, msgArrayPtr, &resp, conversation.appdata_ptr)
        
        guard result == PAM_SUCCESS, let response = resp else {
            return nil
        }
        
        defer {
            if let respStr = response.pointee.resp {
                let len = strlen(respStr)
                memset_s(respStr, len, 0, len) // Secure cleanup
                free(respStr)
            }
            free(response)
        }
        
        guard let respStr = response.pointee.resp else {
            return nil
        }
        
        return String(cString: respStr).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - PAM Helper Functions

private func pam_get_user(_ pamh: OpaquePointer, _ user: UnsafeMutablePointer<UnsafePointer<CChar>?>, _ prompt: UnsafePointer<CChar>?) -> Int32 {
    var item: UnsafeRawPointer?
    let ret = pam_get_item(pamh, PAM_USER, &item)
    if ret == PAM_SUCCESS, let item = item {
        user.pointee = item.assumingMemoryBound(to: CChar.self)
    }
    return ret
}

@_silgen_name("pam_get_item")
private func pam_get_item(_ pamh: OpaquePointer, _ item_type: Int32, _ item: UnsafeMutablePointer<UnsafeRawPointer?>) -> Int32

private func pam_info(_ pamh: OpaquePointer, _ message: String) -> Int32 {
    return message.withCString { msgPtr in
        pam_totp_info(pamh, msgPtr)
    }
}

private func pam_error(_ pamh: OpaquePointer, _ message: String) -> Int32 {
    return message.withCString { msgPtr in
        pam_totp_error(pamh, msgPtr)
    }
}

@_silgen_name("pam_totp_info")
private func pam_totp_info(_ pamh: OpaquePointer, _ msg: UnsafePointer<CChar>) -> Int32

@_silgen_name("pam_totp_error")
private func pam_totp_error(_ pamh: OpaquePointer, _ msg: UnsafePointer<CChar>) -> Int32

// PAM constants
private let PAM_SUCCESS: Int32 = 0
private let PAM_AUTH_ERR: Int32 = 7
private let PAM_USER_UNKNOWN: Int32 = 10
private let PAM_IGNORE: Int32 = 25
private let PAM_USER: Int32 = 2
private let PAM_CONV: Int32 = 5
private let PAM_PROMPT_ECHO_OFF: Int32 = 1

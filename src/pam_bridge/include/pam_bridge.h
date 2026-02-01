// PAM module bridging header for Swift
#ifndef PAM_BRIDGE_H
#define PAM_BRIDGE_H

#include <security/pam_appl.h>
#include <security/pam_modules.h>

// PAM return values
#define PAM_TOTP_SUCCESS PAM_SUCCESS
#define PAM_TOTP_AUTH_ERR PAM_AUTH_ERR
#define PAM_TOTP_USER_UNKNOWN PAM_USER_UNKNOWN
#define PAM_TOTP_IGNORE PAM_IGNORE

// PAM conversation function wrapper
int pam_totp_prompt(pam_handle_t *pamh, const char *msg);
int pam_totp_info(pam_handle_t *pamh, const char *msg);
int pam_totp_error(pam_handle_t *pamh, const char *msg);

#endif // PAM_BRIDGE_H

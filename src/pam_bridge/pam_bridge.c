#include "pam_bridge.h"
#include <stdlib.h>
#include <string.h>

// Helper function to send a message via PAM conversation
static int pam_msg(pam_handle_t *pamh, int style, const char *msg) {
    const struct pam_conv *conv;
    struct pam_message pmsg;
    const struct pam_message *pmsg_ptr = &pmsg;
    struct pam_response *resp = NULL;
    int ret;
    
    ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (ret != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
        return PAM_CONV_ERR;
    }
    
    pmsg.msg_style = style;
    pmsg.msg = (char *)msg;
    
    ret = conv->conv(1, &pmsg_ptr, &resp, conv->appdata_ptr);
    
    if (resp != NULL) {
        if (resp->resp != NULL) {
            memset(resp->resp, 0, strlen(resp->resp));
            free(resp->resp);
        }
        free(resp);
    }
    
    return ret;
}

int pam_totp_prompt(pam_handle_t *pamh, const char *msg) {
    return pam_msg(pamh, PAM_PROMPT_ECHO_ON, msg);
}

int pam_totp_info(pam_handle_t *pamh, const char *msg) {
    return pam_msg(pamh, PAM_TEXT_INFO, msg);
}

int pam_totp_error(pam_handle_t *pamh, const char *msg) {
    return pam_msg(pamh, PAM_ERROR_MSG, msg);
}

/*
 * pam_faceauth.so — C PAM wrapper around the Rust aegyra-pam cdylib.
 *
 * Build (example):
 *   gcc -fPIC -shared -o pam_faceauth.so pam_faceauth.c \
 *       -L../target/release -l:libaegyra_pam.so -lpam
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

extern int  faceauth_unseal_keyring(const char *user, uint8_t *buf, size_t len);
extern void faceauth_zero_buf(uint8_t *buf, size_t len);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_AUTH_ERR;
    }

    uint8_t buf[512];
    int n = faceauth_unseal_keyring(user, buf, sizeof(buf));
    if (n <= 0) {
        faceauth_zero_buf(buf, sizeof(buf));
        return PAM_AUTH_ERR;
    }

    /* PAM_AUTHTOK must be a NUL-terminated string */
    if ((size_t)n >= sizeof(buf)) {
        faceauth_zero_buf(buf, sizeof(buf));
        return PAM_AUTH_ERR;
    }
    buf[n] = '\0';

    int rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *)buf);
    faceauth_zero_buf(buf, sizeof(buf));

    return (rc == PAM_SUCCESS) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

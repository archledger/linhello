/*
 * pam_linhello.so — C PAM wrapper around the Rust linhello-pam cdylib.
 *
 * Build (example):
 *   gcc -fPIC -shared -o pam_linhello.so pam_linhello.c \
 *       -L../target/release -l:liblinhello_pam.so -lpam
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

extern int  linhello_unseal_keyring(const char *user, uint8_t *buf, size_t len);
extern int  linhello_reseal_password(const char *user, uint8_t *buf, size_t len);
extern void linhello_zero_buf(uint8_t *buf, size_t len);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_AUTH_ERR;
    }

    uint8_t buf[512];
    int n = linhello_unseal_keyring(user, buf, sizeof(buf));
    if (n <= 0) {
        linhello_zero_buf(buf, sizeof(buf));
        return PAM_AUTH_ERR;
    }

    /* PAM_AUTHTOK must be a NUL-terminated string */
    if ((size_t)n >= sizeof(buf)) {
        linhello_zero_buf(buf, sizeof(buf));
        return PAM_AUTH_ERR;
    }
    buf[n] = '\0';

    int rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *)buf);
    linhello_zero_buf(buf, sizeof(buf));

    return (rc == PAM_SUCCESS) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/*
 * Password stack: keep the sealed envelope in sync with the real login
 * password. This module must run AFTER the module that actually changes the
 * password (e.g. pam_unix), and be marked `optional` so a reseal failure
 * doesn't block the password change itself.
 *
 * PAM drives password change in two phases:
 *   PAM_PRELIM_CHECK  — sanity / old-authtok check. We defer.
 *   PAM_UPDATE_AUTHTOK — the new token is in PAM_AUTHTOK. Reseal now.
 */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    (void)argc; (void)argv;

    if (flags & PAM_PRELIM_CHECK) {
        return PAM_SUCCESS;
    }
    if (!(flags & PAM_UPDATE_AUTHTOK)) {
        return PAM_SUCCESS;
    }

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_IGNORE;
    }

    const void *authtok = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, &authtok) != PAM_SUCCESS
        || authtok == NULL) {
        return PAM_IGNORE;
    }

    /* Copy into a local buffer so the Rust side can zero it in place without
     * clobbering PAM's own copy. */
    size_t n = strnlen((const char *)authtok, 512);
    if (n == 0 || n >= 512) {
        return PAM_IGNORE;
    }
    uint8_t buf[512];
    memcpy(buf, authtok, n);

    int rc = linhello_reseal_password(user, buf, n);
    linhello_zero_buf(buf, sizeof(buf));

    /* `optional` module: never fail the password change itself. */
    (void)rc;
    return PAM_SUCCESS;
}

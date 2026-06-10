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
#include <syslog.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

extern int  linhello_unseal_keyring(const char *user, uint8_t *buf, size_t len);
extern int  linhello_verify_face(const char *user);
extern int  linhello_reseal_password(const char *user, uint8_t *buf, size_t len);
extern void linhello_zero_buf(uint8_t *buf, size_t len);

/* Module argument `wait` (or `wait=SECONDS`, default 20): keep retrying the
 * face capture until the deadline instead of one shot. Meant for the
 * NON-interactive parallel lockscreen stacks (kde-fingerprint) that start the
 * moment the lock screen appears — a single capture there would fire before
 * the user has even sat down. Never put `wait` on an interactive stack
 * (gdm-password, sddm, kde, sudo): it would hold up the password fallback. */
static int wait_seconds(int argc, const char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "wait") == 0) {
            return 20;
        }
        if (strncmp(argv[i], "wait=", 5) == 0) {
            int s = atoi(argv[i] + 5);
            return (s > 0 && s <= 300) ? s : 20;
        }
    }
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags;

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_AUTH_ERR;
    }

    /* Unprivileged PAM stacks — KDE's kscreenlocker runs PAM as the session
     * user (no root helper since Plasma 5.25). The daemon refuses to release
     * the sealed password to a non-root peer (by design: a user-level process
     * must never be able to extract the login password), and an in-session
     * unlock doesn't need PAM_AUTHTOK anyway — the wallet/keyring is already
     * open. Verify the face (same liveness-gated pipeline) and answer
     * success/failure only. */
    if (geteuid() != 0) {
        time_t deadline = time(NULL) + wait_seconds(argc, argv);
        for (;;) {
            if (linhello_verify_face(user) == 0) {
                pam_syslog(pamh, LOG_NOTICE,
                           "face auth (verify-only, unprivileged) succeeded for user '%s'",
                           user);
                return PAM_SUCCESS;
            }
            if (time(NULL) >= deadline) {
                break;
            }
            /* A capture+match round trip is ~1-2s; a short breather between
             * rounds keeps the camera from being hammered for the window. */
            struct timespec pause = { 0, 400 * 1000 * 1000 };
            nanosleep(&pause, NULL);
        }
        pam_syslog(pamh, LOG_NOTICE,
                   "face auth (verify-only, unprivileged) declined for user '%s'; "
                   "deferring to next auth module",
                   user);
        return PAM_AUTH_ERR;
    }

    /* Interactive stacks relay PAM_TEXT_INFO to their UI (GDM surfaces it on
     * the lock/login screen via UserVerifier InfoQuery; sudo prints a line) —
     * same feedback channel pam_fprintd uses for "Place your finger…". */
    pam_info(pamh, "Looking for your face…");

    uint8_t buf[512];
    int n = linhello_unseal_keyring(user, buf, sizeof(buf));
    if (n <= 0) {
        /* Face verify / TPM unseal declined. The daemon journal (linhellod,
         * "UnsealPassword: ...") carries the precise reason; here we just record
         * that this login fell through to the next module. */
        pam_syslog(pamh, LOG_NOTICE,
                   "face auth declined for user '%s'; deferring to next auth module",
                   user);
        linhello_zero_buf(buf, sizeof(buf));
        return PAM_AUTH_ERR;
    }

    /* PAM_AUTHTOK must be a NUL-terminated string */
    if ((size_t)n >= sizeof(buf)) {
        pam_syslog(pamh, LOG_ERR,
                   "unsealed secret too large for buffer for user '%s'", user);
        linhello_zero_buf(buf, sizeof(buf));
        return PAM_AUTH_ERR;
    }
    buf[n] = '\0';

    int rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *)buf);
    linhello_zero_buf(buf, sizeof(buf));

    if (rc != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_WARNING,
                   "face matched but pam_set_item(PAM_AUTHTOK) failed for user '%s'",
                   user);
        return PAM_AUTH_ERR;
    }

    /* Success: AUTHTOK now holds the unsealed login password so a downstream
     * pam_gnome_keyring `use_authtok` can unlock the login keyring. This is the
     * decisive "a face login happened in this transaction" line. */
    pam_syslog(pamh, LOG_NOTICE,
               "face auth succeeded for user '%s'; PAM_AUTHTOK set for keyring unlock",
               user);
    return PAM_SUCCESS;
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

    /* `optional` module: never fail the password change itself, but leave a
     * breadcrumb so a silently-stale envelope is diagnosable. */
    if (rc == 0) {
        pam_syslog(pamh, LOG_NOTICE,
                   "resealed password envelope for user '%s' after password change",
                   user);
    } else {
        pam_syslog(pamh, LOG_WARNING,
                   "could not reseal password envelope for user '%s' (rc=%d); "
                   "run 'linhello seal-password' to re-sync face auth",
                   user, rc);
    }
    return PAM_SUCCESS;
}

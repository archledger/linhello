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
extern int  linhello_authenticate(const char *user, const char *service,
                                  uint8_t *buf, size_t len);
extern int  linhello_auth_will_capture(const char *user, const char *service,
                                       uint8_t *msg, size_t msg_len);
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

    /* The PAM service name selects the policy class in the daemon (live-session
     * unlock vs greeter login vs sudo/elevation). Missing service → fail safe to
     * the password. */
    const char *service = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS
        || service == NULL) {
        return PAM_IGNORE;
    }

    /* The daemon makes the verify-vs-unseal-vs-deny decision (tier + service +
     * warm-session). We pass the service and react to the outcome. */
    int waits = wait_seconds(argc, argv);

    /* Pre-flight: ask the daemon (same classify→tier→warm→decide, no capture)
     * whether this op will actually engage the camera. This drives the prompt so
     * we never announce "Looking for your face…" for an operation that won't lift
     * a finger — e.g. the convenience tier at the greeter (Deny, RGB-only, no IR):
     * there the camera stays dark and we must fall straight through to the
     * password silently. The secure tier (login unseals, unlock verifies) and any
     * lock-screen Verify still light the camera, so the prompt shows there. */
    /* The pre-flight also reports WHY the camera can't be used, when it can't
     * (hardware privacy switch on, or no camera detected), so we can tell the
     * user instead of failing to the password silently. */
    char notice[256];
    notice[0] = '\0';
    int will_capture = linhello_auth_will_capture(user, service,
                                                  (uint8_t *)notice, sizeof(notice));
    if (will_capture <= 0) {
        /* 0 = policy deny (no camera engaged); <0 = daemon unreachable/error.
         * Either way there is no capture to narrate: stay silent, don't run the
         * retry loop, and cascade to the next module (the password). */
        pam_syslog(pamh, LOG_NOTICE,
                   "face auth not engaged for '%s' [%s] (%s); deferring to password",
                   user, service,
                   will_capture == 0 ? "policy: camera not used for this operation"
                                     : "daemon unavailable");
        return PAM_AUTH_ERR;
    }

    /* Interactive stacks relay PAM_TEXT_INFO to their UI (GDM via UserVerifier
     * InfoQuery; sudo prints a line). The non-interactive parallel lockscreen
     * stacks (kde-fingerprint, `wait`) don't, so skip the prompt there. */
    if (waits == 0) {
        if (notice[0] != '\0') {
            /* Camera blocked (privacy key) or absent: show why, rather than a
             * bare "Looking for your face…" that never engages. We still run the
             * attempt below (and the parallel `wait` stack keeps retrying), so
             * un-blocking the camera re-engages face unlock with no re-lock. */
            pam_info(pamh, "%s", notice);
        } else {
            pam_info(pamh, "Looking for your face…");
        }
    }
    time_t deadline = time(NULL) + waits;

    for (;;) {
        uint8_t buf[512];
        int n = linhello_authenticate(user, service, buf, sizeof(buf));

        if (n > 0) {
            /* Unseal: the buffer holds the unsealed login password. PAM_AUTHTOK
             * must be a NUL-terminated string so pam_gnome_keyring `use_authtok`
             * can unlock the login keyring. */
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
                           "face matched but pam_set_item(PAM_AUTHTOK) failed for '%s'", user);
                return PAM_AUTH_ERR;
            }
            pam_syslog(pamh, LOG_NOTICE,
                       "face auth (unseal) succeeded for '%s' [%s]; PAM_AUTHTOK set",
                       user, service);
            return PAM_SUCCESS;
        }

        if (n == 0) {
            /* Verify-only: a liveness-gated match with no secret released — the
             * convenience-tier / in-session unlock path. The keyring is already
             * open, so PAM_SUCCESS with no AUTHTOK unlocks the session. */
            linhello_zero_buf(buf, sizeof(buf));
            pam_syslog(pamh, LOG_NOTICE,
                       "face auth (verify, no secret) succeeded for '%s' [%s]",
                       user, service);
            return PAM_SUCCESS;
        }

        /* n < 0: declined this round (no match yet, policy deny, or daemon
         * unreachable). The daemon journal ("Authenticate: ...") carries the
         * precise reason. Retry until the deadline for the non-interactive
         * `wait` stacks; otherwise fall through immediately. */
        linhello_zero_buf(buf, sizeof(buf));
        if (time(NULL) >= deadline) {
            break;
        }
        struct timespec pause = { 0, 400 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }

    pam_syslog(pamh, LOG_NOTICE,
               "face auth declined for '%s' [%s]; deferring to next auth module",
               user, service);
    return PAM_AUTH_ERR;
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

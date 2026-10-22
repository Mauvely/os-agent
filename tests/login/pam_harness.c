/* A real PAM run of pam_mauvely, for tests/login/local.sh, container.sh and e2e.sh.
 *
 *   pam_harness <service> <user> [confdir]
 *
 * Runs pam_authenticate then pam_acct_mgmt for <user> under <service>, from
 * /etc/pam.d or <confdir> (pam_start_confdir). Answers the first hidden prompt
 * with $HARNESS_PASSWORD and the next with $HARNESS_CODE, and prints every
 * message and prompt it is given, then each result, one per line. */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hidden;

static int converse(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
    (void)data;
    struct pam_response *r = calloc((size_t)n, sizeof *r);
    if (!r) return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        const char *answer = NULL;
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            printf("PROMPT %s\n", msg[i]->msg);
            answer = getenv(hidden++ == 0 ? "HARNESS_PASSWORD" : "HARNESS_CODE");
            break;
        case PAM_PROMPT_ECHO_ON:
            printf("ASK %s\n", msg[i]->msg);
            answer = "";
            break;
        case PAM_ERROR_MSG:
            printf("ERROR %s\n", msg[i]->msg);
            break;
        case PAM_TEXT_INFO:
            printf("INFO %s\n", msg[i]->msg);
            break;
        }
        if (answer) r[i].resp = strdup(answer);
    }
    fflush(stdout);
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pam_harness <service> <user> [confdir]\n");
        return 2;
    }
    struct pam_conv conv = { converse, NULL };
    pam_handle_t *pamh = NULL;
    int rc = argc > 3 ? pam_start_confdir(argv[1], argv[2], &conv, argv[3], &pamh)
                      : pam_start(argv[1], argv[2], &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        printf("START %d\n", rc);
        return 1;
    }
    rc = pam_authenticate(pamh, 0);
    printf("AUTH %d %s\n", rc, pam_strerror(pamh, rc));
    if (rc == PAM_SUCCESS) {
        rc = pam_acct_mgmt(pamh, 0);
        printf("ACCOUNT %d %s\n", rc, pam_strerror(pamh, rc));
    }
    pam_end(pamh, rc);
    return 0;
}

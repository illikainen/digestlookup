/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <fcntl.h>
#include <unistd.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_gpg.c" /* For access to static functions. */
#include "dlp_mem.h"
#include "test.h"

struct key {
    char *pub;
    char *priv;
    char *fpr;
};

struct state {
    char *home;
    char *cwd;
    char orig_cwd[PATH_MAX];
    struct key ed25519;
    struct key rsa1024;
    struct key rsa4096;
    struct dlp_gpg *gpg;
};

static void setup(gpointer data, gconstpointer user_data)
{
    rsize_t keys;
    struct state *s = data;

    (void)user_data;

    s->ed25519.pub = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                           "ed25519-pub.asc", NULL);
    s->ed25519.priv = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                            "ed25519-priv.asc", NULL);
    s->ed25519.fpr = "16812C729C8F80F7FEFD9231E858A2F4FE99BA3C";

    s->rsa1024.pub = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                           "rsa1024-pub.asc", NULL);
    s->rsa1024.priv = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                            "rsa1024-priv.asc", NULL);
    s->rsa1024.fpr = "9FCF7211645F2B9E64C2E29A38ADE68BD7F8BB66";

    s->rsa4096.pub = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                           "rsa4096-pub.asc", NULL);
    s->rsa4096.priv = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                            "rsa4096-priv.asc", NULL);
    s->rsa4096.fpr = "B587A6D2BFA79A6C4CF15E2A1E9CAFDAAB6E5735";

    g_assert_true(test_setup_home(&s->home));
    g_assert_true(getcwd(s->orig_cwd, sizeof(s->orig_cwd)) != NULL);
    g_assert_nonnull((s->cwd = g_strdup(g_getenv("DLP_TEST_HOME"))));
    g_assert_true(chdir(s->cwd) == 0);

    g_assert_true(dlp_gpg_global_init(NULL));
    g_assert_true(dlp_gpg_init(&s->gpg, NULL));
    g_assert_true(dlp_gpg_check_keyring(s->gpg, &keys, NULL));
    g_assert_true(keys == 0);
}

static void teardown(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(chdir(s->orig_cwd) == 0);
    g_assert_true(dlp_gpg_free(&s->gpg, NULL));
    g_assert_true(dlp_fs_rmdir(s->cwd, NULL));

    dlp_mem_free(&s->cwd);
    dlp_mem_free(&s->home);
    dlp_mem_free(&s->ed25519.pub);
    dlp_mem_free(&s->rsa1024.pub);
    dlp_mem_free(&s->rsa4096.pub);
    dlp_mem_free(&s->ed25519.priv);
    dlp_mem_free(&s->rsa1024.priv);
    dlp_mem_free(&s->rsa4096.priv);
}

static void uids_reset(gpgme_user_id_t uids)
{
    do {
        uids->revoked = 0;
        uids->invalid = 0;
        uids->origin = 0;
        uids->validity = GPGME_VALIDITY_ULTIMATE;
        uids->uid = "foo";
        uids->name = "bar";
        uids->email = "test@example.invalid";
        uids->comment = NULL;
        uids->signatures = NULL;
        uids->address = NULL;
        uids->tofu = NULL;
        uids->last_update = 0;
    } while ((uids = uids->next) != NULL);
}

static void uids_free(gpgme_user_id_t uids)
{
    gpgme_user_id_t uid;

    while (uids != NULL) {
        uid = uids->next;
        dlp_mem_free(&uids);
        uids = uid;
    }
}

static void subkeys_reset(gpgme_subkey_t subkeys)
{
    do {
        subkeys->revoked = 0;
        subkeys->expired = 0;
        subkeys->disabled = 0;
        subkeys->invalid = 0;
        subkeys->can_encrypt = 0;
        subkeys->can_sign = 1;
        subkeys->can_certify = 0;
        subkeys->secret = 0;
        subkeys->can_authenticate = 0;
        subkeys->is_qualified = 0;
        subkeys->is_cardkey = 0;
        subkeys->is_de_vs = 0;
        subkeys->pubkey_algo = GPGME_PK_EDDSA;
        subkeys->length = 256;
        subkeys->keyid = "key id";
        subkeys->fpr = "16812C729C8F80F7FEFD9231E858A2F4FE99BA3C";
        subkeys->timestamp = 0;
        subkeys->expires = 0;
        subkeys->card_number = NULL;
        subkeys->curve = NULL;
        subkeys->keygrip = NULL;
    } while ((subkeys = subkeys->next) != NULL);
}

static void subkeys_free(gpgme_subkey_t subkeys)
{
    gpgme_subkey_t sk;

    while (subkeys != NULL) {
        sk = subkeys->next;
        dlp_mem_free(&subkeys);
        subkeys = sk;
    }
}

static void key_reset(gpgme_key_t key)
{
    if (key == NULL) {
        return;
    }

    key->revoked = 0;
    key->expired = 0;
    key->disabled = 0;
    key->invalid = 0;
    key->can_encrypt = 0;
    key->can_sign = 1;
    key->can_certify = 0;
    key->secret = 0;
    key->can_authenticate = 0;
    key->is_qualified = 0;
    key->origin = 0;
    key->protocol = GPGME_PROTOCOL_OPENPGP;
    key->issuer_serial = NULL;
    key->issuer_name = NULL;
    key->chain_id = NULL;
    key->owner_trust = GPGME_VALIDITY_ULTIMATE;
    key->keylist_mode = GPGME_KEYLIST_MODE_LOCAL;
    key->fpr = "16812C729C8F80F7FEFD9231E858A2F4FE99BA3C";
    key->last_update = 0;

    subkeys_reset(key->subkeys);
    uids_reset(key->uids);
}

static void signatures_reset(gpgme_signature_t sigs)
{
    do {
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sigs->summary = (gpgme_sigsum_t)(GPGME_SIGSUM_GREEN |
                                         GPGME_SIGSUM_VALID);
        sigs->fpr = "16812C729C8F80F7FEFD9231E858A2F4FE99BA3C";
        sigs->status = GPG_ERR_NO_ERROR;
        sigs->timestamp = 0;
        sigs->exp_timestamp = 0;
        sigs->wrong_key_usage = 0;
        sigs->pka_trust = 0;
        sigs->validity = GPGME_VALIDITY_ULTIMATE;
        sigs->validity_reason = GPG_ERR_NO_ERROR;
        sigs->pubkey_algo = GPGME_PK_EDDSA;
        sigs->hash_algo = GPGME_MD_SHA512;

        key_reset(sigs->key);
    } while ((sigs = sigs->next) != NULL);
}

static void signatures_free(gpgme_signature_t sigs)
{
    gpgme_signature_t s;

    while (sigs != NULL) {
        s = sigs->next;
        dlp_mem_free(&sigs);
        sigs = s;
    }
}

static void test_gpg_set_error(gpointer data, gconstpointer user_data)
{
    GError *err = NULL;

    (void)data;
    (void)user_data;

    dlp_gpg_set_error(GPG_ERR_EINVAL, &err);
    g_assert_error(err, DLP_ERROR, GPG_ERR_EINVAL);
    g_clear_error(&err);

    if (getenv("LD_PRELOAD") != NULL) {
        const char *env = "DLP_PRELOAD_GPGME_STRERROR_R_RV";
        g_assert_true(setenv(env, "1", 1) == 0);
        dlp_gpg_set_error(GPG_ERR_EINVAL, &err);
        g_assert_error(err, DLP_ERROR, GPG_ERR_EINVAL);
        g_assert_nonnull(err->message);
        g_assert_cmpuint(strlen(err->message), >, 0);
        g_clear_error(&err);
        g_assert_true(unsetenv(env) == 0);
    }
}

static void test_gpg_check_uids(gpointer data, gconstpointer user_data)
{
    gpgme_user_id_t uids;
    gpgme_user_id_t uid;
    struct state *s = data;

    (void)user_data;

    uids = dlp_mem_alloc(sizeof(*uids));
    uids->next = dlp_mem_alloc(sizeof(*uids));
    uids->next->next = dlp_mem_alloc(sizeof(*uids));

    /*
     * Good.
     */
    uids_reset(uids);
    g_assert_true(dlp_gpg_check_uids(s->gpg, uids, NULL));

    /*
     * Bad arguments.
     */
    g_assert_false(dlp_gpg_check_uids(NULL, uids, NULL));
    g_assert_false(dlp_gpg_check_uids(s->gpg, NULL, NULL));

    for (uid = uids; uid != NULL; uid = uid->next) {
        /*
         * Revoked.
         */
        uids_reset(uids);
        uid->revoked = 1;
        g_assert_false(dlp_gpg_check_uids(s->gpg, uids, NULL));

        /*
         * Invalid.
         */
        uids_reset(uids);
        uid->invalid = 1;
        g_assert_false(dlp_gpg_check_uids(s->gpg, uids, NULL));

        /*
         * Bad validity.
         */
        uids_reset(uids);
        uid->validity = GPGME_VALIDITY_UNDEFINED;
        g_assert_false(dlp_gpg_check_uids(s->gpg, uids, NULL));

        /* cppcheck-suppress redundantAssignment */
        uid->validity = GPGME_VALIDITY_UNKNOWN;
        g_assert_false(dlp_gpg_check_uids(s->gpg, uids, NULL));
    }

    uids_free(uids);
}

static void test_gpg_check_subkeys(gpointer data, gconstpointer user_data)
{
    gpgme_subkey_t subkeys;
    gpgme_subkey_t sk;
    struct state *s = data;

    (void)user_data;

    subkeys = dlp_mem_alloc(sizeof(*subkeys));
    subkeys->next = dlp_mem_alloc(sizeof(*subkeys));
    subkeys->next->next = dlp_mem_alloc(sizeof(*subkeys));

    /*
     * Good.
     */
    subkeys_reset(subkeys);
    g_assert_true(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

    /*
     * Bad arguments.
     */
    g_assert_false(dlp_gpg_check_subkeys(NULL, subkeys, NULL));
    g_assert_false(dlp_gpg_check_subkeys(s->gpg, NULL, NULL));

    for (sk = subkeys; sk != NULL; sk = sk->next) {
        /*
         * Revoked.
         */
        subkeys_reset(subkeys);
        sk->revoked = 1;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Expired.
         */
        subkeys_reset(subkeys);
        sk->expired = 1;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Disabled.
         */
        subkeys_reset(subkeys);
        sk->disabled = 1;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Invalid.
         */
        subkeys_reset(subkeys);
        sk->invalid = 1;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Bad pk algo.
         */
        subkeys_reset(subkeys);
        sk->pubkey_algo = GPGME_PK_DSA;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Bad pk length.
         */
        subkeys_reset(subkeys);
        /* cppcheck-suppress redundantAssignment */
        sk->pubkey_algo = GPGME_PK_RSA;
        sk->length = 1024;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        subkeys_reset(subkeys);
        sk->pubkey_algo = GPGME_PK_EDDSA;
        sk->length = 128;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Bad fingerprint.
         */
        subkeys_reset(subkeys);
        sk->fpr = NULL;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));

        /*
         * Bad creation timestamp.
         */
        subkeys_reset(subkeys);
        sk->timestamp = -1;
        g_assert_false(dlp_gpg_check_subkeys(s->gpg, subkeys, NULL));
    }

    subkeys_free(subkeys);
}

static void test_gpg_check_key(gpointer data, gconstpointer user_data)
{
    gpgme_key_t key;
    gpgme_subkey_t subkey;
    gpgme_user_id_t uid;
    struct state *s = data;

    (void)user_data;

    key = dlp_mem_alloc(sizeof(*key));

    subkey = dlp_mem_alloc(sizeof(*subkey));
    subkeys_reset(subkey);
    key->subkeys = subkey;

    uid = dlp_mem_alloc(sizeof(*uid));
    uids_reset(uid);
    key->uids = uid;

    /*
     * Good.
     */
    key_reset(key);
    g_assert_true(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Bad arguments.
     */
    g_assert_false(dlp_gpg_check_key(NULL, key, NULL));
    g_assert_false(dlp_gpg_check_key(s->gpg, NULL, NULL));

    /*
     * Revoked.
     */
    key_reset(key);
    key->revoked = 1;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Expired.
     */
    key_reset(key);
    key->expired = 1;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Disabled.
     */
    key_reset(key);
    key->disabled = 1;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Invalid.
     */
    key_reset(key);
    key->invalid = 1;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Bad protocol.
     */
    key_reset(key);
    key->protocol = GPGME_PROTOCOL_UNKNOWN;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Bad owner trust.
     */
    key_reset(key);
    key->owner_trust = GPGME_VALIDITY_NEVER;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Bad keylist mode.
     */
    key_reset(key);
    key->keylist_mode = GPGME_KEYLIST_MODE_EXTERN;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Bad fingerprint.
     */
    key_reset(key);
    key->fpr = NULL;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Missing uids.
     */
    key_reset(key);
    key->uids = NULL;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));
    key->uids = uid;

    /*
     * Missing subkeys.
     */
    key_reset(key);
    key->subkeys = NULL;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));
    key->subkeys = subkey;

    /*
     * Bad uids.
     */
    key_reset(key);
    uid->revoked = 1;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    /*
     * Bad subkeys.
     */
    key_reset(key);
    subkey->pubkey_algo = GPGME_PK_DSA;
    g_assert_false(dlp_gpg_check_key(s->gpg, key, NULL));

    dlp_mem_free(&subkey);
    dlp_mem_free(&uid);
    dlp_mem_free(&key);
}

static void test_gpg_check_signatures(gpointer data, gconstpointer user_data)
{
    gpgme_signature_t sigs;
    gpgme_signature_t sig;
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    GError *err = NULL;
    struct state *s = data;

    (void)user_data;

    sigs = dlp_mem_alloc(sizeof(*sigs));
    sigs->next = dlp_mem_alloc(sizeof(*sigs));
    sigs->next->next = dlp_mem_alloc(sizeof(*sigs));

    g_assert_true(dlp_gpg_import_key(s->gpg, s->ed25519.pub, trust, &err));

    /*
     * Good.
     */
    signatures_reset(sigs);
    g_assert_true(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

    /*
     * Bad arguments.
     */
    g_assert_false(dlp_gpg_check_signatures(NULL, sigs, NULL));
    g_assert_false(dlp_gpg_check_signatures(s->gpg, NULL, NULL));

    for (sig = sigs; sig != NULL; sig = sig->next) {
        /*
         * Bad summary.
         */
        signatures_reset(sigs);
        sig->summary = (gpgme_sigsum_t)0;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sig->summary = GPGME_SIGSUM_VALID;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sig->summary = GPGME_SIGSUM_GREEN;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sig->summary = GPGME_SIGSUM_KEY_EXPIRED;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sig->summary = (gpgme_sigsum_t)(GPGME_SIGSUM_VALID |
                                        GPGME_SIGSUM_GREEN | GPGME_SIGSUM_RED);
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Missing fingerprint.
         */
        signatures_reset(sigs);
        sig->fpr = NULL;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Bad fingerprint.
         */
        signatures_reset(sigs);
        sig->fpr = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Bad validity.
         */
        signatures_reset(sigs);
        sig->validity = GPGME_VALIDITY_UNDEFINED;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /* cppcheck-suppress redundantAssignment */
        sig->validity = GPGME_VALIDITY_UNKNOWN;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Bad validity reason.
         */
        signatures_reset(sigs);
        sig->validity_reason = GPG_ERR_GENERAL;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Bad key usage.
         */
        signatures_reset(sigs);
        sig->wrong_key_usage = 1;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Bad pk algo.
         */
        signatures_reset(sigs);
        sig->pubkey_algo = GPGME_PK_DSA;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));

        /*
         * Bad hash algo.
         */
        signatures_reset(sigs);
        sig->hash_algo = GPGME_MD_SHA1;
        g_assert_false(dlp_gpg_check_signatures(s->gpg, sigs, NULL));
    }

    signatures_free(sigs);
}

static void test_gpg_data_from_fd(gpointer data, gconstpointer user_data)
{
    gpgme_data_t d;
    int fd;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    g_assert_true(dlp_gpg_data_from_fd(fd, &d, &err));
    g_assert_no_error(err);
    dlp_gpg_data_release(&d);

    if (getenv("LD_PRELOAD") != NULL) {
        const char *env = "DLP_PRELOAD_GPGME_DATA_NEW_FROM_FD_RV";
        g_assert_true(setenv(env, "2", 1) == 0);
        g_assert_false(dlp_gpg_data_from_fd(fd, &d, &err));
        g_assert_error(err, DLP_ERROR, 2);
        g_clear_error(&err);
        g_assert_true(unsetenv(env) == 0);
    }

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_gpg_change_owner_trust(gpointer data, gconstpointer user_data)
{
    int fd;
    char *exec;
    GError *err = NULL;
    gpgme_validity_t t = GPGME_VALIDITY_ULTIMATE;
    struct dlp_gpg *gpg = NULL;
    struct state *s = data;

    (void)user_data;

    g_assert_true(dlp_gpg_init(&gpg, NULL));
    g_assert_true(dlp_gpg_import_key(gpg, s->ed25519.pub, t, &err));

    /*
     * Bad fingerprint.
     */
    g_assert_false(dlp_gpg_change_owner_trust(gpg, "bad-fpr", t, &err));
    g_assert_error(err, G_SPAWN_EXIT_ERROR, 2);
    g_clear_error(&err);

    /*
     * Missing executable.
     */
    exec = g_build_filename(gpg->home, "missing", NULL);
    g_assert_cmpint(gpgme_ctx_set_engine_info(gpg->ctx, GPGME_PROTOCOL_OPENPGP,
                                              exec, gpg->home),
                    ==, 0);
    g_assert_false(dlp_gpg_change_owner_trust(gpg, s->ed25519.fpr, t, &err));
    g_assert_error(err, DLP_ERROR, GPG_ERR_ENOEXEC);
    g_clear_error(&err);
    dlp_mem_free(&exec);

    /*
     * Bad permissions.
     */
    exec = g_build_filename(gpg->home, "bad-perm", NULL);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_true(dlp_fs_open(exec, O_CREAT | O_RDWR, S_IRWXU, &fd, NULL));
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_cmpint(fchmod(fd, S_IRWXU | S_IWGRP), ==, 0);
    g_assert_true(dlp_fs_close(&fd, NULL));
    g_assert_cmpint(gpgme_ctx_set_engine_info(gpg->ctx, GPGME_PROTOCOL_OPENPGP,
                                              exec, gpg->home),
                    ==, 0);
    g_assert_false(dlp_gpg_change_owner_trust(gpg, s->ed25519.fpr, t, &err));
    g_assert_error(err, DLP_ERROR, EBADFD);
    g_clear_error(&err);
    dlp_mem_free(&exec);

    g_assert_true(dlp_gpg_free(&gpg, NULL));

    /*
     * Mocks.
     */
    if (getenv("LD_PRELOAD") != NULL) {
        /*
         * Bad protocol.
         */
        const char *env = "DLP_PRELOAD_GPGME_GET_PROTOCOL_RV";
        g_assert_true(setenv(env, "123456", 1) == 0);
        g_assert_false(
        dlp_gpg_change_owner_trust(s->gpg, s->ed25519.fpr, t, &err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_UNSUPPORTED_PROTOCOL);
        g_assert_true(unsetenv(env) == 0);
    }
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/gpg/set-error", sizeof(struct state), NULL, setup,
                      test_gpg_set_error, teardown);
    g_test_add_vtable("/gpg/data/fd", sizeof(struct state), NULL, setup,
                      test_gpg_data_from_fd, teardown);
    g_test_add_vtable("/gpg/change-owner-trust", sizeof(struct state), NULL,
                      setup, test_gpg_change_owner_trust, teardown);
    g_test_add_vtable("/gpg/check/uids", sizeof(struct state), NULL, setup,
                      test_gpg_check_uids, teardown);
    g_test_add_vtable("/gpg/check/subkeys", sizeof(struct state), NULL, setup,
                      test_gpg_check_subkeys, teardown);
    g_test_add_vtable("/gpg/check/key", sizeof(struct state), NULL, setup,
                      test_gpg_check_key, teardown);
    g_test_add_vtable("/gpg/check/signatures", sizeof(struct state), NULL,
                      setup, test_gpg_check_signatures, teardown);

    return g_test_run();
}

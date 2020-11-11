/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_gpg.h"
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

static bool read_all(int fd, char **buf)
{
    char tmp[MIN(MIN(SSIZE_MAX, G_MAXSSIZE), 4096)];
    GString *str;
    ssize_t rv;

    str = g_string_new(NULL);
    while ((errno = 0) == 0 && (rv = read(fd, tmp, sizeof(tmp))) != 0) {
        if (rv > 0) {
            g_string_append_len(str, tmp, rv);
        } else if (rv == -1 && errno != EINTR) {
            g_string_free(str, true);
            return false;
        }
    }

    *buf = g_string_free(str, false);
    return true;
}

static void test_gpg_global_init(gpointer data, gconstpointer user_data)
{
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_gpg_global_init(&err));
    g_assert_no_error(err);

    if (getenv("LD_PRELOAD") != NULL) {
        const char *env;

        env = "DLP_PRELOAD_GPGME_CHECK_VERSION_INTERNAL_RV";
        g_assert_true(setenv(env, "1", 1) == 0);
        g_assert_false(dlp_gpg_global_init(&err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_NOT_INITIALIZED);
        g_clear_error(&err);
        g_assert_true(unsetenv(env) == 0);

        env = "DLP_PRELOAD_GPGME_ENGINE_CHECK_VERSION_RV";
        g_assert_true(setenv(env, "123", 1) == 0);
        g_assert_false(dlp_gpg_global_init(&err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);
        g_assert_true(unsetenv(env) == 0);
    }
}

static void test_gpg_import_key(gpointer data, gconstpointer user_data)
{
    struct state *s = data;
    rsize_t keys;
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    GError *err = NULL;

    (void)user_data;

    /*
     * Missing file.
     */
    g_assert_false(dlp_gpg_import_key(s->gpg, "missing-key", trust, &err));
    g_assert_error(err, DLP_ERROR, ENOENT);
    g_clear_error(&err);
    g_assert_true(dlp_gpg_check_keyring(s->gpg, &keys, NULL));
    g_assert_true(keys == 0);

    /*
     * Import ed25519 pubkey.
     */
    g_assert_true(dlp_gpg_import_key(s->gpg, s->ed25519.pub, trust, &err));
    g_assert_no_error(err);
    g_assert_true(dlp_gpg_check_keyring(s->gpg, &keys, NULL));
    g_assert_true(keys == 1);

    /*
     * Import rsa4096 pubkey with bad validity.
     */
    g_assert_false(dlp_gpg_import_key(s->gpg, s->rsa4096.pub, 0, &err));
    g_assert_error(err, DLP_ERROR, GPG_ERR_EINVAL);
}

static void test_gpg_check_keyring(gpointer data, gconstpointer user_data)
{
    size_t count = 123;
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    GError *err = NULL;
    struct state *s = data;

    (void)user_data;

    /*
     * Good keyring.
     */
    g_assert_true(dlp_gpg_check_keyring(s->gpg, &count, &err));
    g_assert_no_error(err);
    g_assert_cmpint(count, ==, 0);

    g_assert_true(dlp_gpg_import_key(s->gpg, s->ed25519.pub, trust, NULL));
    g_assert_true(dlp_gpg_check_keyring(s->gpg, &count, &err));
    g_assert_no_error(err);
    g_assert_cmpint(count, ==, 1);

    g_assert_true(dlp_gpg_import_key(s->gpg, s->rsa4096.pub, trust, NULL));
    g_assert_true(dlp_gpg_check_keyring(s->gpg, &count, &err));
    g_assert_no_error(err);
    g_assert_cmpint(count, ==, 2);

    /*
     * Invalid key length.
     */
    g_assert_true(dlp_gpg_import_key(s->gpg, s->rsa1024.pub, trust, NULL));
    g_assert_false(dlp_gpg_check_keyring(s->gpg, &count, &err));
    g_assert_error(err, DLP_ERROR, GPG_ERR_INV_KEYLEN);
    g_clear_error(&err);
    g_assert_cmpint(count, ==, 0);
}

static void test_gpg_verify_attached(gpointer data, gconstpointer user_data)
{
    size_t i;
    int msgfd;
    int outfd;
    const char *msg;
    char *content;
    struct verify {
        const char *msg;
        const char *content;
        int err;
    } verify[] = {
        { .msg = "data-clearsign-ed25519.txt.asc",
          .content = "ed25519 clearsign\n",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-clearsign-ed25519-leading-header.txt.asc",
          .content = "ed25519 clearsign\n",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-clearsign-ed25519-trailing-footer.txt.asc",
          .content = "ed25519 clearsign\n",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-clearsign-ed25519-both.txt.asc",
          .content = "ed25519 clearsign\n",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-clearsign-rsa1024.txt.asc",
          .content = "rsa1024 clearsign\n",
          .err = GPG_ERR_INV_KEYLEN },
        { .msg = "data-clearsign-rsa4096.txt.asc",
          .content = "rsa4096 clearsign\n",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-clearsign-rsa4096-bad.txt.asc",
          .content = "rsa4096 clearsign\n",
          .err = GPG_ERR_BAD_SIGNATURE },
        { .msg = "data-inline-ed25519.txt.asc",
          .content = "ed25519 inline\n",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-inline-rsa1024.txt.asc",
          .content = "rsa1024 inline\n",
          .err = GPG_ERR_INV_KEYLEN },
        { .msg = "data-inline-rsa4096.txt.asc",
          .content = "rsa4096 inline\n",
          .err = GPG_ERR_NO_ERROR },
    };
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    GError *err = NULL;
    struct state *s = data;

    (void)user_data;

    /*
     * Verify without public key.
     */
    for (i = 0; i < G_N_ELEMENTS(verify); i++) {
        msg = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                                  verify[i].msg, NULL);
        g_assert_true(dlp_fs_open(msg, O_RDONLY, S_IRUSR, &msgfd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, &err));

        g_assert_false(dlp_gpg_verify_attached(s->gpg, msgfd, outfd, &err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_NO_PUBKEY);
        g_clear_error(&err);

        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_true(dlp_fs_close(&msgfd, NULL));
    }

    /*
     * Import keys.
     */
    g_assert_true(dlp_gpg_import_key(s->gpg, s->ed25519.pub, trust, NULL));
    g_assert_true(dlp_gpg_import_key(s->gpg, s->rsa1024.pub, trust, NULL));
    g_assert_true(dlp_gpg_import_key(s->gpg, s->rsa4096.pub, trust, NULL));

    /*
     * Verify with public key.
     */
    for (i = 0; i < G_N_ELEMENTS(verify); i++) {
        msg = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                                  verify[i].msg, NULL);
        g_assert_true(dlp_fs_open(msg, O_RDONLY, S_IRUSR, &msgfd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, &err));

        if (verify[i].err == GPG_ERR_NO_ERROR) {
            g_assert_true(dlp_gpg_verify_attached(s->gpg, msgfd, outfd, &err));
            g_assert_no_error(err);
            g_assert_true(read_all(outfd, &content));
            g_assert_cmpstr(verify[i].content, ==, content);
            dlp_mem_free(&content);
        } else {
            g_assert_false(dlp_gpg_verify_attached(s->gpg, msgfd, outfd, &err));
            g_assert_error(err, DLP_ERROR, verify[i].err);
            g_clear_error(&err);
        }

        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_true(dlp_fs_close(&msgfd, NULL));
    }
}

static void test_gpg_verify_detached(gpointer data, gconstpointer user_data)
{
    size_t i;
    int msgfd;
    int sigfd;
    const char *msg;
    const char *sig;
    struct verify {
        const char *msg;
        const char *sig;
        int err;
    } verify[] = {
        { .msg = "data-detach-ed25519.txt",
          .sig = "data-detach-ed25519.txt.asc",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-detach-rsa1024.txt",
          .sig = "data-detach-rsa1024.txt.asc",
          .err = GPG_ERR_INV_KEYLEN },
        { .msg = "data-detach-rsa4096.txt",
          .sig = "data-detach-rsa4096.txt.asc",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-detach-ed25519-rsa4096.txt",
          .sig = "data-detach-ed25519-rsa4096.txt.asc",
          .err = GPG_ERR_NO_ERROR },
        { .msg = "data-detach-rsa4096.txt",
          .sig = "data-detach-ed25519.txt.asc",
          .err = GPG_ERR_BAD_SIGNATURE },
        { .msg = "data-detach-ed25519-rsa1024.txt",
          .sig = "data-detach-ed25519-rsa1024.txt.asc",
          .err = GPG_ERR_INV_KEYLEN },
    };
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    GError *err = NULL;
    struct state *s = data;

    (void)user_data;

    /*
     * Verify without public key.
     */
    for (i = 0; i < G_N_ELEMENTS(verify); i++) {
        msg = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                                  verify[i].msg, NULL);
        sig = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                                  verify[i].sig, NULL);
        g_assert_true(dlp_fs_open(msg, O_RDONLY, S_IRUSR, &msgfd, NULL));
        g_assert_true(dlp_fs_open(sig, O_RDONLY, S_IRUSR, &sigfd, NULL));

        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, &err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_NO_PUBKEY);
        g_clear_error(&err);

        g_assert_true(dlp_fs_close(&msgfd, NULL));
        g_assert_true(dlp_fs_close(&sigfd, NULL));
    }

    /*
     * Import keys.
     */
    g_assert_true(dlp_gpg_import_key(s->gpg, s->ed25519.pub, trust, NULL));
    g_assert_true(dlp_gpg_import_key(s->gpg, s->rsa1024.pub, trust, NULL));
    g_assert_true(dlp_gpg_import_key(s->gpg, s->rsa4096.pub, trust, NULL));

    /*
     * Verify with public key.
     */
    for (i = 0; i < G_N_ELEMENTS(verify); i++) {
        msg = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                                  verify[i].msg, NULL);
        sig = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                                  verify[i].sig, NULL);
        g_assert_true(dlp_fs_open(msg, O_RDONLY, S_IRUSR, &msgfd, NULL));
        g_assert_true(dlp_fs_open(sig, O_RDONLY, S_IRUSR, &sigfd, NULL));

        if (verify[i].err == GPG_ERR_NO_ERROR) {
            g_assert_true(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, &err));
            g_assert_no_error(err);
        } else {
            g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, &err));
            g_assert_error(err, DLP_ERROR, verify[i].err);
            g_clear_error(&err);
        }

        g_assert_true(dlp_fs_close(&sigfd, NULL));
        g_assert_true(dlp_fs_close(&msgfd, NULL));
    }
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/gpg/global-init", sizeof(struct state), NULL, setup,
                      test_gpg_global_init, teardown);
    g_test_add_vtable("/gpg/import-key", sizeof(struct state), NULL, setup,
                      test_gpg_import_key, teardown);
    g_test_add_vtable("/gpg/check/keyring", sizeof(struct state), NULL, setup,
                      test_gpg_check_keyring, teardown);
    g_test_add_vtable("/gpg/verify/attached", sizeof(struct state), NULL, setup,
                      test_gpg_verify_attached, teardown);
    g_test_add_vtable("/gpg/verify/detached", sizeof(struct state), NULL, setup,
                      test_gpg_verify_detached, teardown);

    return g_test_run();
}

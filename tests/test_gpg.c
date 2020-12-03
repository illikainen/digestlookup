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
    key->_refs = 123;

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

static void test_gpg_global_init(gpointer data, gconstpointer user_data)
{
    gpgme_error_t rv;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_gpg_global_init(&err));
    g_assert_no_error(err);

    if (test_wrap_p()) {
        test_wrap_push(gpgme_check_version_internal, true, NULL);
        g_assert_false(dlp_gpg_global_init(&err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_NOT_INITIALIZED);
        g_clear_error(&err);

        rv = 123;
        test_wrap_push(gpgme_engine_check_version, true, &rv);
        g_assert_false(dlp_gpg_global_init(&err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);
    }
}

static void test_gpg_init(gpointer data, gconstpointer user_data)
{
    errno_t e;
    gpgme_error_t gerr;
    struct dlp_gpg *gpg = NULL;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    if (test_wrap_p()) {
        /*
         * mkdtemp() failure
         */
        e = EACCES;
        test_wrap_push(mkdtemp, true, &e);
        g_assert_false(dlp_gpg_init(&gpg, &err));
        g_assert_error(err, DLP_ERROR, e);
        g_clear_error(&err);

        /*
         * gpgme_new() failure
         */
        gerr = GPG_ERR_NOT_INITIALIZED;
        test_wrap_push(gpgme_new, true, &gerr);
        g_assert_false(dlp_gpg_init(&gpg, &err));
        g_assert_nonnull(err);
        g_clear_error(&err);
    }
}

static void test_gpg_set_error(gpointer data, gconstpointer user_data)
{
    int rv;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    if (test_wrap_p()) {
        rv = 1;
        test_wrap_push(gpgme_strerror_r, true, &rv);
        test_wrap_push(gpgme_check_version_internal, true, NULL);
        g_assert_false(dlp_gpg_global_init(&err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_NOT_INITIALIZED);
        g_assert_nonnull(err->message);
        g_assert_cmpuint(strlen(err->message), >, 0);
        g_clear_error(&err);
    }
}

static void test_gpg_import_key(gpointer data, gconstpointer user_data)
{
    struct state *s = data;
    rsize_t keys;
    int fd;
    char *path;
    gpgme_error_t e;
    gpgme_protocol_t proto;
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    struct _gpgme_import_status status = { 0 };
    struct _gpgme_op_import_result result = { .imports = &status };
    struct _gpgme_engine_info info1 = { 0 };
    struct _gpgme_engine_info info2 = { 0 };
    struct dlp_gpg *gpg = NULL;
    GError *err = NULL;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    int flags = O_CREAT | O_RDWR;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    mode_t mode = S_IRWXU;

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
     * Bogus key.
     */
    path = g_build_filename(s->home, "bogus-key", NULL);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_true(dlp_fs_open(path, O_CREAT | O_RDWR, S_IRUSR, &fd, NULL));
    g_assert_true(write(fd, "foobar", 6) == 6);
    g_assert_true(dlp_fs_close(&fd, NULL));
    g_assert_false(dlp_gpg_import_key(s->gpg, path, trust, &err));
    g_assert_nonnull(err);
    g_clear_error(&err);
    dlp_mem_free(&path);

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
    g_clear_error(&err);

    /*
     * Import from resource.
     */
    g_assert_true(dlp_gpg_import_key(s->gpg,
                                     "resource:///dlp/keys/debian/"
                                     "buster-automatic.asc",
                                     trust, &err));
    g_assert_no_error(err);

    /*
     * Import from missing resource.
     */
    g_assert_false(dlp_gpg_import_key(s->gpg, "resource:///foo", trust, &err));
    g_assert_error(err, G_RESOURCE_ERROR, G_RESOURCE_ERROR_NOT_FOUND);
    g_clear_error(&err);

    if (test_wrap_p()) {
        /* gpgme_data_new_from_fd() failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        e = 123;
        test_wrap_push(gpgme_data_new_from_fd, true, &e);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_data_new_from_mem() failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        e = 123;
        test_wrap_push(gpgme_data_new_from_mem, true, &e);
        g_assert_false(dlp_gpg_import_key(gpg,
                                          "resource:///dlp/keys/debian/"
                                          "buster-automatic.asc",
                                          trust, &err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_op_import failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        e = 123;
        test_wrap_push(gpgme_op_import, true, &e);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_op_import_result failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));

        test_wrap_push(gpgme_op_import_result, true, NULL);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_nonnull(err);
        g_clear_error(&err);

        result.imported = 1;
        status.result = 123;
        test_wrap_push(gpgme_op_import_result, true, &result);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);

        /* cppcheck-suppress redundantAssignment */
        status.result = GPG_ERR_NO_ERROR;
        status.fpr = NULL;
        test_wrap_push(gpgme_op_import_result, true, &result);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_nonnull(err);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_get_protocol() failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        proto = GPGME_PROTOCOL_UNKNOWN;
        test_wrap_push(gpgme_get_protocol, true, &proto);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_UNSUPPORTED_PROTOCOL);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_ctx_get_engine_info() empty list */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        test_wrap_push(gpgme_ctx_get_engine_info, true, NULL);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_ENOEXEC);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_ctx_get_engine_info() bad executable */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        info1.protocol = GPGME_PROTOCOL_OPENPGP;
        test_wrap_push(gpgme_ctx_get_engine_info, true, &info1);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, GPG_ERR_ENOEXEC);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* gpgme_ctx_get_engine_info() bad permission */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        g_assert_true(dlp_fs_open("exec", flags, mode, &fd, NULL));
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        g_assert_true(fchmod(fd, S_IRWXU | S_IWGRP) == 0);
        info1.protocol = GPGME_PROTOCOL_CMS;
        info1.next = &info2;
        info2.protocol = GPGME_PROTOCOL_OPENPGP;
        info2.file_name = "exec";
        test_wrap_push(gpgme_ctx_get_engine_info, true, &info1);
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_error(err, DLP_ERROR, EBADFD);
        g_clear_error(&err);
        g_assert_true(dlp_fs_close(&fd, NULL));
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* g_subprocess_communicate_utf8() failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        test_wrap_push(g_subprocess_communicate_utf8, true, "foo");
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_nonnull(err);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));

        /* g_subprocess_wait_check() failure */
        g_assert_true(dlp_gpg_init(&gpg, NULL));
        test_wrap_push(g_subprocess_wait_check, true, "foo");
        g_assert_false(dlp_gpg_import_key(gpg, s->rsa4096.pub, trust, &err));
        g_assert_nonnull(err);
        g_clear_error(&err);
        g_assert_true(dlp_gpg_free(&gpg, NULL));
    }
}

static void test_gpg_import_keys(gpointer data, gconstpointer user_data)
{
    GPtrArray *arr;
    char *missing_path;
    char *bogus_path;
    rsize_t keys;
    bool rv;
    struct dlp_gpg *gpg = NULL;
    GError *err = NULL;
    struct state *s = data;

    (void)user_data;

    /*
     * Create missing file path.
     */
    missing_path = g_build_filename(s->home, "missing-key", NULL);

    /*
     * Create bogus key.
     */
    bogus_path = g_build_filename(s->home, "bogus-key", NULL);
    g_assert_true(g_file_set_contents(bogus_path, "foobar", -1, NULL));

    /*
     * Import with one missing key.
     */
    g_assert_true(dlp_gpg_init(&gpg, NULL));
    arr = g_ptr_array_new();
    g_ptr_array_add(arr, s->ed25519.pub);
    g_ptr_array_add(arr, missing_path);
    rv = dlp_gpg_import_keys(gpg, arr, GPGME_VALIDITY_ULTIMATE, &err);
    g_assert_error(err, DLP_ERROR, ENOENT);
    g_assert_false(rv);
    g_clear_error(&err);
    g_ptr_array_unref(arr);
    g_assert_true(dlp_gpg_free(&gpg, NULL));

    /*
     * Import with one bogus key.
     */
    g_assert_true(dlp_gpg_init(&gpg, NULL));
    arr = g_ptr_array_new();
    g_ptr_array_add(arr, s->ed25519.pub);
    g_ptr_array_add(arr, bogus_path);
    rv = dlp_gpg_import_keys(gpg, arr, GPGME_VALIDITY_ULTIMATE, &err);
    g_assert_error(err, DLP_ERROR, GPG_ERR_BAD_KEY);
    g_assert_false(rv);
    g_clear_error(&err);
    g_ptr_array_unref(arr);
    g_assert_true(dlp_gpg_free(&gpg, NULL));

    /*
     * Import with one good key.
     */
    g_assert_true(dlp_gpg_init(&gpg, NULL));
    arr = g_ptr_array_new();
    g_ptr_array_add(arr, s->ed25519.pub);
    rv = dlp_gpg_import_keys(gpg, arr, GPGME_VALIDITY_ULTIMATE, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_gpg_check_keyring(gpg, &keys, NULL));
    g_assert_cmpuint(keys, ==, 1);
    g_ptr_array_unref(arr);
    g_assert_true(dlp_gpg_free(&gpg, NULL));

    /*
     * Import with multiple good keys.
     */
    g_assert_true(dlp_gpg_init(&gpg, NULL));
    arr = g_ptr_array_new();
    g_ptr_array_add(arr, s->ed25519.pub);
    g_ptr_array_add(arr, s->rsa4096.pub);
    rv = dlp_gpg_import_keys(gpg, arr, GPGME_VALIDITY_ULTIMATE, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_gpg_check_keyring(gpg, &keys, NULL));
    g_assert_cmpuint(keys, ==, 2);
    g_ptr_array_unref(arr);
    g_assert_true(dlp_gpg_free(&gpg, NULL));

    dlp_mem_free(&missing_path);
    dlp_mem_free(&bogus_path);
}

static void test_gpg_check_keyring(gpointer data, gconstpointer user_data)
{
    size_t count = 123;
    gpgme_error_t e;
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

    if (test_wrap_p()) {
        /*
         * gpgme_op_keylist_start() failure
         */
        e = 123;
        test_wrap_push(gpgme_op_keylist_start, true, &e);
        g_assert_false(dlp_gpg_check_keyring(s->gpg, &count, &err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);
        g_assert_cmpint(count, ==, 0);

        /*
         * gpgme_op_keylist_next() failure
         */
        e = 456;
        test_wrap_push(gpgme_op_keylist_next, true, &e);
        g_assert_false(dlp_gpg_check_keyring(s->gpg, &count, &err));
        g_assert_error(err, DLP_ERROR, 456);
        g_clear_error(&err);
        g_assert_cmpint(count, ==, 0);
    }
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

static void test_gpg_verify_mock(gpointer data, gconstpointer user_data)
{
    int msgfd;
    int sigfd;
    const char *msg;
    const char *sig;
    gpgme_error_t e;
    struct _gpgme_user_id uids = { 0 };
    struct _gpgme_subkey subkeys = { 0 };
    struct _gpgme_key key = { .uids = &uids, .subkeys = &subkeys };
    struct _gpgme_signature sigs = { 0 };
    struct _gpgme_op_verify_result result = { .signatures = &sigs };
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    struct state *s = data;
    GError *err = NULL;

    (void)user_data;

    g_assert_true(dlp_gpg_import_key(s->gpg, s->ed25519.pub, trust, NULL));
    msg = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                              "data-detach-ed25519.txt", NULL);
    sig = g_test_get_filename(G_TEST_DIST, "tests", "data", "gpg",
                              "data-detach-ed25519.txt.asc", NULL);
    g_assert_true(dlp_fs_open(msg, O_RDONLY, S_IRUSR, &msgfd, NULL));
    g_assert_true(dlp_fs_open(sig, O_RDONLY, S_IRUSR, &sigfd, NULL));

    if (test_wrap_p()) {
        /*
         * Good.
         */
        g_assert_true(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * gpgme_op_verify() failure
         */
        e = 123;
        test_wrap_push(gpgme_op_verify, true, &e);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, &err));
        g_assert_error(err, DLP_ERROR, 123);
        g_clear_error(&err);

        /*
         * gpgme_op_verify_result() failure
         */
        test_wrap_push(gpgme_op_verify_result, true, NULL);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad summary.
         */
        signatures_reset(&sigs);

        sigs.summary = (gpgme_sigsum_t)0;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sigs.summary = GPGME_SIGSUM_VALID;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sigs.summary = GPGME_SIGSUM_GREEN;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sigs.summary = GPGME_SIGSUM_KEY_EXPIRED;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /* cppcheck-suppress redundantAssignment */
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        sigs.summary = (gpgme_sigsum_t)(GPGME_SIGSUM_VALID |
                                        GPGME_SIGSUM_GREEN | GPGME_SIGSUM_RED);
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad validity.
         */
        signatures_reset(&sigs);
        sigs.validity = GPGME_VALIDITY_UNDEFINED;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /* cppcheck-suppress redundantAssignment */
        sigs.validity = GPGME_VALIDITY_UNKNOWN;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad validity reason.
         */
        signatures_reset(&sigs);
        sigs.validity_reason = GPG_ERR_GENERAL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Missing fingerprint.
         */
        signatures_reset(&sigs);
        sigs.fpr = NULL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad key usage.
         */
        signatures_reset(&sigs);
        sigs.wrong_key_usage = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad pk algo.
         */
        signatures_reset(&sigs);
        sigs.pubkey_algo = GPGME_PK_DSA;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad md algo.
         */
        signatures_reset(&sigs);
        sigs.hash_algo = GPGME_MD_SHA1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Missing key.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, NULL);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Revoked key.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.revoked = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Expired key.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.expired = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Disabled key.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.disabled = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Invalid key.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.invalid = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad protocol.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.protocol = GPGME_PROTOCOL_UNKNOWN;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad owner trust.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.owner_trust = GPGME_VALIDITY_NEVER;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad keylist mode.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.keylist_mode = GPGME_KEYLIST_MODE_EXTERN;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad fingerprint.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.fpr = NULL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Missing UID(s).
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.uids = NULL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));
        key.uids = &uids;

        /*
         * Missing subkey(s).
         */
        signatures_reset(&sigs);
        key_reset(&key);
        key.subkeys = NULL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));
        key.subkeys = &subkeys;

        /*
         * Revoked subkey.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.revoked = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Expired subkey.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.expired = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Disabled subkey.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.disabled = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Invalid subkey.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.invalid = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Missing subkey fingerprint.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.fpr = NULL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad subkey pk algo.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.pubkey_algo = GPGME_PK_DSA;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad subkey pk length.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        /* cppcheck-suppress redundantAssignment */
        subkeys.pubkey_algo = GPGME_PK_RSA;
        subkeys.length = 1024;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.pubkey_algo = GPGME_PK_EDDSA;
        subkeys.length = 128;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad subkey timestamp.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        subkeys.timestamp = -1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Revoked uid.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        uids.revoked = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Invalid uid.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        uids.invalid = 1;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * Bad uid validity.
         */
        signatures_reset(&sigs);
        key_reset(&key);
        uids.validity = GPGME_VALIDITY_NEVER;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        test_wrap_push(gpgme_get_key, true, &key);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));

        /*
         * gpgme_op_verify_result() no signatures
         */
        result.signatures = NULL;
        test_wrap_push(gpgme_op_verify_result, true, &result);
        g_assert_false(dlp_gpg_verify_detached(s->gpg, msgfd, sigfd, NULL));
    }

    g_assert_true(dlp_fs_close(&sigfd, NULL));
    g_assert_true(dlp_fs_close(&msgfd, NULL));
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/gpg/global-init", sizeof(struct state), NULL, setup,
                      test_gpg_global_init, teardown);
    g_test_add_vtable("/gpg/init", sizeof(struct state), NULL, setup,
                      test_gpg_init, teardown);
    g_test_add_vtable("/gpg/set-error", sizeof(struct state), NULL, setup,
                      test_gpg_set_error, teardown);
    g_test_add_vtable("/gpg/import-key", sizeof(struct state), NULL, setup,
                      test_gpg_import_key, teardown);
    g_test_add_vtable("/gpg/import-keys", sizeof(struct state), NULL, setup,
                      test_gpg_import_keys, teardown);
    g_test_add_vtable("/gpg/check/keyring", sizeof(struct state), NULL, setup,
                      test_gpg_check_keyring, teardown);
    g_test_add_vtable("/gpg/verify/attached", sizeof(struct state), NULL, setup,
                      test_gpg_verify_attached, teardown);
    g_test_add_vtable("/gpg/verify/detached", sizeof(struct state), NULL, setup,
                      test_gpg_verify_detached, teardown);
    g_test_add_vtable("/gpg/verify/mock", sizeof(struct state), NULL, setup,
                      test_gpg_verify_mock, teardown);

    return g_test_run();
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include "dlp_digest.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "test.h"

struct state {
    char *home;
    char *cwd;
    char orig_cwd[PATH_MAX];
};

static void setup(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(test_setup_home(&s->home));
    g_assert_true(getcwd(s->orig_cwd, sizeof(s->orig_cwd)) != NULL);
    g_assert_nonnull((s->cwd = g_strdup(g_getenv("DLP_TEST_HOME"))));
    g_assert_true(chdir(s->cwd) == 0);
}

static void teardown(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(chdir(s->orig_cwd) == 0);
    g_assert_true(dlp_fs_rmdir(s->cwd, NULL));

    dlp_mem_free(&s->cwd);
    dlp_mem_free(&s->home);
}

static void test_digest_compute_hex(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    size_t i;
    char *digest;
    uint8_t buf[8192 * 32];
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty.
     */
    rv = dlp_digest_compute(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            &digest, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpstr(digest, ==,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b78"
                    "52b855");
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);
    dlp_mem_free(&digest);

    /*
     * Short content.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
    rv = dlp_digest_compute(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            &digest, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpstr(digest, ==,
                    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e8862"
                    "66e7ae");
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);
    dlp_mem_free(&digest);

    /*
     * Short content with bad digest algorithm.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wassign-enum"
    rv = dlp_digest_compute(fd, 999, DLP_DIGEST_ENCODE_HEX, &digest, &err);
#pragma GCC diagnostic pop
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_ALGORITHM);
    g_assert_false(rv);
    g_assert_null(digest);
    g_clear_error(&err);

    /*
     * Short content with bad encoding.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wassign-enum"
    rv = dlp_digest_compute(fd, G_CHECKSUM_SHA256, 999, &digest, &err);
#pragma GCC diagnostic pop
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_ENCODE);
    g_assert_false(rv);
    g_assert_null(digest);
    g_clear_error(&err);

    /*
     * Short content with a position in the middle.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foobar", 6, NULL));
    g_assert_true(dlp_fs_seek(fd, 3, SEEK_SET, NULL));
    rv = dlp_digest_compute(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            &digest, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpstr(digest, ==,
                    "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714cae"
                    "f0c4f2");
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);
    dlp_mem_free(&digest);

    /*
     * Short content with a position at the beginning.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foobar", 6, NULL));
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    rv = dlp_digest_compute(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            &digest, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpstr(digest, ==,
                    "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714cae"
                    "f0c4f2");
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);
    dlp_mem_free(&digest);

    /*
     * Large-ish content.
     */
    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = i % UINT8_MAX;
    }
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, buf, sizeof(buf), NULL));
    rv = dlp_digest_compute(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            &digest, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpstr(digest, ==,
                    "310cf89e49a5c6e06c7ab13176933b4a5c370eb5438c71b6e1eee9b071"
                    "da55e3");
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);
    dlp_mem_free(&digest);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_digest_cmp_hex(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    char buf[8192 * 32];
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty md5 success.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_MD5, DLP_DIGEST_ENCODE_HEX,
                        "d41d8cd98f00b204e9800998ecf8427e", &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    /*
     * Empty sha1 success.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA1, DLP_DIGEST_ENCODE_HEX,
                        "da39a3ee5e6b4b0d3255bfef95601890afd80709", &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    /*
     * Empty sha256 success.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca49599"
                        "1b7852b855",
                        &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    /*
     * Empty sha384 success.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA384, DLP_DIGEST_ENCODE_HEX,
                        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7"
                        "bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                        &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    /*
     * Empty sha512 success.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA512, DLP_DIGEST_ENCODE_HEX,
                        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a9"
                        "21d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd4741"
                        "7a81a538327af927da3e",
                        &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    /*
     * Empty truncated failure.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca49599"
                        "1b7852b85",
                        &err);
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Empty complete mismatch failure.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a396071"
                        "4caef0c4f2",
                        &err);
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Empty empty failure.
     */
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX, "", &err);
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Short content success.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e"
                        "886266e7ae",
                        &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    /*
     * Short truncated failure.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e"
                        "886266e7a",
                        &err);
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Short complete mismatch failure.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a396071"
                        "4caef0c4f2",
                        &err);
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Short empty failure.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX, "", &err);
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Short content with bad digest algorithm.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wassign-enum"
    rv = dlp_digest_cmp(fd, 999, DLP_DIGEST_ENCODE_HEX,
                        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e"
                        "886266e7ae",
                        &err);
#pragma GCC diagnostic pop
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_ALGORITHM);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Short content with bad encoding.
     */
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wassign-enum"
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, 999,
                        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e"
                        "886266e7ae",
                        &err);
#pragma GCC diagnostic pop
    g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_ENCODE);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Large-ish content success.
     */
    memset(buf, 'A', sizeof(buf));
    g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
    g_assert_true(dlp_fs_truncate(fd, 0, NULL));
    g_assert_true(dlp_fs_write_bytes(fd, buf, sizeof(buf), NULL));
    rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                        "97a2fc5541dcc9c06b99b2a84c34961fa0c3af20dba3968df2f96a"
                        "56c6bc00c9",
                        &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(lseek(fd, 0, SEEK_CUR), ==, 0);

    if (test_wrap_p()) {
        GVariantDict *v;

        /*
         * Invalid filesize.
         */
        g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
        g_assert_true(dlp_fs_truncate(fd, 0, NULL));
        g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "st_size", "i", -1);
        test_wrap_push(__fxstat64, true, v);
        rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f9"
                            "8a5e886266e7ae",
                            &err);
        g_assert_error(err, DLP_ERROR, EOVERFLOW);
        g_assert_false(rv);
        g_clear_error(&err);
        g_variant_dict_unref(v);

        /*
         * Bad EOF.
         */
        g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
        g_assert_true(dlp_fs_truncate(fd, 0, NULL));
        g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "errno", "i", EBADF);
        g_variant_dict_insert(v, "rv", "i", 0);
        test_wrap_push(read, true, v);
        rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f9"
                            "8a5e886266e7ae",
                            &err);
        g_assert_error(err, DLP_ERROR, EBADE);
        g_assert_false(rv);
        g_clear_error(&err);
        g_variant_dict_unref(v);

        /*
         * Cleanup failure.
         */
        g_assert_true(dlp_fs_seek(fd, 0, SEEK_SET, NULL));
        g_assert_true(dlp_fs_truncate(fd, 0, NULL));
        g_assert_true(dlp_fs_write_bytes(fd, "foo", 3, NULL));
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "errno", "i", EBADF);
        test_wrap_push(lseek64, true, v);
        test_wrap_push(lseek64, false, NULL);
        rv = dlp_digest_cmp(fd, G_CHECKSUM_SHA256, DLP_DIGEST_ENCODE_HEX,
                            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f9"
                            "8a5e886266e7ae",
                            &err);
        g_assert_error(err, DLP_ERROR, EBADF);
        g_assert_false(rv);
        g_clear_error(&err);
        g_variant_dict_unref(v);
    }

    g_assert_true(dlp_fs_close(&fd, NULL));
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/digest/compute/hex", sizeof(struct state), NULL, setup,
                      test_digest_compute_hex, teardown);
    g_test_add_vtable("/digest/cmp/hex", sizeof(struct state), NULL, setup,
                      test_digest_cmp_hex, teardown);

    return g_test_run();
}

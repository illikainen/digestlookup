/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>
#include <limits.h>

#include "dlp_error.h"
#include "dlp_portage.h"
#include "test.h"

#define TEST_BLAKE2B_FOO                                                       \
    "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb" \
    "3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d"

#define TEST_BLAKE2B_BAR                                                       \
    "76aafe37ce69887569c3c1a51f14b639191fb2180cb0c87b566529496636712868556a9a" \
    "df069d59769bf7e2393d215f195d8e7694f26fc7e20d92195973add8"

#define TEST_BLAKE2B_BAZ                                                       \
    "2305476f21a28dd31ba7aaa4bcbd92780ff6c3ee77d45ea025dfec737e6bc725ce391585" \
    "326dc22208f77c2643ca4afa34334042858a6f250e9094c8f77c82f6"

#define TEST_BLAKE2B_QUX                                                       \
    "214890439bc483b052c325b90a58cd87eacf4ff23c565a6724d5ca95065ee330d51fdcf0" \
    "fb357dd67d904148be5e0b3131558fdb9ea05f9a9aaf27f657861405"

#define TEST_BLAKE2B_QUUX                                                      \
    "0af919d685f353e54f27ef9e36fb07b7c7d820fb59239261ac59c70d2782990580549821" \
    "b32308cf831bc9811a395203c07eb0ba2506dd98b089d02aa87937d3"

#define TEST_SHA512_FOO                                                        \
    "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41" \
    "be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"

#define TEST_SHA512_BAR                                                        \
    "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5" \
    "b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"

#define TEST_SHA512_BAZ                                                        \
    "22b41602570746d784cef124fa6713eec180f93af02a1bfee05528e94a1b053e4136b446" \
    "015161d04e9900849575bd8f95f857773868a205dbed42413cd054f1"

#define TEST_SHA512_QUX                                                        \
    "8c6be9ed448a34883a13a13f4ead4aefa036b67dcda59020c01e57ea075ea8a4792d428f" \
    "2c6fd0c09d1c49994d6c22789336e062188df29572ed07e7f9779c52"

#define TEST_SHA512_QUUX                                                       \
    "8c6be9ed448a34883a13a13f4ead4aefa036b67dcda59020c01e57ea075ea8a4792d428f" \
    "2c6fd0c09d1c49994d6c22789336e062188df29572ed07e7f9779c52"

static gint test_sort_entry(gconstpointer a, gconstpointer b)
{
    if (a != NULL && b != NULL) {
        return g_strcmp0(((const struct dlp_portage_entry *)a)->file,
                         ((const struct dlp_portage_entry *)b)->file);
    }
    return -1;
}

static void test_portage_manifest_read_empty(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "";
    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_null(m);
}

static void test_portage_manifest_read_full(void)
{
    bool rv;
    char *str;
    GList *m;
    struct dlp_portage_entry *e;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n"

          "EBUILD bar.ebuild 0 "
          "BLAKE2B " TEST_BLAKE2B_BAR " "
          "SHA512 " TEST_SHA512_BAR "\n"

          "EBUILD baz.ebuild 321 "
          "BLAKE2B " TEST_BLAKE2B_BAZ " "
          "SHA512 " TEST_SHA512_BAZ "\n"

          "MISC qux.misc 1 "
          "BLAKE2B " TEST_BLAKE2B_QUX " "
          "SHA512 " TEST_SHA512_QUX "\n"

          "AUX quux.aux 1 "
          "BLAKE2B " TEST_BLAKE2B_QUUX " "
          "SHA512 " TEST_SHA512_QUUX "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(m);

    g_assert_cmpuint(g_list_length(m), ==, 5);
    m = g_list_sort(m, test_sort_entry);

    e = g_list_nth_data(m, 0);
    g_assert_cmpstr(e->file, ==, "bar.ebuild");
    g_assert_cmpint(e->type, ==, DLP_PORTAGE_TYPE_EBUILD);
    g_assert_cmpuint(e->size, ==, 0);
    g_assert_cmpstr(e->blake2b, ==, TEST_BLAKE2B_BAR);
    g_assert_cmpstr(e->sha512, ==, TEST_SHA512_BAR);

    e = g_list_nth_data(m, 1);
    g_assert_cmpstr(e->file, ==, "baz.ebuild");
    g_assert_cmpint(e->type, ==, DLP_PORTAGE_TYPE_EBUILD);
    g_assert_cmpuint(e->size, ==, 321);
    g_assert_cmpstr(e->blake2b, ==, TEST_BLAKE2B_BAZ);
    g_assert_cmpstr(e->sha512, ==, TEST_SHA512_BAZ);

    e = g_list_nth_data(m, 2);
    g_assert_cmpstr(e->file, ==, "foo.tar.gz");
    g_assert_cmpint(e->type, ==, DLP_PORTAGE_TYPE_DIST);
    g_assert_cmpuint(e->size, ==, 1234);
    g_assert_cmpstr(e->blake2b, ==, TEST_BLAKE2B_FOO);
    g_assert_cmpstr(e->sha512, ==, TEST_SHA512_FOO);

    e = g_list_nth_data(m, 3);
    g_assert_cmpstr(e->file, ==, "quux.aux");
    g_assert_cmpint(e->type, ==, DLP_PORTAGE_TYPE_AUX);
    g_assert_cmpuint(e->size, ==, 1);
    g_assert_cmpstr(e->blake2b, ==, TEST_BLAKE2B_QUUX);
    g_assert_cmpstr(e->sha512, ==, TEST_SHA512_QUUX);

    e = g_list_nth_data(m, 4);
    g_assert_cmpstr(e->file, ==, "qux.misc");
    g_assert_cmpint(e->type, ==, DLP_PORTAGE_TYPE_MISC);
    g_assert_cmpuint(e->size, ==, 1);
    g_assert_cmpstr(e->blake2b, ==, TEST_BLAKE2B_QUX);
    g_assert_cmpstr(e->sha512, ==, TEST_SHA512_QUX);

    dlp_portage_manifest_free(&m);
}

static void test_portage_manifest_read_len_overflow(void)
{
    if (SIZE_MAX > G_MAXUINT) {
        bool rv;
        GList *m;
        GError *err = NULL;

        rv = dlp_portage_manifest_read("", SIZE_MAX, &m, &err);
        g_assert_error(err, DLP_ERROR, ERANGE);
        g_assert_false(rv);
        g_assert_null(m);
        g_clear_error(&err);
    }
}

static void test_portage_manifest_read_missing_type(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "BLAKE2B  " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_duplicate_type(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1 "
          "DIST bar.tar.gz 1 "
          "BLAKE2B  " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_bad_size(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz ... "
          "BLAKE2B  " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_bad_file(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST \033[32mfoo.tar.gz\033[0m 1 "
          "BLAKE2B  " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_truncated_blake2b(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B 1234 "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_truncated_sha512(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B " TEST_BLAKE2B_FOO " "
          "SHA512 abcd\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_duplicate_blake2b(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B  " TEST_BLAKE2B_FOO " "
          "BLAKE2B  " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_duplicate_sha512(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_bad_blake2b(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B ==== "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_bad_sha512(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B " TEST_BLAKE2B_FOO " "
          "SHA512 ====\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_missing_blake2b(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_missing_sha512(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "BLAKE2B " TEST_BLAKE2B_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_read_bad_symbol(void)
{
    bool rv;
    char *str;
    GList *m;
    GError *err = NULL;

    str = "DIST foo.tar.gz 1234 "
          "ABCD "
          "BLAKE2B " TEST_BLAKE2B_FOO " "
          "SHA512 " TEST_SHA512_FOO "\n";

    rv = dlp_portage_manifest_read(str, strlen(str), &m, &err);
    g_assert_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(m);
    g_clear_error(&err);
}

static void test_portage_manifest_free(void)
{
    GList *m = NULL;

    dlp_portage_manifest_free(NULL);
    dlp_portage_manifest_free(&m);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/portage/manifest/read/empty",
                    test_portage_manifest_read_empty);
    g_test_add_func("/portage/manifest/read/full",
                    test_portage_manifest_read_full);
    g_test_add_func("/portage/manifest/read/len-overflow",
                    test_portage_manifest_read_len_overflow);
    g_test_add_func("/portage/manifest/read/missing-type",
                    test_portage_manifest_read_missing_type);
    g_test_add_func("/portage/manifest/read/duplicate-type",
                    test_portage_manifest_read_duplicate_type);
    g_test_add_func("/portage/manifest/read/bad-size",
                    test_portage_manifest_read_bad_size);
    g_test_add_func("/portage/manifest/read/bad-file",
                    test_portage_manifest_read_bad_file);
    g_test_add_func("/portage/manifest/read/truncated-blake2b",
                    test_portage_manifest_read_truncated_blake2b);
    g_test_add_func("/portage/manifest/read/truncated-sha512",
                    test_portage_manifest_read_truncated_sha512);
    g_test_add_func("/portage/manifest/read/duplicate-blake2b",
                    test_portage_manifest_read_duplicate_blake2b);
    g_test_add_func("/portage/manifest/read/duplicate-sha512",
                    test_portage_manifest_read_duplicate_sha512);
    g_test_add_func("/portage/manifest/read/bad-blake2b",
                    test_portage_manifest_read_bad_blake2b);
    g_test_add_func("/portage/manifest/read/bad-sha512",
                    test_portage_manifest_read_bad_sha512);
    g_test_add_func("/portage/manifest/read/missing-blake2b",
                    test_portage_manifest_read_missing_blake2b);
    g_test_add_func("/portage/manifest/read/missing-sha512",
                    test_portage_manifest_read_missing_sha512);
    g_test_add_func("/portage/manifest/read/bad-symbol",
                    test_portage_manifest_read_bad_symbol);
    g_test_add_func("/portage/manifest/free", test_portage_manifest_free);

    return g_test_run();
}

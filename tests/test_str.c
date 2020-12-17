/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_str.h"
#include "test.h"

static void test_str_sanitize_printable(void)
{
    char *str;

    str = g_strdup("foo");
    dlp_str_sanitize(str);
    g_assert_cmpstr(str, ==, "foo");
    g_free(str);

    str = g_strdup("\033[31mfoo\033[0m");
    dlp_str_sanitize(str);
    g_assert_cmpstr(str, ==, "_[31mfoo_[0m");
    g_free(str);

    str = g_strdup("\033[31m  foo  \033[32m  bar  \033[0m");
    dlp_str_sanitize(str);
    g_assert_cmpstr(str, ==, "_[31m  foo  _[32m  bar  _[0m");
    g_free(str);

    str = g_strdup("\033[31mfoo\nbar\033[0m");
    dlp_str_sanitize(str);
    g_assert_cmpstr(str, ==, "_[31mfoo\nbar_[0m");
    g_free(str);
}

static void test_str_sanitize_filename(void)
{
    char *str;

    str = g_strdup("foo");
    dlp_str_sanitize_filename(str);
    g_assert_cmpstr(str, ==, "foo");
    g_free(str);

    str = g_strdup("foo.bar");
    dlp_str_sanitize_filename(str);
    g_assert_cmpstr(str, ==, "foo_bar");
    g_free(str);

    str = g_strdup("foo/bar");
    dlp_str_sanitize_filename(str);
    g_assert_cmpstr(str, ==, "foo_bar");
    g_free(str);

    str = g_strdup("../../foo/../bar");
    dlp_str_sanitize_filename(str);
    g_assert_cmpstr(str, ==, "______foo____bar");
    g_free(str);

    str = g_strdup("foo!bar.baz#$");
    dlp_str_sanitize_filename(str);
    g_assert_cmpstr(str, ==, "foo_bar_baz__");
    g_free(str);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_add_func("/str/sanitize/printable", test_str_sanitize_printable);
    g_test_add_func("/str/sanitize/filename", test_str_sanitize_filename);

    g_test_init(&argc, &argv, NULL);

    return g_test_run();
}

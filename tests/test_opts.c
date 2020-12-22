/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_error.h"
#include "dlp_opts.h"
#include "test.h"

static void test_opts_parse_unknown_arg(void)
{
    struct dlp_opts *opts;
    char *argv[] = { "prog", "--foobar", NULL };
    int argc = G_N_ELEMENTS(argv) - 1;
    GError *err = NULL;
    bool rv = false;

    rv = dlp_opts_parse(argc, argv, &opts, &err);
    g_assert_error(err, G_OPTION_ERROR, G_OPTION_ERROR_UNKNOWN_OPTION);
    g_assert_false(rv);
    g_clear_error(&err);
}

static void test_opts_parse_no_patterns(void)
{
    struct dlp_opts *opts;
    char *argv[] = { "prog", NULL };
    int argc = G_N_ELEMENTS(argv) - 1;
    GError *err = NULL;
    bool rv = false;

    rv = dlp_opts_parse(argc, argv, &opts, &err);
    g_assert_error(err, DLP_ERROR, G_OPTION_ERROR_BAD_VALUE);
    g_assert_false(rv);
    g_clear_error(&err);
}

static void test_opts_parse_bad_pattern(void)
{
    struct dlp_opts *opts;
    char *argv[] = { "prog", "foo", "bar[", NULL };
    int argc = G_N_ELEMENTS(argv) - 1;
    GError *err = NULL;
    bool rv = false;

    rv = dlp_opts_parse(argc, argv, &opts, &err);
    g_assert_error(err, G_REGEX_ERROR,
                   G_REGEX_ERROR_UNTERMINATED_CHARACTER_CLASS);
    g_assert_false(rv);
    g_clear_error(&err);
}

static void test_opts_parse_success(void)
{
    struct dlp_opts *opts;
    char *argv[] = { "prog", "foo", "bar", NULL };
    int argc = G_N_ELEMENTS(argv) - 1;
    GError *err = NULL;
    bool rv = false;

    rv = dlp_opts_parse(argc, argv, &opts, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    dlp_opts_free(&opts);
}

static void test_opts_free(void)
{
    dlp_opts_free(NULL);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/opts/parse/unknown-arg", test_opts_parse_unknown_arg);
    g_test_add_func("/opts/parse/no-patterns", test_opts_parse_no_patterns);
    g_test_add_func("/opts/parse/bad-pattern", test_opts_parse_bad_pattern);
    g_test_add_func("/opts/parse/success", test_opts_parse_success);
    g_test_add_func("/opts/free", test_opts_free);

    return g_test_run();
}

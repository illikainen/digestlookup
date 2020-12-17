/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include "dlp_error.h"
#include "dlp_table.h"
#include "test.h"

static void test_table_init_free(void)
{
    struct dlp_table *t = NULL;

    dlp_table_init(&t);
    g_assert_nonnull(t);

    dlp_table_free(&t);
    g_assert_null(t);

    dlp_table_free(&t);
    dlp_table_free(NULL);
}

static void test_table_add_columns(void)
{
    if (test_wrap_p()) {
        struct dlp_table *t;

        dlp_table_init(&t);
        g_assert_nonnull(t);

        test_wrap_push(g_strdup, true, NULL);
        g_assert_false(dlp_table_add_columns(t, NULL, "foo", NULL));
        dlp_table_free(&t);
    }
}

static void test_table_format(void)
{
    struct dlp_table *t;
    char *s;
    bool rv;
    GError *err = NULL;

    dlp_table_init(&t);
    g_assert_nonnull(t);

    /*
     * Only columns.
     */
    rv = dlp_table_add_columns(t, &err, "foo", "bar", "baz", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    g_assert_true(dlp_table_format(t, &s));
    g_assert_nonnull(strstr(s, "| foo | bar | baz |\n"));
    g_assert_nonnull(strstr(s, "|-----|-----|-----|\n"));
    dlp_mem_free(&s);

    /*
     * Invalid column name.
     */
    rv = dlp_table_add_row(t, &err, "foo", "1", "bar", "2", "baz12", "3", NULL);
    g_assert_error(err, DLP_ERROR, EINVAL);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * All columns provided.
     */
    rv = dlp_table_add_row(t, &err, "foo", "1", "bar", "2", "baz", "3", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    g_assert_true(dlp_table_format(t, &s));
    g_assert_nonnull(strstr(s, "| foo | bar | baz |\n"));
    g_assert_nonnull(strstr(s, "|-----|-----|-----|\n"));
    g_assert_nonnull(strstr(s, "| 1   | 2   | 3   |\n"));
    dlp_mem_free(&s);

    /*
     * Some columns provided.
     */
    rv = dlp_table_add_row(t, &err, "bar", "abcdefgh", "baz", "ijklmno", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    g_assert_true(dlp_table_format(t, &s));
    g_assert_nonnull(strstr(s, "| foo | bar      | baz     |\n"));
    g_assert_nonnull(strstr(s, "|-----|----------|---------|\n"));
    g_assert_nonnull(strstr(s, "| 1   | 2        | 3       |\n"));
    g_assert_nonnull(strstr(s, "|     | abcdefgh | ijklmno |\n"));
    dlp_mem_free(&s);

    /*
     * No columns provided.
     */
    rv = dlp_table_add_row(t, &err, NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    g_assert_true(dlp_table_format(t, &s));
    g_assert_nonnull(strstr(s, "| foo | bar      | baz     |\n"));
    g_assert_nonnull(strstr(s, "|-----|----------|---------|\n"));
    g_assert_nonnull(strstr(s, "| 1   | 2        | 3       |\n"));
    g_assert_nonnull(strstr(s, "|     | abcdefgh | ijklmno |\n"));
    g_assert_nonnull(strstr(s, "|     |          |         |\n"));
    dlp_mem_free(&s);

    dlp_table_free(&t);
}

static void test_table_print(void)
{
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_test_trap_subprocess("/table/print/subprocess/no-rows", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("| foobar | baz |\n"
                              "|--------|-----|\n");

    g_test_trap_subprocess("/table/print/subprocess/misc", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("| foobar   | baz |\n"
                              "|----------|-----|\n"
                              "| abcdefgh | 123 |\n"
                              "| qux      |     |\n");
}

static void test_table_print_no_rows(void)
{
    struct dlp_table *t;

    dlp_table_init(&t);
    g_assert_nonnull(t);
    g_assert_true(dlp_table_add_columns(t, NULL, "foobar", "baz", NULL));
    dlp_table_print(t);
    dlp_table_free(&t);
}

static void test_table_print_misc(void)
{
    struct dlp_table *t;

    dlp_table_init(&t);
    g_assert_nonnull(t);
    g_assert_true(dlp_table_add_columns(t, NULL, "foobar", "baz", NULL));
    g_assert_true(dlp_table_add_row(t, NULL, "foobar", "qux", NULL));
    g_assert_true(
        dlp_table_add_row(t, NULL, "foobar", "abcdefgh", "baz", "123", NULL));
    dlp_table_print(t);
    dlp_table_free(&t);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/table/init-free", test_table_init_free);
    g_test_add_func("/table/add-columns", test_table_add_columns);
    g_test_add_func("/table/format", test_table_format);
    g_test_add_func("/table/print", test_table_print);
    g_test_add_func("/table/print/subprocess/no-rows",
                    test_table_print_no_rows);
    g_test_add_func("/table/print/subprocess/misc", test_table_print_misc);

    return g_test_run();
}

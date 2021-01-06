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

static void test_str_match_plain(void)
{
    GRegex *rx;
    GPtrArray *rxs;

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);

    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_assert_nonnull(rx);
    g_ptr_array_add(rxs, rx);

    rx = g_regex_new("bar", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_assert_nonnull(rx);
    g_ptr_array_add(rxs, rx);

    g_assert_true(dlp_str_match_plain(rxs, "foo"));
    g_assert_true(dlp_str_match_plain(rxs, "bar"));
    g_assert_true(dlp_str_match_plain(rxs, "foobar"));
    g_assert_false(dlp_str_match_plain(rxs, "baz"));

    dlp_mem_ptr_array_unref(&rxs);
}

static void test_str_match_parray(void)
{
    GRegex *rx;
    GPtrArray *rxs;
    GPtrArray *strs;

    strs = g_ptr_array_new();
    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);

    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_assert_nonnull(rx);
    g_ptr_array_add(rxs, rx);

    rx = g_regex_new("bar", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_assert_nonnull(rx);
    g_ptr_array_add(rxs, rx);

    g_ptr_array_add(strs, "foo");
    g_ptr_array_add(strs, "bar");
    g_ptr_array_add(strs, "baz");
    g_assert_true(dlp_str_match_parray(rxs, strs));
    g_ptr_array_remove_range(strs, 0, strs->len);

    g_ptr_array_add(strs, "baz");
    g_assert_false(dlp_str_match_parray(rxs, strs));
    g_ptr_array_remove_range(strs, 0, strs->len);

    dlp_mem_ptr_array_unref(&rxs);
    dlp_mem_ptr_array_unref(&strs);
}

static void test_str_match_list(void)
{
    struct elt {
        int i;
        const char *str;
    };
    struct elt foo = { .i = 123, .str = "foo" };
    struct elt bar = { .i = 123, .str = "bar" };
    struct elt baz = { .i = 123, .str = "baz" };
    GRegex *rx;
    GPtrArray *rxs;
    GList *list = NULL;
    glong off = G_STRUCT_OFFSET(struct elt, str);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);

    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_assert_nonnull(rx);
    g_ptr_array_add(rxs, rx);

    rx = g_regex_new("bar", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_assert_nonnull(rx);
    g_ptr_array_add(rxs, rx);

    list = g_list_append(list, &foo);
    g_assert_true(dlp_str_match_list(rxs, list, off));

    list = g_list_append(list, &bar);
    g_assert_true(dlp_str_match_list(rxs, list, off));

    g_list_free(g_steal_pointer(&list));
    list = g_list_append(list, &baz);
    g_assert_false(dlp_str_match_list(rxs, list, off));

    g_list_free(g_steal_pointer(&list));
    dlp_mem_ptr_array_unref(&rxs);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_add_func("/str/sanitize/printable", test_str_sanitize_printable);
    g_test_add_func("/str/sanitize/filename", test_str_sanitize_filename);
    g_test_add_func("/str/match/plain", test_str_match_plain);
    g_test_add_func("/str/match/parray", test_str_match_parray);
    g_test_add_func("/str/match/list", test_str_match_list);

    g_test_init(&argc, &argv, NULL);

    return g_test_run();
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_mem.h"
#include "test.h"

struct test_mem {
    char *foo;
    char *bar;
};

static void test_mem_alloc_0(void)
{
    char *ptr;

    ptr = dlp_mem_alloc(0);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_large(void)
{
    char *ptr;

    ptr = dlp_mem_alloc(RSIZE_MAX);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc(void)
{
    char *ptr;
    char nul[123] = { '\0' };
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_assert_nonnull(ptr = dlp_mem_alloc(sizeof(nul)));
    g_assert_cmpint(memcmp(ptr, nul, sizeof(nul)), ==, 0);
    dlp_mem_free(&ptr);

    g_test_trap_subprocess("/mem/alloc/subprocess/0", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");

    g_test_trap_subprocess("/mem/alloc/subprocess/large", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");
}

static void test_mem_alloc_n_size_0(void)
{
    char *ptr;

    ptr = dlp_mem_alloc_n(0, 1);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_n_size_large(void)
{
    char *ptr;

    ptr = dlp_mem_alloc_n(RSIZE_MAX, 1);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_n_nmemb_0(void)
{
    char *ptr;

    ptr = dlp_mem_alloc_n(1, 0);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_n_nmemb_large(void)
{
    char *ptr;

    ptr = dlp_mem_alloc_n(1, RSIZE_MAX);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_n_size_nmemb_0(void)
{
    char *ptr;

    ptr = dlp_mem_alloc_n(0, 0);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_n_size_nmemb_large(void)
{
    char *ptr;

    ptr = dlp_mem_alloc_n(RSIZE_MAX, RSIZE_MAX);
    dlp_mem_free(&ptr);
}

static void test_mem_alloc_n(void)
{
    void *ptr;
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_assert_nonnull(ptr = dlp_mem_alloc_n(123, 321));
    dlp_mem_free(&ptr);

    g_test_trap_subprocess("/mem/alloc-n/subprocess/size-0", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");

    g_test_trap_subprocess("/mem/alloc-n/subprocess/size-large", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");

    g_test_trap_subprocess("/mem/alloc-n/subprocess/nmemb-0", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");

    g_test_trap_subprocess("/mem/alloc-n/subprocess/nmemb-large", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");

    g_test_trap_subprocess("/mem/alloc-n/subprocess/size-nmemb-0", 0, flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");

    g_test_trap_subprocess("/mem/alloc-n/subprocess/size-nmemb-large", 0,
                           flags);
    g_test_trap_assert_failed();
    g_test_trap_assert_stderr("*ERROR*invalid size*");
}

static void test_mem_free(gpointer data)
{
    struct test_mem *m = data;

    g_assert_nonnull(m->foo);
    dlp_mem_free(&m->foo);
    g_assert_null(m->foo);

    g_assert_nonnull(m->bar);
    dlp_mem_free(&m->bar);
    g_assert_null(m->bar);

    dlp_mem_free(&m);
    g_assert_null(m);

    dlp_mem_free(&m);
    g_assert_null(m);
}

static void test_mem_clear(void)
{
    struct test_mem *m;

    m = dlp_mem_alloc(sizeof(*m));
    g_assert_nonnull(m);
    m->foo = dlp_mem_alloc(123);
    g_assert_nonnull(m->foo);
    m->bar = dlp_mem_alloc(321);
    g_assert_nonnull(m->bar);

    dlp_mem_clear(&m, &test_mem_free);
}

static void test_mem_ptr_array_unref(void)
{
    GPtrArray *arr = NULL;

    dlp_mem_ptr_array_unref(NULL);
    dlp_mem_ptr_array_unref(&arr);

    arr = g_ptr_array_new_full(0, g_free);
    g_assert_nonnull(arr);
    g_ptr_array_add(arr, g_strdup("foo"));
    dlp_mem_ptr_array_unref(&arr);
    g_assert_null(arr);
}

static void test_mem_ptr_array_destroy(void)
{
    GPtrArray *arr;

    dlp_mem_ptr_array_destroy(NULL);

    arr = g_ptr_array_new_full(0, g_free);
    g_assert_nonnull(arr);
    g_ptr_array_add(arr, g_strdup("foo"));
    dlp_mem_ptr_array_destroy(arr);
}

static void test_mem_regex_unref(void)
{
    GRegex *rx = NULL;

    dlp_mem_regex_unref(NULL);
    dlp_mem_regex_unref(&rx);

    rx = g_regex_new("[a-zA-Z0-9]", G_REGEX_DOLLAR_ENDONLY,
                     G_REGEX_MATCH_NOTEMPTY, NULL);
    g_assert_nonnull(rx);
    dlp_mem_regex_unref(&rx);
    g_assert_null(rx);
}

static void test_mem_regex_destroy(void)
{
    GRegex *rx = NULL;

    dlp_mem_regex_destroy(NULL);
    dlp_mem_regex_destroy(rx);

    rx = g_regex_new("[a-zA-Z0-9]", G_REGEX_DOLLAR_ENDONLY,
                     G_REGEX_MATCH_NOTEMPTY, NULL);
    g_assert_nonnull(rx);
    dlp_mem_regex_destroy(rx);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/mem/alloc/subprocess/0", test_mem_alloc_0);
    g_test_add_func("/mem/alloc/subprocess/large", test_mem_alloc_large);
    g_test_add_func("/mem/alloc", test_mem_alloc);
    g_test_add_func("/mem/alloc-n", test_mem_alloc_n);
    g_test_add_func("/mem/alloc-n/subprocess/size-0", test_mem_alloc_n_size_0);
    g_test_add_func("/mem/alloc-n/subprocess/size-large",
                    test_mem_alloc_n_size_large);
    g_test_add_func("/mem/alloc-n/subprocess/nmemb-0",
                    test_mem_alloc_n_nmemb_0);
    g_test_add_func("/mem/alloc-n/subprocess/nmemb-large",
                    test_mem_alloc_n_nmemb_large);
    g_test_add_func("/mem/alloc-n/subprocess/size-nmemb-0",
                    test_mem_alloc_n_size_nmemb_0);
    g_test_add_func("/mem/alloc-n/subprocess/size-nmemb-large",
                    test_mem_alloc_n_size_nmemb_large);
    g_test_add_func("/mem/clear", test_mem_clear);
    g_test_add_func("/mem/ptr-array-unref", test_mem_ptr_array_unref);
    g_test_add_func("/mem/ptr-array-destroy", test_mem_ptr_array_destroy);
    g_test_add_func("/mem/regex-unref", test_mem_regex_unref);
    g_test_add_func("/mem/regex-destroy", test_mem_regex_destroy);

    return g_test_run();
}

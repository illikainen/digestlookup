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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/mem/alloc/subprocess/0", test_mem_alloc_0);
    g_test_add_func("/mem/alloc/subprocess/large", test_mem_alloc_large);
    g_test_add_func("/mem/alloc", test_mem_alloc);
    g_test_add_func("/mem/clear", test_mem_clear);

    return g_test_run();
}

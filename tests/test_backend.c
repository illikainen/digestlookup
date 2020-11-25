/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_backend.h"
#include "dlp_error.h"
#include "test.h"

static void test_backend_misc(void)
{
    struct dlp_backend *be;
    struct dlp_backend a = { .name = "a" };
    struct dlp_backend b = { .name = "b" };
    struct dlp_backend c = { .name = "a" };

    /*
     * Add duplicates.
     */
    dlp_backend_add(&a);
    g_assert_true(dlp_backend_find("a", &be, NULL));
    dlp_backend_add(&b);
    dlp_backend_add(&c);
    g_assert_true(dlp_backend_find("a", &be, NULL));
    g_assert_true(&a == be);
    dlp_backend_remove(&a);
    g_assert_false(dlp_backend_find("a", &be, NULL));
    g_assert_null(be);
    dlp_backend_remove(&b);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/backend/misc", test_backend_misc);

    return g_test_run();
}

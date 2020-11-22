/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_error.h"
#include "dlp_mem.h"
#include "dlp_resource.h"
#include "test.h"

static void test_resource_p(void)
{
    g_assert_true(dlp_resource_p("resource:///foo/bar"));
    g_assert_false(dlp_resource_p("/foo/bar"));
}

static void test_resource_exists_p(void)
{
    bool rv;
    GError *err = NULL;

    rv = dlp_resource_exists_p("/foo/bar", &err);
    g_assert_error(err, G_RESOURCE_ERROR, G_RESOURCE_ERROR_NOT_FOUND);
    g_assert_false(rv);
    g_clear_error(&err);

    rv = dlp_resource_exists_p("/dlp/keys/debian/buster-automatic.asc", &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_resource_exists_p("resource:///dlp/keys/debian/"
                               "buster-automatic.asc",
                               &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    if (test_wrap_p()) {
        test_wrap_push(g_static_resource_get_resource, true, NULL);
        rv = dlp_resource_exists_p("/dlp/keys/debian/buster-automatic.asc",
                                   &err);
        g_assert_error(err, DLP_ERROR, G_RESOURCE_ERROR_INTERNAL);
        g_assert_false(rv);
        g_clear_error(&err);
    }
}

static void test_resource_data(void)
{
    bool rv;
    void *first;
    void *second;
    gsize first_size;
    gsize second_size;
    GError *err = NULL;

    rv = dlp_resource_data("/foo/bar", &first, &first_size, &err);
    g_assert_error(err, G_RESOURCE_ERROR, G_RESOURCE_ERROR_NOT_FOUND);
    g_assert_false(rv);
    g_assert_null(first);
    g_assert_cmpuint(first_size, ==, 0);
    g_clear_error(&err);

    rv = dlp_resource_data("/dlp/keys/debian/buster-automatic.asc", &first,
                           &first_size, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(first);
    g_assert_cmpuint(first_size, !=, 0);

    rv = dlp_resource_data("resource:///dlp/keys/debian/buster-automatic.asc",
                           &second, &second_size, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(second);
    g_assert_cmpuint(second_size, !=, 0);

    g_assert_cmpmem(first, first_size, second, second_size);

    dlp_mem_free(&first);
    dlp_mem_free(&second);

    if (test_wrap_p()) {
        test_wrap_push(g_static_resource_get_resource, true, NULL);
        rv = dlp_resource_data("/dlp/keys/debian/buster-automatic.asc", &first,
                               &first_size, &err);
        g_assert_error(err, DLP_ERROR, G_RESOURCE_ERROR_INTERNAL);
        g_assert_false(rv);
        g_assert_null(first);
        g_assert_cmpuint(first_size, ==, 0);
        g_clear_error(&err);

        test_wrap_push(g_bytes_unref_to_data, true, NULL);
        rv = dlp_resource_data("/dlp/keys/debian/buster-automatic.asc", &first,
                               &first_size, &err);
        g_assert_error(err, DLP_ERROR, G_RESOURCE_ERROR_INTERNAL);
        g_assert_false(rv);
        g_assert_null(first);
        g_assert_cmpuint(first_size, ==, 0);
        g_clear_error(&err);
    }
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/resource/p", test_resource_p);
    g_test_add_func("/resource/exists-p", test_resource_exists_p);
    g_test_add_func("/resource/data", test_resource_data);

    return g_test_run();
}

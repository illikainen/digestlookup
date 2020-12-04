/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>
#include <locale.h>

#include "dlp_date.h"
#include "dlp_error.h"
#include "test.h"

static void test_date_parse(void)
{
    time_t t;
    bool rv;
    GError *err = NULL;

    /*
     * Success with 0 timestmap.
     */
    rv = dlp_date_parse("Thu, 01 Jan 1970 00:00:00 +0000",
                        "%a, %d %b %Y %H:%M:%S %z", &t, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpint(t, ==, 0);

    /*
     * Success with non-0 timestmap.
     */
    rv = dlp_date_parse("Thu, 01 Jan 2020 00:00:00 +0000",
                        "%a, %d %b %Y %H:%M:%S %z", &t, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpint(t, ==, 1577836800);

    /*
     * Bogus string.
     */
    rv = dlp_date_parse("Thu, 01 Jan 2020 00:00:00 FOO",
                        "%a, %d %b %Y %H:%M:%S %z", &t, &err);
    g_assert_error(err, DLP_ERROR, DLP_DATE_ERROR_FORMAT);
    g_assert_false(rv);
    g_clear_error(&err);

    if (test_wrap_p()) {
        locale_t loc;

        /*
         * newlocale() failure.
         */
        test_wrap_push(newlocale, true, NULL);
        rv = dlp_date_parse("Thu, 01 Jan 2020 00:00:00 +0000",
                            "%a, %d %b %Y %H:%M:%S %z", &t, &err);
        g_assert_error(err, DLP_ERROR, EINVAL);
        g_assert_false(rv);
        g_clear_error(&err);

        /*
         * uselocale() failure.
         */
        test_wrap_push(uselocale, true, NULL);
        rv = dlp_date_parse("Thu, 01 Jan 2020 00:00:00 +0000",
                            "%a, %d %b %Y %H:%M:%S %z", &t, &err);
        g_assert_error(err, DLP_ERROR, EINVAL);
        g_assert_false(rv);
        g_clear_error(&err);

        /*
         * uselocale() cleanup failure.
         */
        loc = LC_GLOBAL_LOCALE; /* avoid leak */
        test_wrap_push(newlocale, true, &loc);
        test_wrap_push(uselocale, true, NULL);
        test_wrap_push(uselocale, false, NULL);
        rv = dlp_date_parse("Thu, 01 Jan 2020 00:00:00 +0000",
                            "%a, %d %b %Y %H:%M:%S %z", &t, &err);
        g_assert_error(err, DLP_ERROR, EINVAL);
        g_assert_false(rv);
        g_clear_error(&err);

        /*
         * timegm() failure.
         */
        test_wrap_push(timegm, true, NULL);
        rv = dlp_date_parse("Thu, 01 Jan 2020 00:00:00 +0000",
                            "%a, %d %b %Y %H:%M:%S %z", &t, &err);
        g_assert_error(err, DLP_ERROR, EOVERFLOW);
        g_assert_false(rv);
        g_clear_error(&err);
    }
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/date/parse", test_date_parse);

    return g_test_run();
}

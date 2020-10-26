/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include "dlp_error.h"
#include "test.h"

static void test_error_str(void **state)
{
    (void)state;

    errno = 0;
    assert_string_equal(dlp_error_str("foo"), "foo");

    errno = EOVERFLOW;
    assert_string_not_equal(dlp_error_str("foo"), "foo");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_error_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

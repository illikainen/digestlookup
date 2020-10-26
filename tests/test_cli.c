/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "dlp_cli.h"

static void test_cli(void **state)
{
    (void)state;

    assert_int_equal(dlp_cli(), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cli),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

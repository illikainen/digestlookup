/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_cli.h"
#include "test.h"

static void test_cli(void **state)
{
    (void)state;

    assert_true(dlp_cli());
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cli),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

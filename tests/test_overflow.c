/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <stdint.h>

#include "dlp_overflow.h"
#include "test.h"

static void test_overflow(void **state)
{
    int i;
    unsigned int u;

    (void)state;

    assert_true(dlp_overflow_add(INT_MAX, 1, &i));

    assert_false(dlp_overflow_add(INT_MAX, 0, &i));
    assert_true(i == INT_MAX);

    assert_false(dlp_overflow_add(INT_MAX - 1, 1, &i));
    assert_true(i == INT_MAX);

    assert_true(dlp_overflow_add(UINT_MAX, 1, &u));

    assert_false(dlp_overflow_add(UINT_MAX, 0, &u));
    assert_true(u == UINT_MAX);

    assert_false(dlp_overflow_add(UINT_MAX - 1, 1, &u));
    assert_true(u == UINT_MAX);

    assert_true(dlp_overflow_sub(INT_MIN, 1, &i));

    assert_false(dlp_overflow_sub(INT_MIN, 0, &i));
    assert_true(i == INT_MIN);

    assert_false(dlp_overflow_sub(INT_MIN + 1, 1, &i));
    assert_true(i == INT_MIN);

    assert_true(dlp_overflow_sub(0, 1, &u));

    assert_false(dlp_overflow_sub(0, 0, &u));
    assert_true(u == 0);

    assert_false(dlp_overflow_sub(1, 1, &u));
    assert_true(u == 0);

    assert_true(dlp_overflow_mul(INT_MAX, 2, &i));

    assert_false(dlp_overflow_mul(INT_MAX, 1, &i));
    assert_true(i == INT_MAX);

    assert_false(dlp_overflow_mul(INT_MAX, 0, &i));
    assert_true(i == 0);

    assert_true(dlp_overflow_mul(UINT_MAX, 2, &u));

    assert_false(dlp_overflow_mul(UINT_MAX, 1, &u));
    assert_true(u == UINT_MAX);

    assert_false(dlp_overflow_mul(UINT_MAX, 0, &u));
    assert_true(u == 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_overflow),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

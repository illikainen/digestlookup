/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_OVERFLOW_H
#define DLP_OVERFLOW_H

#define dlp_overflow_add(a, b, res) __builtin_add_overflow((a), (b), (res))
#define dlp_overflow_sub(a, b, res) __builtin_sub_overflow((a), (b), (res))
#define dlp_overflow_mul(a, b, res) __builtin_mul_overflow((a), (b), (res))

#endif /* DLP_OVERFLOW_H */

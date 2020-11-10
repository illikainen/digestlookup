/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_H
#define DLP_H

#if defined(__clang__) || defined(__GNUC__)
#    define DLP_NODISCARD __attribute__((warn_unused_result))
#else
#    define DLP_NODISCARD
#endif

#if defined(__clang__)
#    define DLP_DISCARD(expr) ((void)(expr))
#elif defined(__GNUC__)
#    define DLP_DISCARD(expr)                                                  \
        do {                                                                   \
            /* sigh... */                                                      \
            if ((expr)) {                                                      \
            }                                                                  \
        } while (0)
#else
#    define DLP_DISCARD
#endif

#endif /* DLP_H */

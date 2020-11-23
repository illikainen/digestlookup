/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_H
#define DLP_H

#if defined(__clang__) || defined(__GNUC__)
#    define DLP_ALLOC_SIZE(n) __attribute__((alloc_size(n)))
#    define DLP_NODISCARD __attribute__((warn_unused_result))
#    define DLP_CONSTRUCTOR __attribute__((constructor))
#    define DLP_DESTRUCTOR __attribute__((destructor))
#else
#    define DLP_ALLOC_SIZE(n)
#    define DLP_NODISCARD
#    define DLP_CONSTRUCTOR _Static_assert(false, "fix DLP_CONSTRUCTOR");
#    define DLP_DESTRUCTOR _Static_assert(false, "fix DLP_DESTRUCTOR");
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

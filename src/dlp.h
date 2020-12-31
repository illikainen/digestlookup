/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_H
#define DLP_H

#include <limits.h>
#include <stdint.h>

#include <glib.h>

#define DLP_BUFSIZ MIN(8192, MIN(SIZE_MAX, SSIZE_MAX))

#if defined(__clang__) || defined(__GNUC__)
#    define DLP_MALLOC __attribute__((malloc))
#    define DLP_ALLOC_SIZE(n) __attribute__((alloc_size(n)))
#    define DLP_ALLOC_SIZE_2(n, m) __attribute__((alloc_size(n, m)))
#    define DLP_NODISCARD __attribute__((warn_unused_result))
#    define DLP_CONSTRUCTOR __attribute__((constructor))
#    define DLP_DESTRUCTOR __attribute__((destructor))
#    define DLP_TYPE_COMPAT_P(x, y) __builtin_types_compatible_p(x, y)
#    define DLP_ASSERT_TYPE_COMPAT(x, y)                                       \
        _Static_assert(DLP_TYPE_COMPAT_P(x, y), "incompatible types")
#else
#    define DLP_MALLOC
#    define DLP_ALLOC_SIZE(n)
#    define DLP_ALLOC_SIZE_2(n, m)
#    define DLP_NODISCARD
#    define DLP_CONSTRUCTOR _Static_assert(false, "fix DLP_CONSTRUCTOR");
#    define DLP_DESTRUCTOR _Static_assert(false, "fix DLP_DESTRUCTOR");
#    define DLP_TYPE_COMPAT_P(x, y)                                            \
        (sizeof(x) == sizeof(y) && _Alignof(x) == _Alignof(y))
#    define DLP_ASSERT_TYPE_COMPAT(x, y)                                       \
        _Static_assert(DLP_TYPE_COMPAT_P(x, y), "incompatible types")
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

DLP_ASSERT_TYPE_COMPAT(gchar, char);
DLP_ASSERT_TYPE_COMPAT(guchar, unsigned char);
DLP_ASSERT_TYPE_COMPAT(gshort, short);
DLP_ASSERT_TYPE_COMPAT(gushort, unsigned short);
DLP_ASSERT_TYPE_COMPAT(gint, int);
DLP_ASSERT_TYPE_COMPAT(gint8, int8_t);
DLP_ASSERT_TYPE_COMPAT(gint16, int16_t);
DLP_ASSERT_TYPE_COMPAT(gint32, int32_t);
DLP_ASSERT_TYPE_COMPAT(gint64, int64_t);
DLP_ASSERT_TYPE_COMPAT(gintptr, intptr_t);
DLP_ASSERT_TYPE_COMPAT(guint, unsigned int);
DLP_ASSERT_TYPE_COMPAT(guint8, uint8_t);
DLP_ASSERT_TYPE_COMPAT(guint16, uint16_t);
DLP_ASSERT_TYPE_COMPAT(guint32, uint32_t);
DLP_ASSERT_TYPE_COMPAT(guint64, uint64_t);
DLP_ASSERT_TYPE_COMPAT(guintptr, uintptr_t);
DLP_ASSERT_TYPE_COMPAT(glong, long);
DLP_ASSERT_TYPE_COMPAT(gulong, unsigned long);
DLP_ASSERT_TYPE_COMPAT(gsize, size_t);
DLP_ASSERT_TYPE_COMPAT(gssize, ssize_t);
DLP_ASSERT_TYPE_COMPAT(gfloat, float);
DLP_ASSERT_TYPE_COMPAT(gdouble, double);
DLP_ASSERT_TYPE_COMPAT(gpointer, void *);
DLP_ASSERT_TYPE_COMPAT(gconstpointer, const void *);

#endif /* DLP_H */

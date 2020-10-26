/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef TEST_H
#define TEST_H

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>
#include <glib.h>

#define TEST_ARRAY_LEN(a) (sizeof(a) / sizeof(*(a)))

#define TEST_ASSERT_ERR(err, c, ...)                                           \
    do {                                                                       \
        gchar *err_pattern = g_strdup_printf(__VA_ARGS__);                     \
        assert_non_null(err);                                                  \
        g_print("[%d] %s\n", (err)->code, (err)->message);                     \
        assert_int_equal((err)->code, c);                                      \
        assert_true(g_pattern_match_simple(err_pattern, (err)->message));      \
        g_free(err_pattern);                                                   \
        g_error_free(err);                                                     \
    } while (0)

#define TEST_ASSERT_FD_CONTENT(fd, ...)                                        \
    do {                                                                       \
        struct stat fd_s;                                                      \
        gchar *fd_str = g_strdup_printf(__VA_ARGS__);                          \
        assert_int_equal(fstat(fd, &fd_s), 0);                                 \
        if (g_strcmp0(fd_str, "") == 0) {                                      \
            assert_int_equal(fd_s.st_size, 0);                                 \
        } else {                                                               \
            rsize_t fd_size;                                                   \
            ssize_t fd_ssize;                                                  \
            gchar *fd_content;                                                 \
                                                                               \
            assert_int_equal(lseek(fd, 0, SEEK_SET), 0);                       \
            assert_false(dlp_overflow_add(fd_s.st_size, 0, &fd_ssize));        \
            assert_false(dlp_overflow_add(fd_s.st_size, 1, &fd_size));         \
            assert_true(fd_size <= RSIZE_MAX);                                 \
                                                                               \
            fd_content = g_malloc0(fd_size);                                   \
            assert_int_equal(read(fd, fd_content, fd_size), fd_ssize);         \
            assert_string_equal(fd_content, fd_str);                           \
            g_free(fd_content);                                                \
            assert_int_equal(lseek(fd, 0, SEEK_SET), 0);                       \
        }                                                                      \
        g_free(fd_str);                                                        \
    } while (0)

#endif /* TEST_H */

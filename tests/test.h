/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef TEST_H
#define TEST_H

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <sys/stat.h>

#include <cmocka.h>
#include <curl/curl.h>
#include <gio/gio.h>
#include <glib.h>
#include <gpgme.h>

#include "dlp.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

#define TEST_ARRAY_LEN(a) (sizeof(a) / sizeof(*(a)))

#define TEST_ASSERT_ERR(err, c, ...)                                           \
    do {                                                                       \
        gchar *err_pattern = g_strdup_printf(__VA_ARGS__);                     \
        assert_non_null(err);                                                  \
        g_print("[%d] %s\n", (err)->code, (err)->message);                     \
        assert_int_equal((err)->code, c);                                      \
        assert_true(g_pattern_match_simple(err_pattern, (err)->message));      \
        dlp_mem_free(&err_pattern);                                            \
        g_error_free(err);                                                     \
        err = NULL;                                                            \
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
            fd_content = dlp_mem_alloc(fd_size);                               \
            assert_int_equal(read(fd, fd_content, fd_size), fd_ssize);         \
            assert_string_equal(fd_content, fd_str);                           \
            dlp_mem_free(&fd_content);                                         \
            assert_int_equal(lseek(fd, 0, SEEK_SET), 0);                       \
        }                                                                      \
        dlp_mem_free(&fd_str);                                                 \
    } while (0)

#define test_wrap_push(fn, wrp, value)                                         \
    test_wrap_push_impl("__wrap_" #fn, wrp, value)
#define test_wrap_pop(def) test_wrap_pop_impl(__func__, def)

struct test_wrap;

bool test_wrap_p(void) DLP_NODISCARD;
void test_wrap_push_impl(const char *fn, bool wrap, void *value);
bool test_wrap_pop_impl(const char *fn, struct test_wrap *elt);
bool test_setup_home(char **path) DLP_NODISCARD;

uid_t __wrap_getuid(void);
uid_t __real_getuid(void);

uid_t __wrap_getgid(void);
uid_t __real_getgid(void);

int __wrap_close(int fd);
int __real_close(int fd);

int __wrap_unlink(const char *path);
int __real_unlink(const char *path);

int __wrap_unlinkat(int fd, const char *path, int flag);
int __real_unlinkat(int fd, const char *path, int flag);

int __wrap___xstat64(int ver, const char *path, struct stat *s);
int __real___xstat64(int ver, const char *path, struct stat *s);

int __wrap___fxstat64(int ver, int fd, struct stat *s);
int __real___fxstat64(int ver, int fd, struct stat *s);

int __wrap___fxstatat64(int ver, int fd, const char *path, struct stat *s,
                        int flag);
int __real___fxstatat64(int ver, int fd, const char *path, struct stat *s,
                        int flag);

char *__wrap_mkdtemp(char *template);
char *__real_mkdtemp(char *template);

int __wrap_mkstemp64(char *template);
int __real_mkstemp64(char *template);

DIR *__wrap_fdopendir(int fd);
DIR *__real_fdopendir(int fd);

int __wrap_closedir(DIR *dir);
int __real_closedir(DIR *dir);

struct dirent *__wrap_readdir64(DIR *dir);
struct dirent *__real_readdir64(DIR *dir);

CURLcode __wrap_curl_global_init(long flags);
CURLcode __real_curl_global_init(long flags);

CURL *__wrap_curl_easy_init(void);
CURL *__real_curl_easy_init(void);

const char *__wrap_gpgme_check_version_internal(const char *req_version,
                                                size_t offset);
const char *__real_gpgme_check_version_internal(const char *req_version,
                                                size_t offset);

gpgme_error_t __wrap_gpgme_engine_check_version(gpgme_protocol_t proto);
gpgme_error_t __real_gpgme_engine_check_version(gpgme_protocol_t proto);

gpgme_error_t __wrap_gpgme_new(gpgme_ctx_t *ctx);
gpgme_error_t __real_gpgme_new(gpgme_ctx_t *ctx);

gpgme_protocol_t __wrap_gpgme_get_protocol(gpgme_ctx_t ctx);
gpgme_protocol_t __real_gpgme_get_protocol(gpgme_ctx_t ctx);

int __wrap_gpgme_strerror_r(gpg_error_t err, char *buf, size_t buflen);
int __real_gpgme_strerror_r(gpg_error_t err, char *buf, size_t buflen);

gpgme_error_t __wrap_gpgme_data_new_from_fd(gpgme_data_t *dh, int fd);
gpgme_error_t __real_gpgme_data_new_from_fd(gpgme_data_t *dh, int fd);

gpgme_engine_info_t __wrap_gpgme_ctx_get_engine_info(gpgme_ctx_t ctx);
gpgme_engine_info_t __real_gpgme_ctx_get_engine_info(gpgme_ctx_t ctx);

gpgme_error_t __wrap_gpgme_op_verify(gpgme_ctx_t ctx, gpgme_data_t sig,
                                     gpgme_data_t signed_text,
                                     gpgme_data_t plaintext);
gpgme_error_t __real_gpgme_op_verify(gpgme_ctx_t ctx, gpgme_data_t sig,
                                     gpgme_data_t signed_text,
                                     gpgme_data_t plaintext);

gpgme_verify_result_t __wrap_gpgme_op_verify_result(gpgme_ctx_t ctx);
gpgme_verify_result_t __real_gpgme_op_verify_result(gpgme_ctx_t ctx);

gpgme_error_t __wrap_gpgme_get_key(gpgme_ctx_t ctx, const char *fpr,
                                   gpgme_key_t *r_key, int secret);
gpgme_error_t __real_gpgme_get_key(gpgme_ctx_t ctx, const char *fpr,
                                   gpgme_key_t *r_key, int secret);

gpgme_error_t __wrap_gpgme_op_keylist_start(gpgme_ctx_t ctx,
                                            const char *pattern,
                                            int secret_only);
gpgme_error_t __real_gpgme_op_keylist_start(gpgme_ctx_t ctx,
                                            const char *pattern,
                                            int secret_only);

gpgme_error_t __wrap_gpgme_op_keylist_next(gpgme_ctx_t ctx, gpgme_key_t *r_key);
gpgme_error_t __real_gpgme_op_keylist_next(gpgme_ctx_t ctx, gpgme_key_t *r_key);

gpgme_error_t __wrap_gpgme_op_import(gpgme_ctx_t ctx, gpgme_data_t keydata);
gpgme_error_t __real_gpgme_op_import(gpgme_ctx_t ctx, gpgme_data_t keydata);

gpgme_import_result_t __wrap_gpgme_op_import_result(gpgme_ctx_t ctx);
gpgme_import_result_t __real_gpgme_op_import_result(gpgme_ctx_t ctx);

gboolean __wrap_g_subprocess_communicate_utf8(GSubprocess *proc, const char *in,
                                              GCancellable *cancellable,
                                              char **out, char **err,
                                              GError **error);
gboolean __real_g_subprocess_communicate_utf8(GSubprocess *proc, const char *in,
                                              GCancellable *cancellable,
                                              char **out, char **err,
                                              GError **error);

gboolean __wrap_g_subprocess_wait_check(GSubprocess *proc,
                                        GCancellable *cancellable,
                                        GError **error);
gboolean __real_g_subprocess_wait_check(GSubprocess *proc,
                                        GCancellable *cancellable,
                                        GError **error);

GTokenType __wrap_g_scanner_peek_next_token(GScanner *scanner);
GTokenType __real_g_scanner_peek_next_token(GScanner *scanner);

gpointer __wrap_g_bytes_unref_to_data(GBytes *bytes, gsize *size);
gpointer __real_g_bytes_unref_to_data(GBytes *bytes, gsize *size);

GResource *__wrap_g_static_resource_get_resource(GStaticResource *resource);
GResource *__real_g_static_resource_get_resource(GStaticResource *resource);

gchar *__wrap_g_strdup(const gchar *str) G_GNUC_MALLOC;
gchar *__real_g_strdup(const gchar *str) G_GNUC_MALLOC;

gboolean __wrap_g_key_file_load_from_data(GKeyFile *key_file, const gchar *data,
                                          gsize length, GKeyFileFlags flags,
                                          GError **error);
gboolean __real_g_key_file_load_from_data(GKeyFile *key_file, const gchar *data,
                                          gsize length, GKeyFileFlags flags,
                                          GError **error);

gchar *__wrap_g_key_file_get_value(GKeyFile *key_file, const gchar *group_name,
                                   const gchar *key,
                                   GError **error) G_GNUC_MALLOC;
gchar *__real_g_key_file_get_value(GKeyFile *key_file, const gchar *group_name,
                                   const gchar *key,
                                   GError **error) G_GNUC_MALLOC;

#endif /* TEST_H */

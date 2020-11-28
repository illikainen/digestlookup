/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "test.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dlp_fs.h"

struct test_wrap {
    const char *fn;
    bool wrap;
    void *value;
};

static GList *test_wrap_list;

/**
 * Setup a per-test home directory.
 *
 * HOME must be set before glib is used because g_get_home_dir() caches the
 * home directory.
 *
 * This function may be called multiple times (e.g. by multiple fixtures within
 * the same test suite).  However, subsequent invocations simply get the same
 * value of HOME since glib can't easily be made to invalidate its cached HOME
 * directory.
 *
 * NOTE: GLib >= 2.60 supports G_TEST_OPTION_ISOLATE_DIRS.
 */
bool test_setup_home(char **path)
{
    char *p;

    if ((p = getenv("DLP_TEST_HOME")) != NULL) {
        if ((p = strdup(p)) == NULL || g_strcmp0(p, getenv("HOME")) != 0 ||
            g_strcmp0(p, g_get_home_dir()) != 0 || !dlp_fs_mkdir(p, NULL)) {
            free(p);
            return false;
        }
    } else {
        int rv;

        p = malloc(PATH_MAX);
        if (p == NULL) {
            return false;
        }

        rv = snprintf(p, PATH_MAX, "%s/XXXXXX", BUILD_DIR);
        if (rv <= 0 || rv >= PATH_MAX) {
            free(p);
            return false;
        }

        if (mkdtemp(p) == NULL) {
            free(p);
            return false;
        }

        if (setenv("HOME", p, 1) != 0 || setenv("DLP_TEST_HOME", p, 1) != 0) {
            free(p);
            return false;
        }

        if (g_strcmp0(g_get_home_dir(), p) != 0) {
            free(p);
            return false;
        }
    }

    if (path != NULL) {
        *path = p;
    } else {
        free(p);
    }

    return true;
}

bool test_wrap_p(void)
{
#ifdef TEST_WRAP
    return true;
#else
    return false;
#endif
}

void test_wrap_push_impl(const char *fn, bool wrap, void *value)
{
    if (test_wrap_p()) {
        struct test_wrap *elt;

        elt = dlp_mem_alloc(sizeof(*elt));
        elt->fn = fn;
        elt->wrap = wrap;
        elt->value = value;
        test_wrap_list = g_list_prepend(test_wrap_list, elt);
    }
}

bool test_wrap_pop_impl(const char *fn, struct test_wrap *elt)
{
    GList *cur;
    struct test_wrap *w;

    if (test_wrap_p()) {
        for (cur = test_wrap_list; cur != NULL; cur = cur->next) {
            w = cur->data;
            if (g_strcmp0(w->fn, fn) == 0) {
                elt->fn = w->fn;
                elt->wrap = w->wrap;
                elt->value = w->value;
                test_wrap_list = g_list_remove(test_wrap_list, w);
                dlp_mem_free(&w);
                return true;
            }
        }
    }

    return false;
}

#ifdef TEST_WRAP

/* cppcheck-suppress unusedFunction */
uid_t __wrap_getuid(void)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(uid_t *)elt.value;
    }
    return __real_getuid();
}

/* cppcheck-suppress unusedFunction */
uid_t __wrap_getgid(void)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gid_t *)elt.value;
    }
    return __real_getgid();
}

/* cppcheck-suppress unusedFunction */
int __wrap_close(int fd)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real_close(fd);
}

/* cppcheck-suppress unusedFunction */
ssize_t __wrap_read(int fd, void *buf, size_t len)
{
    gint32 rv;
    guint32 ln;
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        if (g_variant_dict_lookup(elt.value, "errno", "i", &errno) &&
            g_variant_dict_lookup(elt.value, "rv", "i", &rv)) {
            return rv;
        }

        if (g_variant_dict_lookup(elt.value, "len", "u", &ln)) {
            return __real_read(fd, buf, ln);
        }

        g_error("unhandled spec");
    }
    return __real_read(fd, buf, len);
}

/* cppcheck-suppress unusedFunction */
ssize_t __wrap_write(int fd, void *buf, size_t len)
{
    gint32 rv;
    guint32 ln;
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        if (g_variant_dict_lookup(elt.value, "errno", "i", &errno) &&
            g_variant_dict_lookup(elt.value, "rv", "i", &rv)) {
            return rv;
        }

        if (g_variant_dict_lookup(elt.value, "len", "u", &ln)) {
            if (ln > 0) {
                return __real_write(fd, buf, ln);
            }
            return ln;
        }

        g_error("unhandled spec");
    }
    return __real_write(fd, buf, len);
}

/* cppcheck-suppress unusedFunction */
int __wrap___xstat64(int ver, const char *path, struct stat *s)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real___xstat64(ver, path, s);
}

/* cppcheck-suppress unusedFunction */
int __wrap___fxstat64(int ver, int fd, struct stat *s)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real___fxstat64(ver, fd, s);
}

/* cppcheck-suppress unusedFunction */
int __wrap___fxstatat64(int ver, int fd, const char *path, struct stat *s,
                        int flag)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real___fxstatat64(ver, fd, path, s, flag);
}

/* cppcheck-suppress unusedFunction */
int __wrap_unlink(const char *path)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real_unlink(path);
}

/* cppcheck-suppress unusedFunction */
int __wrap_unlinkat(int fd, const char *path, int flag)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real_unlinkat(fd, path, flag);
}

/* cppcheck-suppress unusedFunction */
char *__wrap_mkdtemp(char *template)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return NULL;
    }
    return __real_mkdtemp(template);
}

/* cppcheck-suppress unusedFunction */
int __wrap_mkstemp64(char *template)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real_mkstemp64(template);
}

/* cppcheck-suppress unusedFunction */
DIR *__wrap_fdopendir(int fd)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return NULL;
    }
    return __real_fdopendir(fd);
}

/* cppcheck-suppress unusedFunction */
struct dirent *__wrap_readdir64(DIR *dir)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        errno = *(errno_t *)elt.value;
        return NULL;
    }
    return __real_readdir64(dir);
}

/* cppcheck-suppress unusedFunction */
int __wrap_closedir(DIR *dir)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        __real_closedir(dir); /* for the leak sanitizer */
        errno = *(errno_t *)elt.value;
        return -1;
    }
    return __real_closedir(dir);
}

/* cppcheck-suppress unusedFunction */
CURLcode __wrap_curl_global_init(long flags)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(CURLcode *)elt.value;
    }
    return __real_curl_global_init(flags);
}

/* cppcheck-suppress unusedFunction */
CURL *__wrap_curl_easy_init(void)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_curl_easy_init();
}

/* cppcheck-suppress unusedFunction */
const char *__wrap_gpgme_check_version_internal(const char *req_version,
                                                size_t offset)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_gpgme_check_version_internal(req_version, offset);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_engine_check_version(gpgme_protocol_t proto)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_engine_check_version(proto);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_new(gpgme_ctx_t *ctx)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_new(ctx);
}

/* cppcheck-suppress unusedFunction */
gpgme_protocol_t __wrap_gpgme_get_protocol(gpgme_ctx_t ctx)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_protocol_t *)elt.value;
    }
    return __real_gpgme_get_protocol(ctx);
}

/* cppcheck-suppress unusedFunction */
int __wrap_gpgme_strerror_r(gpg_error_t err, char *buf, size_t buflen)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(int *)elt.value;
    }
    return __real_gpgme_strerror_r(err, buf, buflen);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_data_new_from_fd(gpgme_data_t *dh, int fd)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_data_new_from_fd(dh, fd);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_data_new_from_mem(gpgme_data_t *dh, const char *buf,
                                             size_t size, int copy)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_data_new_from_mem(dh, buf, size, copy);
}

/* cppcheck-suppress unusedFunction */
gpgme_engine_info_t __wrap_gpgme_ctx_get_engine_info(gpgme_ctx_t ctx)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_gpgme_ctx_get_engine_info(ctx);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_op_verify(gpgme_ctx_t ctx, gpgme_data_t sig,
                                     gpgme_data_t signed_text,
                                     gpgme_data_t plaintext)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_op_verify(ctx, sig, signed_text, plaintext);
}

/* cppcheck-suppress unusedFunction */
gpgme_verify_result_t __wrap_gpgme_op_verify_result(gpgme_ctx_t ctx)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_gpgme_op_verify_result(ctx);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_get_key(gpgme_ctx_t ctx, const char *fpr,
                                   gpgme_key_t *r_key, int secret)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        *r_key = elt.value;
        return GPG_ERR_NO_ERROR;
    }
    return __real_gpgme_get_key(ctx, fpr, r_key, secret);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_op_keylist_start(gpgme_ctx_t ctx,
                                            const char *pattern,
                                            int secret_only)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_op_keylist_start(ctx, pattern, secret_only);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_op_keylist_next(gpgme_ctx_t ctx, gpgme_key_t *r_key)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_op_keylist_next(ctx, r_key);
}

/* cppcheck-suppress unusedFunction */
gpgme_error_t __wrap_gpgme_op_import(gpgme_ctx_t ctx, gpgme_data_t keydata)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return *(gpgme_error_t *)elt.value;
    }
    return __real_gpgme_op_import(ctx, keydata);
}

/* cppcheck-suppress unusedFunction */
gpgme_import_result_t __wrap_gpgme_op_import_result(gpgme_ctx_t ctx)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_gpgme_op_import_result(ctx);
}

/* cppcheck-suppress unusedFunction */
gboolean __wrap_g_subprocess_communicate_utf8(GSubprocess *proc, const char *in,
                                              GCancellable *cancellable,
                                              char **out, char **err,
                                              GError **error)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        g_set_error(error, G_SPAWN_ERROR, 123, "%s", elt.value);
        return false;
    }
    return __real_g_subprocess_communicate_utf8(proc, in, cancellable, out, err,
                                                error);
}

/* cppcheck-suppress unusedFunction */
gboolean __wrap_g_subprocess_wait_check(GSubprocess *proc,
                                        GCancellable *cancellable,
                                        GError **error)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        g_set_error(error, G_SPAWN_ERROR, 123, "%s", elt.value);
        return false;
    }
    return __real_g_subprocess_wait_check(proc, cancellable, error);
}

/* cppcheck-suppress unusedFunction */
GTokenType __wrap_g_scanner_peek_next_token(GScanner *scanner)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        scanner->next_token = *(GTokenType *)elt.value;
        scanner->next_value.v_error = G_ERR_UNKNOWN;
        return scanner->next_token;
    }
    return __real_g_scanner_peek_next_token(scanner);
}

/* cppcheck-suppress unusedFunction */
gpointer __wrap_g_bytes_unref_to_data(GBytes *bytes, gsize *size)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        if (elt.value == NULL) {
            *size = 0;
            return NULL;
        }
        *size = strlen(elt.value);
        return elt.value;
    }
    return __real_g_bytes_unref_to_data(bytes, size);
}

/* cppcheck-suppress unusedFunction */
GResource *__wrap_g_static_resource_get_resource(GStaticResource *resource)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_g_static_resource_get_resource(resource);
}

/* cppcheck-suppress unusedFunction */
gchar *__wrap_g_strdup(const gchar *str)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_g_strdup(str);
}

/* cppcheck-suppress unusedFunction */
gboolean __wrap_g_key_file_load_from_data(GKeyFile *key_file, const gchar *data,
                                          gsize length, GKeyFileFlags flags,
                                          GError **error)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return GPOINTER_TO_INT(elt.value);
    }
    return __real_g_key_file_load_from_data(key_file, data, length, flags,
                                            error);
}

/* cppcheck-suppress unusedFunction */
gchar *__wrap_g_key_file_get_value(GKeyFile *key_file, const gchar *group_name,
                                   const gchar *key, GError **error)
{
    struct test_wrap elt = { 0 };

    if (test_wrap_pop(&elt) && elt.wrap) {
        return elt.value;
    }
    return __real_g_key_file_get_value(key_file, group_name, key, error);
}

#endif /* TEST_WRAP */

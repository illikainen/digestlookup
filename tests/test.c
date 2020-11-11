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

#endif /* TEST_WRAP */

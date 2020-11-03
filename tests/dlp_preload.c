/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>
#include <glib.h>

#include "dlp_overflow.h"

typedef DIR *(*fdopendir_fn)(int fd);
typedef struct dirent *(*readdir_fn)(DIR *dir);
typedef int (*closedir_fn)(DIR *dir);
typedef uid_t (*getuid_fn)(void);
typedef uid_t (*getgid_fn)(void);
typedef char *(*mkdtemp_fn)(char *template);
typedef int (*unlinkat_fn)(int fd, const char *path, int flag);
typedef int (*__fxstat_fn)(int ver, int fd, struct stat *s);
typedef int (*__fxstatat_fn)(int ver, int fd, const char *path, struct stat *s,
                             int flag);
typedef int (*__xstat_fn)(int ver, const char *path, struct stat *s);
typedef CURL *(*curl_easy_init_fn)(void);
typedef CURLcode (*curl_global_init_fn)(long flags);

static void *dlp_preload_sym(const char *sym)
{
    void *fn;

    if ((fn = dlsym(RTLD_NEXT, sym)) == NULL) {
        fprintf(stderr, "ERROR: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    return fn;
}

static bool dlp_preload_get_env(const char *name, char **value)
{
    GString *str;
    char *env;

    str = g_string_new(NULL);
    g_string_printf(str, "DLP_PRELOAD_%s", name);
    g_string_ascii_up(str);
    env = g_string_free(str, false);

    *value = g_strdup(getenv(env));
    g_free(env);
    return *value != NULL;
}

static bool dlp_preload_get_ll(const char *name, long long *value)
{
    char *str;

    if (dlp_preload_get_env(name, &str)) {
        long long ll;
        char *end = NULL;

        errno = 0;
        ll = strtoll(str, &end, 10);
        if ((errno == 0 || (ll != 0 && ll != LONG_MIN && ll != LONG_MAX)) &&
            end != str && end != NULL && *end == '\0') {
            *value = ll;
            g_free(str);
            return true;
        }
        g_free(str);
    }
    return false;
}

static bool dlp_preload_get_int(const char *name, int *value)
{
    long long ll;

    return dlp_preload_get_ll(name, &ll) && !dlp_overflow_add(ll, 0, value);
}

static bool dlp_preload_get_uid(const char *name, uid_t *value)
{
    long long ll;

    return dlp_preload_get_ll(name, &ll) && !dlp_overflow_add(ll, 0, value);
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
DIR *fdopendir(int fd)
{
    static fdopendir_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (fdopendir_fn)dlp_preload_sym("fdopendir");
    }

    if (dlp_preload_get_int("fdopendir_rv", &rv) && rv != 0) {
        errno = EACCES;
        return NULL;
    }

    return fn(fd);
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
struct dirent *readdir(DIR *dir)
{
    static readdir_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (readdir_fn)dlp_preload_sym("readdir");
    }

    if (dlp_preload_get_int("readdir_rv", &rv) && rv != 0) {
        errno = EOVERFLOW;
        return NULL;
    }

    return fn(dir);
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
int closedir(DIR *dir)
{
    static closedir_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (closedir_fn)dlp_preload_sym("closedir");
    }

    if (dlp_preload_get_int("closedir_rv", &rv)) {
        fn(dir); /* for the leak sanitizer */
        errno = EACCES;
        return rv;
    }

    return fn(dir);
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
uid_t getuid(void)
{
    static getuid_fn fn;
    uid_t rv;

    if (fn == NULL) {
        fn = (getuid_fn)dlp_preload_sym("getuid");
    }

    if (dlp_preload_get_uid("getuid_rv", &rv)) {
        return rv;
    }

    return fn();
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
uid_t getgid(void)
{
    static getgid_fn fn;
    uid_t rv;

    if (fn == NULL) {
        fn = (getgid_fn)dlp_preload_sym("getgid");
    }

    if (dlp_preload_get_uid("getgid_rv", &rv)) {
        return rv;
    }

    return fn();
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
char *mkdtemp(char *template)
{
    static mkdtemp_fn fn;
    error_t err;

    if (fn == NULL) {
        fn = (mkdtemp_fn)dlp_preload_sym("mkdtemp");
    }

    if (dlp_preload_get_int("mkdtemp_errno", &err)) {
        errno = err;
        return NULL;
    }

    return fn(template);
}

/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
int unlinkat(int fd, const char *path, int flag)
{
    static unlinkat_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (unlinkat_fn)dlp_preload_sym("unlinkat");
    }

    if (dlp_preload_get_int("unlinkat_rv", &rv)) {
        errno = EACCES;
        return rv;
    }

    return fn(fd, path, flag);
}

/* cppcheck-suppress unusedFunction */
/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
int __fxstat(int ver, int fd, struct stat *s)
{
    static __fxstat_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (__fxstat_fn)dlp_preload_sym("__fxstat");
    }

    if (dlp_preload_get_int("fstat_rv", &rv)) {
        errno = EACCES;
        return rv;
    }

    return fn(ver, fd, s);
}

/* cppcheck-suppress unusedFunction */
/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
int __fxstatat(int ver, int fd, const char *path, struct stat *s, int flag)
{
    static __fxstatat_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (__fxstatat_fn)dlp_preload_sym("__fxstatat");
    }

    if (dlp_preload_get_int("fstatat_rv", &rv)) {
        errno = EACCES;
        return rv;
    }

    return fn(ver, fd, path, s, flag);
}

/* cppcheck-suppress unusedFunction */
/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
int __xstat(int ver, const char *path, struct stat *s)
{
    static __xstat_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (__xstat_fn)dlp_preload_sym("__xstat");
    }

    if (dlp_preload_get_int("stat_rv", &rv)) {
        errno = EACCES;
        return rv;
    }

    return fn(ver, path, s);
}

CURL *curl_easy_init(void)
{
    static curl_easy_init_fn fn;
    int rv;

    if (fn == NULL) {
        fn = (curl_easy_init_fn)dlp_preload_sym("curl_easy_init");
    }

    if (dlp_preload_get_int("curl_easy_init_rv", &rv)) {
        return NULL;
    }

    return fn();
}

CURLcode curl_global_init(long flags)
{
    static curl_global_init_fn fn;
    CURLcode cc;
    int rv;

    if (fn == NULL) {
        fn = (curl_global_init_fn)dlp_preload_sym("curl_global_init");
    }

    if (dlp_preload_get_int("curl_global_init_rv", &rv) &&
        !dlp_overflow_add(rv, 0, &cc)) {
        return cc;
    }

    return fn(flags);
}

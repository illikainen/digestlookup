/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "test.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "dlp_fs.h"

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

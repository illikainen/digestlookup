/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "test.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Setup a per-test home directory.
 *
 * This function must be called before glib is used because g_get_home_dir()
 * caches the home directory.
 */
bool test_setup_home(char **path)
{
    char *p;
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

    if (setenv("HOME", p, 1) != 0) {
        free(p);
        return false;
    }

    if (g_strcmp0(g_get_home_dir(), p) != 0) {
        free(p);
        return false;
    }

    if (path != NULL) {
        *path = p;
    } else {
        free(p);
    }

    return true;
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_fs.h"

#include <errno.h>

#include <sys/stat.h>
#include <unistd.h>

#include <glib/gi18n.h>

#include "config.h"
#include "dlp_error.h"

static bool dlp_fs_user_dir(const char *base, char **path, GError **error);

/**
 * Recursively create a directory if it doesn't exist.
 *
 * @param path  Directory to create.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_mkdir(const char *path, GError **error)
{
    struct stat s;

    g_return_val_if_fail(path != NULL, false);

    errno = 0;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (g_mkdir_with_parents(path, S_IRWXU) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    errno = 0;
    if (stat(path, &s) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    if ((s.st_uid != getuid() && s.st_uid != 0) ||
        (s.st_gid != getgid() && s.st_gid != 0) ||
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        (s.st_mode & S_IWGRP || s.st_mode & S_IWOTH)) {
        g_set_error(error, DLP_ERROR, DLP_FS_ERROR_FAILED, "%s: %s", path,
                    _("invalid permission"));
        return false;
    }

    return true;
}

/**
 * Retrieve a per-user cache directory.
 *
 * The directory is created if it doesn't exist.
 *
 * @param path  Cache directory that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_cache_dir(char **path, GError **error)
{
    return dlp_fs_user_dir(g_get_user_cache_dir(), path, error);
}

/**
 * Retrieve a per-user config directory.
 *
 * The directory is created if it doesn't exist.
 *
 * @param path  Config directory that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_config_dir(char **path, GError **error)
{
    return dlp_fs_user_dir(g_get_user_config_dir(), path, error);
}

/**
 * Retrieve a per-user data directory.
 *
 * The directory is created if it doesn't exist.
 *
 * @param path  Data directory that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_data_dir(char **path, GError **error)
{
    return dlp_fs_user_dir(g_get_user_data_dir(), path, error);
}

/**
 * Retrieve a per-user directory with a given base.
 *
 * The directory is created if it doesn't exist.
 *
 * @param base  Prefix for the path.
 * @param path  Path that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_fs_user_dir(const char *base, char **path, GError **error)
{
    g_return_val_if_fail(base != NULL && path != NULL, false);

    *path = g_build_filename(base, PROJECT_NAME, NULL);
    if (!dlp_fs_mkdir(*path, error)) {
        g_free(*path);
        *path = NULL;
        return false;
    }

    return true;
}

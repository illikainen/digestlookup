/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_fs.h"

#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <glib/gi18n.h>

#include "config.h"
#include "dlp_error.h"

static bool dlp_fs_user_dir(const char *base, char **path, GError **error);
static bool dlp_fs_walk_do(int fd, const char *path, dlp_fs_walk_cb cb,
                           void *data, GError **error);

/**
 * Traverse a file hierarchy.
 *
 * @param path  Beginning of the walk.
 * @param cb    Callback to invoke for each element in the tree.  Ownership is
 *              retained for every argument other than the user-provided data.
 * @param data  User data to pass to the callback.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_walk(const char *path, dlp_fs_walk_cb cb, void *data,
                 GError **error)
{
    static GMutex lock;
    struct stat s;
    int fd;
    bool rv;

    g_return_val_if_fail(path != NULL && cb != NULL, false);

    errno = 0;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    errno = 0;
    if (fstat(fd, &s) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        close(fd); /* return code ignored */
        return false;
    }

    g_mutex_lock(&lock);
    rv = dlp_fs_walk_do(fd, path, cb, data, error) &&
         cb(AT_FDCWD, path, path, &s, data, error);
    g_mutex_unlock(&lock);

    return rv;
}

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

/**
 * Traverse a file hierarchy.
 *
 * @param fd    Directory file descriptor.  Ownership is transferred; any
 *              attempt to close it or modify its state is undefined behavior,
 *              see POSIX.1-2017 on fdopendir.
 * @param path  Current filename relative to the beginning of the walk.
 * @param cb    Callback to invoke for each element in the tree.  Ownership is
 *              retained for every argument other than the user-provided data.
 * @param data  User data to pass to the callback.
 * @return True on success and false on failure.
 */
static bool dlp_fs_walk_do(int fd, const char *path, dlp_fs_walk_cb cb,
                           void *data, GError **error)
{
    DIR *dir;
    int cfd;
    char *walkpath;
    struct stat s;
    struct dirent *de;

    errno = 0;
    if ((dir = fdopendir(fd)) == NULL) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    /* cppcheck-suppress readdirCalled */
    while ((errno = 0) == 0 && (de = readdir(dir)) != NULL) {
        if (!g_strcmp0(de->d_name, ".") || !g_strcmp0(de->d_name, "..")) {
            continue;
        }

        walkpath = g_build_filename(path, de->d_name, NULL);

        errno = 0;
        if (fstatat(fd, de->d_name, &s, AT_SYMLINK_NOFOLLOW) != 0) {
            g_set_error(error, DLP_ERROR, errno, "%s: %s", walkpath,
                        g_strerror(errno));
            g_free(walkpath);
            closedir(dir); /* return code ignored */
            return false;
        }

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        if (S_ISDIR(s.st_mode)) {
            errno = 0;
            /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
            cfd = openat(fd, de->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (cfd == -1) {
                g_set_error(error, DLP_ERROR, errno, "%s: %s", walkpath,
                            g_strerror(errno));
                g_free(walkpath);
                closedir(dir); /* return code ignored */
                return false;
            }

            if (!dlp_fs_walk_do(cfd, walkpath, cb, data, error)) {
                g_free(walkpath);
                closedir(dir); /* return code ignored */
                return false;
            }
        }

        if (!cb(fd, de->d_name, walkpath, &s, data, error)) {
            g_free(walkpath);
            closedir(dir); /* return code ignored */
            return false;
        }

        g_free(walkpath);
    }

    errno = 0;
    if (closedir(dir) != 0) {
        if (error != NULL && *error == NULL) {
            g_set_error(error, DLP_ERROR, errno, "%s: %s", path,
                        g_strerror(errno));
        }
        return false;
    }
    return true;
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_fs.h"

#include <errno.h>
#include <stdarg.h>

#include <fcntl.h>
#include <unistd.h>

#include <glib/gi18n.h>

#include "config.h"
#include "dlp_error.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

static bool dlp_fs_user_dir(const char *base, char **path,
                            GError **error) DLP_NODISCARD;
static bool dlp_fs_user_path(const char *base, char **path, va_list *ap,
                             GError **error) DLP_NODISCARD;
static bool dlp_fs_walk_do(int fd, const char *path, dlp_fs_walk_cb cb,
                           void *data, GError **error) DLP_NODISCARD;
static bool dlp_fs_rmdir_cb(int fd, const char *name, const char *path,
                            const struct stat *s, void *data,
                            GError **error) DLP_NODISCARD;

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
    if (!dlp_fs_open(path, O_RDONLY | O_NOFOLLOW, 0, &fd, error)) {
        return false;
    }

    errno = 0;
    if (fstat(fd, &s) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        DLP_DISCARD(dlp_fs_close(&fd, NULL));
        return false;
    }

    g_mutex_lock(&lock);
    rv = dlp_fs_walk_do(fd, path, cb, data, error) &&
         cb(AT_FDCWD, path, path, &s, data, error);
    g_mutex_unlock(&lock);

    return rv;
}

/**
 * Open a file.
 *
 * @param dfd   Directory to use for relative paths.
 * @param path  Path to open.
 * @param flags Flags to open the file with.
 * @param mode  Mode for newly created files.
 * @param fd    Output pointer for the file descriptor.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_openat(int dfd, const char *path, int flags, mode_t mode, int *fd,
                   GError **error)
{
    struct stat s;

    g_return_val_if_fail(path != NULL && fd != NULL, false);

    errno = 0;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if ((*fd = openat(dfd, path, flags | O_CLOEXEC, mode)) == -1) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    errno = 0;
    if (fstat(*fd, &s) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        DLP_DISCARD(dlp_fs_close(fd, NULL));
        return false;
    }

    if (!dlp_fs_check_stat(&s, s.st_mode & DLP_FS_TYPE, error)) {
        DLP_DISCARD(dlp_fs_close(fd, NULL));
        return false;
    }

    return true;
}

/**
 * Open a file.
 *
 * @param path  Path to open.
 * @param flags Flags to open the file with.
 * @param mode  Mode for newly created files.
 * @param fd    Output pointer for the file descriptor.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_open(const char *path, int flags, mode_t mode, int *fd,
                 GError **error)
{
    return dlp_fs_openat(AT_FDCWD, path, flags, mode, fd, error);
}

/**
 * Close a file descriptor.
 *
 * It's a noop if the file descriptor pointer is NULL or if it points to a
 * value below 0.  The pointed to descriptor is set to -1 on both success and
 * failure if the pointer is non-NULL.
 *
 * The Linux man-pages project state that it's unwise to retry close() on
 * failure because the file descriptor may have been released before the
 * failure happened and potentially reused by another thread.
 *
 * See:
 * - https://manpages.debian.org/buster/manpages-dev/close.2.en.html
 *
 * @param fd    Pointer to a file descriptor to close.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_close(int *fd, GError **error)
{
    if (fd != NULL) {
        errno = 0;
        if (*fd >= 0 && close(*fd) != 0) {
            g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
            *fd = -1;
            return false;
        }
        *fd = -1;
    }

    return true;
}

/**
 * Read from a file descriptor.
 *
 * This function tries to read a specified number of bytes while recovering
 * from EINTR.  It does not try to recover from partial reads (arithmetic on
 * void pointers is undefined behavior); instead it is considered a success if
 * the number of bytes read is in the interval [0, len].
 *
 * @param fd    File descriptor to read.
 * @param buf   Destination buffer.
 * @param len   Number of bytes to read.
 * @param res   Number of bytes that were read.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_read(int fd, void *buf, size_t len, size_t *res, GError **error)
{
    ssize_t n;

    g_return_val_if_fail(fd >= 0 && buf != NULL && res != NULL, false);
    *res = 0;

    if (len == 0 || len > SSIZE_MAX) {
        g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
        return false;
    }

    do {
        errno = 0;
        if ((n = read(fd, buf, len)) < 0) {
            if (errno != EINTR) {
                g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
                return false;
            }
        }
    } while (n < 0);

    if (dlp_overflow_add(n, 0, res) || *res > len) {
        *res = 0;
        g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
        return false;
    }

    return true;
}

/**
 * Move the position of a file descriptor.
 *
 * @param fd     File descriptor to reposition.
 * @param offset New position relative to whence.
 * @param whence Base for offset.
 * @param error  Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_seek(int fd, off_t offset, int whence, GError **error)
{
    g_return_val_if_fail(fd >= 0, false);

    errno = 0;
    if (lseek(fd, offset, whence) == -1) {
        g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
        return false;
    }

    return true;
}

/**
 * Truncate a file descriptor.
 *
 * @param fd    File descriptor to truncate.
 * @param len   New length of the file.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_truncate(int fd, off_t len, GError **error)
{
    g_return_val_if_fail(fd >= 0, false);

    errno = 0;
    if (ftruncate(fd, len) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
        return false;
    }

    return true;
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
    g_return_val_if_fail(path != NULL, false);

    errno = 0;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (g_mkdir_with_parents(path, S_IRWXU) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    if (!dlp_fs_check_path(path, DLP_FS_DIR, true, error)) {
        return false;
    }

    return true;
}

/**
 * Recursively remove a directory.
 *
 * @param path  Directory to remove.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_rmdir(const char *path, GError **error)
{
    return dlp_fs_walk(path, dlp_fs_rmdir_cb, NULL, error);
}

/**
 * Create a per-user temporary directory.
 *
 * @param path  Temporary directory that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_mkdtemp(char **path, GError **error)
{
    char *cache;
    char *tmp;

    g_return_val_if_fail(path != NULL, false);
    *path = NULL;

    if (!dlp_fs_cache_dir(&cache, error)) {
        return false;
    }

    /*
     * POSIX.1-2017 specifies that mkdtemp() should replace six or more X's.
     * Glibc 2.28 only replaces six X's but other implementations may replace
     * more.
     */
    tmp = g_build_filename(cache, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", NULL);
    dlp_mem_free(&cache);

    errno = 0;
    if ((*path = mkdtemp(tmp)) == NULL || *path != tmp) {
        g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
        g_free(tmp);
        return false;
    }

    /* cppcheck-suppress memleak
     *
     * Cppcheck believes that tmp is leaking here.  However, a pointer to
     * the same region is returned by mkdtemp() and assigned to *path, with
     * ownership transferred to the caller.
     */
    return true;
}

/**
 * Create a per-user temporary file.
 *
 * @param fd    File descriptor that must be closed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_mkstemp(int *fd, GError **error)
{
    char *cache;
    char *tmp;

    g_return_val_if_fail(fd != NULL, false);
    *fd = -1;

    if (!dlp_fs_cache_dir(&cache, error)) {
        return false;
    }

    /*
     * POSIX.1-2017 specifies that mkstemp() should replace six or more X's.
     * Glibc 2.28 only replaces six X's but other implementations may replace
     * more.
     */
    tmp = g_build_filename(cache, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", NULL);
    dlp_mem_free(&cache);

    errno = 0;
    if ((*fd = mkstemp(tmp)) == -1) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", tmp, g_strerror(errno));
        g_free(tmp);
        return false;
    }

    /*
     * The cache directory is created with S_IRWXU and mkstemp() creates the
     * file itself with S_IRUSR|S_IWUSR, so this race condition is OK.
     */
    errno = 0;
    if (unlink(tmp) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", tmp, g_strerror(errno));
        DLP_DISCARD(dlp_fs_close(fd, NULL));
        g_free(tmp);
        return false;
    }

    g_free(tmp);
    return true;
}

/**
 * Check that a path looks reasonable.
 *
 * @param path       Path to check.
 * @param type       Required type of the path.
 * @param must_exist Whether the path must exist.
 * @param error      Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_check_path(const char *path, mode_t type, bool must_exist,
                       GError **error)
{
    struct stat s;

    g_return_val_if_fail(path != NULL, false);

    errno = 0;
    if (stat(path, &s) != 0) {
        if (errno == ENOENT && !must_exist) {
            return true;
        }
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }

    return dlp_fs_check_stat(&s, type, error);
}

/**
 * Check that a stat structure looks reasonable.
 *
 * @param s     Structure to check.
 * @param type  Required type of the path.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_check_stat(const struct stat *s, mode_t type, GError **error)
{
    g_return_val_if_fail(s != NULL, false);

    if ((s->st_mode & DLP_FS_TYPE) != type) {
        g_set_error(error, DLP_ERROR, DLP_FS_ERROR_TYPE, "%s",
                    _("invalid type"));
        return false;
    }

    if ((s->st_uid != getuid() && s->st_uid != 0) ||
        (s->st_gid != getgid() && s->st_gid != 0) ||
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        s->st_mode & (S_IWGRP | S_IWOTH)) {
        g_set_error(error, DLP_ERROR, EBADFD, "%s", g_strerror(EBADFD));
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
 * Retrieve a per-user path in the cache directory.
 *
 * The base directory for the path is created if it doesn't exist.
 *
 * @param path  Path that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_cache_path(char **path, GError **error, ...)
{
    va_list ap;
    char *dir = NULL;
    bool rv = false;

    if (!dlp_fs_cache_dir(&dir, error)) {
        return false;
    }

    va_start(ap, error);
    rv = dlp_fs_user_path(dir, path, &ap, error);
    va_end(ap);

    dlp_mem_free(&dir);
    return rv;
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
 * Retrieve a per-user path in the config directory.
 *
 * The base directory for the path is created if it doesn't exist.
 *
 * @param path  Path that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_config_path(char **path, GError **error, ...)
{
    va_list ap;
    char *dir = NULL;
    bool rv = false;

    if (!dlp_fs_config_dir(&dir, error)) {
        return false;
    }

    va_start(ap, error);
    rv = dlp_fs_user_path(dir, path, &ap, error);
    va_end(ap);

    dlp_mem_free(&dir);
    return rv;
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
 * Retrieve a per-user path in the data directory.
 *
 * The base directory for the path is created if it doesn't exist.
 *
 * @param path  Path that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_fs_data_path(char **path, GError **error, ...)
{
    va_list ap;
    char *dir = NULL;
    bool rv = false;

    if (!dlp_fs_data_dir(&dir, error)) {
        return false;
    }

    va_start(ap, error);
    rv = dlp_fs_user_path(dir, path, &ap, error);
    va_end(ap);

    dlp_mem_free(&dir);
    return rv;
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
        dlp_mem_free(path);
        return false;
    }

    return true;
}

/**
 * Retrieve a per-user path with a given base.
 *
 * The base directory for the path is created if it doesn't exist.
 *
 * @param base  Prefix for the path.
 * @param path  Path that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_fs_user_path(const char *base, char **path, va_list *ap,
                             GError **error)
{
    char *dir;

    g_return_val_if_fail(base != NULL && path != NULL && ap != NULL, false);

    *path = g_build_filename_valist(base, ap);

    dir = g_path_get_dirname(*path);
    if (!dlp_fs_mkdir(dir, error)) {
        dlp_mem_free(&dir);
        dlp_mem_free(path);
        return false;
    }

    dlp_mem_free(&dir);
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
            dlp_mem_free(&walkpath);
            closedir(dir); /* return code ignored */
            return false;
        }

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        if (S_ISDIR(s.st_mode)) {
            errno = 0;
            /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
            if (!dlp_fs_openat(fd, de->d_name, O_RDONLY | O_NOFOLLOW, 0, &cfd,
                               error)) {
                dlp_mem_free(&walkpath);
                closedir(dir); /* return code ignored */
                return false;
            }

            if (!dlp_fs_walk_do(cfd, walkpath, cb, data, error)) {
                dlp_mem_free(&walkpath);
                closedir(dir); /* return code ignored */
                return false;
            }
        }

        if (!cb(fd, de->d_name, walkpath, &s, data, error)) {
            dlp_mem_free(&walkpath);
            closedir(dir); /* return code ignored */
            return false;
        }

        dlp_mem_free(&walkpath);
    }

    if (errno != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        closedir(dir); /* return code ignored */
        return false;
    }

    errno = 0;
    if (closedir(dir) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }
    return true;
}

/**
 * Remove an entry in a file hierarchy.
 *
 * See dlp_fs_walk_do() for an explanation of the parameters.
 */
static bool dlp_fs_rmdir_cb(int fd, const char *name, const char *path,
                            const struct stat *s, void *data, GError **error)
{
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    int flags = S_ISDIR(s->st_mode) ? AT_REMOVEDIR : 0;

    (void)data;

    errno = 0;
    if (unlinkat(fd, name, flags) != 0) {
        g_set_error(error, DLP_ERROR, errno, "%s: %s", path, g_strerror(errno));
        return false;
    }
    return true;
}

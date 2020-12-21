/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_FS_H
#define DLP_FS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <glib.h>

#include "dlp.h"

#define dlp_fs_read_bytes(fd, buf, len, error)                                 \
    _Generic((buf),                                                            \
        char *: dlp_fs_read_bytes_impl(fd, DLP_FS_PTR_CHAR, buf, len, error),  \
        uint8_t *: dlp_fs_read_bytes_impl(fd, DLP_FS_PTR_U8, buf, len, error))

#define dlp_fs_write_bytes(fd, buf, len, error)                                \
    _Generic((buf),                                                            \
        char *: dlp_fs_write_bytes_impl(fd, DLP_FS_PTR_CHAR, buf, len, error), \
        uint8_t *: dlp_fs_write_bytes_impl(fd, DLP_FS_PTR_U8, buf, len, error),\
        const char *: dlp_fs_write_bytes_impl(fd, DLP_FS_PTR_CHAR, buf, len,   \
                                              error),                          \
        const uint8_t *: dlp_fs_write_bytes_impl(fd, DLP_FS_PTR_U8, buf, len,  \
                                                 error))

#define DLP_FS_TYPE ((unsigned int)(S_IFMT))
#define DLP_FS_DIR ((unsigned int)(S_IFDIR))
#define DLP_FS_REG ((unsigned int)(S_IFREG))

enum dlp_fs_error {
    DLP_FS_ERROR_FAILED = 1,
    DLP_FS_ERROR_EOF,
    DLP_FS_ERROR_TYPE,
};

enum dlp_fs_ptr {
    DLP_FS_PTR_CHAR,
    DLP_FS_PTR_U8,
};

typedef bool (*dlp_fs_walk_cb)(int dfd, const char *name, const char *path,
                               const struct stat *s, void *data,
                               GError **error);

bool dlp_fs_walk(const char *path, dlp_fs_walk_cb cb, void *data,
                 GError **error) DLP_NODISCARD;
bool dlp_fs_openat(int dfd, const char *path, int flags, mode_t mode, int *fd,
                   GError **error) DLP_NODISCARD;
bool dlp_fs_open(const char *path, int flags, mode_t mode, int *fd,
                 GError **error) DLP_NODISCARD;
bool dlp_fs_close(int *fd, GError **error) DLP_NODISCARD;
bool dlp_fs_read(int fd, void *buf, size_t len, size_t *res,
                 GError **error) DLP_NODISCARD;
bool dlp_fs_read_bytes_impl(int fd, enum dlp_fs_ptr type, void *buf, size_t len,
                            GError **error) DLP_NODISCARD;
bool dlp_fs_write(int fd, const void *buf, size_t len, size_t *res,
                  GError **error) DLP_NODISCARD;
bool dlp_fs_write_bytes_impl(int fd, enum dlp_fs_ptr type, const void *buf,
                             size_t len, GError **error) DLP_NODISCARD;
bool dlp_fs_seek(int fd, off_t offset, int whence,
                 GError **error) DLP_NODISCARD;
bool dlp_fs_truncate(int fd, off_t len, GError **error) DLP_NODISCARD;
bool dlp_fs_copy(int infd, int outfd, GError **error) DLP_NODISCARD;
bool dlp_fs_size(int fd, size_t *size, GError **error) DLP_NODISCARD;
bool dlp_fs_mkdir(const char *path, GError **error) DLP_NODISCARD;
bool dlp_fs_rmdir(const char *path, GError **error) DLP_NODISCARD;
bool dlp_fs_remove(const char *path, GError **error) DLP_NODISCARD;
bool dlp_fs_mkdtemp(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_mkstemp(int *fd, GError **error) DLP_NODISCARD;
bool dlp_fs_stat(const char *path, struct stat *s,
                 GError **error) DLP_NODISCARD;
bool dlp_fs_fstat(int fd, struct stat *s, GError **error) DLP_NODISCARD;
bool dlp_fs_check_path(const char *path, mode_t type, bool must_exist,
                       GError **error) DLP_NODISCARD;
bool dlp_fs_check_stat(const struct stat *s, mode_t type,
                       GError **error) DLP_NODISCARD;
bool dlp_fs_stale_p(const char *path, time_t max_diff, bool *stale,
                    GError **error) DLP_NODISCARD;
bool dlp_fs_cache_dir(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_cache_path(char **path, GError **error,
                       ...) DLP_NODISCARD G_GNUC_NULL_TERMINATED;
bool dlp_fs_config_dir(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_config_path(char **path, GError **error,
                        ...) DLP_NODISCARD G_GNUC_NULL_TERMINATED;
bool dlp_fs_data_dir(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_data_path(char **path, GError **error,
                      ...) DLP_NODISCARD G_GNUC_NULL_TERMINATED;

#endif /* DLP_FS_H */

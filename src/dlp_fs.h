/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_FS_H
#define DLP_FS_H

#include <stdbool.h>

#include <sys/stat.h>

#include <glib.h>

#include "dlp.h"

enum dlp_fs_error {
    DLP_FS_ERROR_FAILED = 1,
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
bool dlp_fs_seek(int fd, off_t offset, int whence,
                 GError **error) DLP_NODISCARD;
bool dlp_fs_truncate(int fd, off_t len, GError **error) DLP_NODISCARD;
bool dlp_fs_mkdir(const char *path, GError **error) DLP_NODISCARD;
bool dlp_fs_rmdir(const char *path, GError **error) DLP_NODISCARD;
bool dlp_fs_mkdtemp(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_mkstemp(int *fd, GError **error) DLP_NODISCARD;
bool dlp_fs_check_stat(const struct stat *s, GError **error) DLP_NODISCARD;
bool dlp_fs_cache_dir(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_config_dir(char **path, GError **error) DLP_NODISCARD;
bool dlp_fs_data_dir(char **path, GError **error) DLP_NODISCARD;

#endif /* DLP_FS_H */

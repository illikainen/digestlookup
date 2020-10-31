/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_FS_H
#define DLP_FS_H

#include <stdbool.h>

#include <glib.h>

enum dlp_fs_error {
    DLP_FS_ERROR_FAILED = 1,
};

bool dlp_fs_mkdir(const char *path, GError **error);
bool dlp_fs_cache_dir(char **path, GError **error);
bool dlp_fs_config_dir(char **path, GError **error);
bool dlp_fs_data_dir(char **path, GError **error);

#endif /* DLP_FS_H */

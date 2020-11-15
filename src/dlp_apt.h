/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_APT_H
#define DLP_APT_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

enum dlp_apt_error {
    DLP_APT_ERROR_LEX = 1,
    DLP_APT_ERROR_DUPLICATE,
    DLP_APT_ERROR_REQUIRED,
};

bool dlp_apt_read_release(int fd, GHashTable **release,
                          GError **error) DLP_NODISCARD;
bool dlp_apt_read_sources(int fd, GList **pkgs, GError **error) DLP_NODISCARD;
void dlp_apt_list_free(GList **list);
void dlp_apt_ht_free(GHashTable **ht);

#endif /* DLP_APT_H */

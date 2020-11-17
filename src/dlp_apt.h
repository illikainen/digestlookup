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
    DLP_APT_ERROR_FAILED = 1,
    DLP_APT_ERROR_LEX,
    DLP_APT_ERROR_DUPLICATE,
    DLP_APT_ERROR_REQUIRED,
};

struct dlp_apt_file {
    char *name;
    guint64 size;
    char *digest;
};

struct dlp_apt_release {
    char *codename;
    char *suite;
    GList *md5sum;
    GList *sha256;
};

struct dlp_apt_source {
    char *package;
    GList *files;
    GList *checksums_sha256;
};

bool dlp_apt_release_read(int fd, struct dlp_apt_release **release,
                          GError **error) DLP_NODISCARD;
void dlp_apt_release_free(struct dlp_apt_release **release);
bool dlp_apt_sources_read(int fd, GList **sources,
                          GError **error) DLP_NODISCARD;
void dlp_apt_sources_free(GList **sources);

#endif /* DLP_APT_H */

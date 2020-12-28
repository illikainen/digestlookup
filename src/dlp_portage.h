/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_PORTAGE_H
#define DLP_PORTAGE_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

enum dlp_portage_error {
    DLP_PORTAGE_ERROR_LEX = 1,
};

enum dlp_portage_type {
    DLP_PORTAGE_TYPE_DIST,
    DLP_PORTAGE_TYPE_EBUILD,
    DLP_PORTAGE_TYPE_MISC,
    DLP_PORTAGE_TYPE_AUX,
};

struct dlp_portage_entry {
    char *file;
    enum dlp_portage_type type;
    guint64 size;
    char *blake2b;
    char *sha512;
};

bool dlp_portage_manifest_read(const char *data, size_t len, GList **manifest,
                               GError **error) DLP_NODISCARD;
void dlp_portage_manifest_free(GList **manifest);

#endif /* DLP_PORTAGE_H */

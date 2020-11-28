/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_BACKEND_H
#define DLP_BACKEND_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

enum dlp_curl_error {
    DLP_BACKEND_ERROR_NOT_FOUND = 1,
};

struct dlp_backend {
    const char *name;
    bool (*lookup)(char **pkgs, GError **error);
};

void dlp_backend_add(struct dlp_backend *be);
void dlp_backend_remove(struct dlp_backend *be);
bool dlp_backend_find(const char *name, struct dlp_backend **be,
                      GError **error) DLP_NODISCARD;

#endif /* DLP_BACKEND_H */
/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_CFG_H
#define DLP_CFG_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"
#include "dlp_backend.h"

struct dlp_cfg;

enum dlp_cfg_error {
    DLP_CFG_ERROR_FAILED = 1,
};

struct dlp_cfg_repo {
    char *name;
    struct dlp_backend *backend;
    char *url;
    char *tls_key;
    char *user_agent;
    GPtrArray *verify_keys;
    guint64 cache;
};

struct dlp_cfg {
    GList *repos;
};

bool dlp_cfg_read(const char *path, struct dlp_cfg **cfg,
                  GError **error) DLP_NODISCARD;
void dlp_cfg_free(struct dlp_cfg **cfg);

#endif /* DLP_CFG_H */

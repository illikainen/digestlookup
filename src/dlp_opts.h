/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_OPTS_H
#define DLP_OPTS_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

struct dlp_opts {
    char *config;
    char **repos;
    char **patterns;
    GPtrArray *regex;
    bool deep;
    bool verbose;
};

bool dlp_opts_parse(int argc, char **argv, struct dlp_opts **opts,
                    GError **error) DLP_NODISCARD;
void dlp_opts_free(struct dlp_opts **opts);

#endif /* DLP_OPTS_H */

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_RESOURCE_H
#define DLP_RESOURCE_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

bool dlp_resource_p(const char *path) DLP_NODISCARD;
bool dlp_resource_exists_p(const char *path, GError **error) DLP_NODISCARD;
bool dlp_resource_data(const char *path, void **data, gsize *size,
                       GError **error) DLP_NODISCARD;

#endif /* DLP_RESOURCE_H */

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_ERROR_H
#define DLP_ERROR_H

#include <glib.h>

#include "dlp.h"

#define DLP_ERROR dlp_error_quark()

GQuark dlp_error_quark(void) DLP_NODISCARD;
const gchar *dlp_error_str(const char *fallback) DLP_NODISCARD;

#endif /* DLP_ERROR_H */

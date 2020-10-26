/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_error.h"

#include <errno.h>

const gchar *dlp_error_str(const char *fallback)
{
    if (errno) {
        return g_strerror(errno);
    }
    return fallback;
}

/* clang-format off */
G_DEFINE_QUARK(dlp-error-quark, dlp_error)
/* clang-format on */

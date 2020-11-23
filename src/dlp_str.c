/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_str.h"

#include <glib.h>

/**
 * Simple string sanitizer.
 *
 * @param str String to sanitize.
 */
void dlp_str_sanitize(char *str)
{
    g_return_if_fail(str != NULL);

    for (; *str != '\0'; str++) {
        if (*str < 0x20 || *str > 0x7d) {
            *str = '_';
        }
    }
}

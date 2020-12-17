/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_str.h"

#include <glib.h>

#define DLP_STR_ASCII_DIGITS "0123456789"
#define DLP_STR_ASCII_A_Z "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DLP_STR_ASCII_OTHER " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~\n"
#define DLP_STR_ASCII_PRINTABLE                                                \
    DLP_STR_ASCII_DIGITS DLP_STR_ASCII_A_Z DLP_STR_ASCII_OTHER

/**
 * Simple string sanitizer.
 *
 * @param str String to sanitize.
 */
void dlp_str_sanitize(char *str)
{
    g_return_if_fail(str != NULL);

    g_strcanon(str, DLP_STR_ASCII_PRINTABLE, '_');
}

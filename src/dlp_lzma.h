/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_LZMA_H
#define DLP_LZMA_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

enum dlp_lzma_error {
    DLP_LZMA_ERROR_FAILED = 1,
    DLP_LZMA_ERROR_EOF,
};

bool dlp_lzma_decompress(int infd, int outfd, GError **error) DLP_NODISCARD;

#endif /* DLP_LZMA_H */

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_DIGEST_H
#define DLP_DIGEST_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

enum dlp_digest_error {
    DLP_DIGEST_ERROR_FAILED = 1,
    DLP_DIGEST_ERROR_ALGORITHM,
    DLP_DIGEST_ERROR_ENCODE,
    DLP_DIGEST_ERROR_MISMATCH,
    DLP_DIGEST_ERROR_TRUNCATED,
};

enum dlp_digest_encode {
    DLP_DIGEST_ENCODE_HEX,
};

bool dlp_digest_cmp(int fd, GChecksumType type, enum dlp_digest_encode enc,
                    char *digest, GError **error) DLP_NODISCARD;
bool dlp_digest_compute(int fd, GChecksumType type, enum dlp_digest_encode enc,
                        char **digest, GError **error) DLP_NODISCARD;

#endif /* DLP_DIGEST_H */

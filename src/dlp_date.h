/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_DATE_H
#define DLP_DATE_H

#include <stdbool.h>
#include <time.h>

#include <glib.h>

#include "dlp.h"

enum dlp_date_error {
    /*
     * Negative to differentiate from errno.
     *
     * See ISO/IEC 9899:201x 7.5.
     */
    DLP_DATE_ERROR_FORMAT = -1,
};

bool dlp_date_parse(const char *str, const char *fmt, time_t *t,
                    GError **error) DLP_NODISCARD;

#endif /* DLP_DATE_H */

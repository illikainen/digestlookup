/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_STR_H
#define DLP_STR_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

void dlp_str_sanitize(char *str);
void dlp_str_sanitize_filename(char *str);
bool dlp_str_match_plain(const GPtrArray *regex, const char *str);
bool dlp_str_match_parray(const GPtrArray *regex, const GPtrArray *strs);
bool dlp_str_match_list(const GPtrArray *regex, const GList *list, glong off);

#endif /* DLP_STR_H */

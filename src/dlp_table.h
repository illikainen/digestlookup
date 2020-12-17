/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_TABLE_H
#define DLP_TABLE_H

#include <stdbool.h>

#include <glib.h>

#include "dlp.h"

struct dlp_table;

void dlp_table_init(struct dlp_table **table);
void dlp_table_free(struct dlp_table **table);
bool dlp_table_add_columns(struct dlp_table *table, GError **error,
                           ...) DLP_NODISCARD G_GNUC_NULL_TERMINATED;
bool dlp_table_add_row(struct dlp_table *table, GError **error,
                       ...) DLP_NODISCARD G_GNUC_NULL_TERMINATED;
bool dlp_table_format(struct dlp_table *table, char **str) DLP_NODISCARD;
void dlp_table_print(struct dlp_table *table);

#endif /* DLP_TABLE_H */

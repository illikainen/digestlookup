/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_table.h"

#include <errno.h>

#include "dlp_error.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

struct dlp_table_column {
    char *name;
    int len;
};

struct dlp_table {
    GList *columns;
    GList *rows;
    GMutex mutex;
};

static bool dlp_table_find_column(struct dlp_table *table, const char *name,
                                  struct dlp_table_column **col,
                                  GError **error) DLP_NODISCARD;
static bool dlp_table_strlen(const char *str, int *len,
                             GError **error) DLP_NODISCARD;

/**
 * Initialize a table.
 *
 * @param table Table to initialize.
 */
void dlp_table_init(struct dlp_table **table)
{
    g_return_if_fail(table != NULL);

    *table = dlp_mem_alloc(sizeof(**table));
    g_mutex_init(&(*table)->mutex);
}

/**
 * Free a table and clear its pointer.
 *
 * @param table Table to free.  It is a noop if this is NULL or a NULL pointer.
 */
void dlp_table_free(struct dlp_table **table)
{
    GList *elt;
    struct dlp_table_column *col;

    if (table != NULL && *table != NULL) {
        for (elt = (*table)->rows; elt != NULL; elt = elt->next) {
            if (elt->data != NULL) {
                g_hash_table_unref(elt->data);
            }
        }
        g_list_free((*table)->rows);

        for (elt = (*table)->columns; elt != NULL; elt = elt->next) {
            col = elt->data;
            if (col != NULL) {
                dlp_mem_free(&col->name);
                dlp_mem_free(&col);
            }
        }
        g_list_free((*table)->columns);

        g_mutex_clear(&(*table)->mutex);
        dlp_mem_free(table);
    }
}

/**
 * Add columns for a table.
 *
 * @param table Table initialized with dlp_table_init().
 * @param error Optional error information.
 * @param ...   NULL-terminated column names to set for the table.
 * @return True on success and false on failure.
 */
bool dlp_table_add_columns(struct dlp_table *table, GError **error, ...)
{
    va_list ap;
    const char *str;
    struct dlp_table_column *col;

    g_return_val_if_fail(table != NULL, false);

    g_mutex_lock(&table->mutex);
    va_start(ap, error);

    /* See: https://bugs.llvm.org/show_bug.cgi?id=41311
     *
     * NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized) */
    while ((str = va_arg(ap, const char *)) != NULL) {
        col = dlp_mem_alloc(sizeof(*col));
        table->columns = g_list_append(table->columns, col);

        if ((col->name = g_strdup(str)) == NULL ||
            !dlp_table_strlen(col->name, &col->len, error)) {
            break;
        }
    }

    va_end(ap);
    g_mutex_unlock(&table->mutex);

    return str == NULL;
}

/**
 * Add a table row.
 *
 * @param table Table initialized with dlp_table_init().
 * @param error Optional error information.
 * @param ...   NULL-terminated row to add.  Each column must be specified as a
 *              pair of strings where the first string is the column name and
 *              the second string is the column value.
 * @return True on success and false on failure.
 */
bool dlp_table_add_row(struct dlp_table *table, GError **error, ...)
{
    va_list ap;
    int len;
    GHashTable *row;
    struct dlp_table_column *col;
    const char *str;
    char *key = NULL;
    char *value = NULL;
    size_t i = 1;

    g_return_val_if_fail(table != NULL && table->columns != NULL, false);

    g_mutex_lock(&table->mutex);
    row = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    table->rows = g_list_prepend(table->rows, row);

    va_start(ap, error);

    /* See: https://bugs.llvm.org/show_bug.cgi?id=41311
     *
     * NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized) */
    while ((str = va_arg(ap, const char *)) != NULL) {
        if (i % 2) {
            key = g_strdup(str);
        } else {
            value = g_strdup(str);
            g_hash_table_replace(row, key, value);

            if (!dlp_table_find_column(table, key, &col, error) ||
                !dlp_table_strlen(value, &len, error)) {
                break;
            }
            col->len = MAX(col->len, len);
        }
        i++;
    }

    va_end(ap);
    g_mutex_unlock(&table->mutex);

    return str == NULL;
}

/**
 * Format a table as a string.
 *
 * @param table Table initialized with dlp_table_init().
 * @param str   Resulting string.
 * @return True on success and false on failure.
 */
bool dlp_table_format(struct dlp_table *table, char **str)
{
    GList *cols;
    GList *rows;
    GString *s;
    char *tmp;
    struct dlp_table_column *col;

    g_return_val_if_fail(table != NULL && table->columns != NULL && str != NULL,
                         false);
    *str = NULL;
    g_mutex_lock(&table->mutex);

    s = g_string_new(NULL);
    for (cols = table->columns; cols != NULL; cols = cols->next) {
        col = cols->data;
        g_string_append_printf(s, "| %-*s ", col->len, col->name);
    }
    g_string_append(s, "|\n");

    tmp = g_strdup(s->str);
    g_string_append(s, g_strcanon(tmp, "|\n", '-'));
    dlp_mem_free(&tmp);

    for (rows = table->rows; rows != NULL; rows = rows->next) {
        for (cols = table->columns; cols != NULL; cols = cols->next) {
            col = cols->data;
            tmp = g_hash_table_lookup(rows->data, col->name);
            if (tmp == NULL) {
                tmp = "";
            }
            g_string_append_printf(s, "| %-*s ", col->len, tmp);
        }
        g_string_append(s, "|\n");
    }

    *str = g_string_free(s, false);
    g_mutex_unlock(&table->mutex);

    return *str != NULL;
}

/**
 * Print a table.
 *
 * @param table Table initialized with dlp_table_init().
 */
void dlp_table_print(struct dlp_table *table)
{
    char *str;

    g_return_if_fail(table != NULL && table->columns != NULL);

    if (dlp_table_format(table, &str)) {
        g_print("%s", g_strchomp(str));
        dlp_mem_free(&str);
    }
}

/**
 * Lookup a column.
 *
 * @param table Table initialized with dlp_table_init().
 * @param name  Column name.
 * @param col   Found column.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_table_find_column(struct dlp_table *table, const char *name,
                                  struct dlp_table_column **col, GError **error)
{
    GList *columns;

    g_return_val_if_fail(table != NULL && name != NULL && col != NULL, false);

    for (columns = table->columns; columns != NULL; columns = columns->next) {
        *col = columns->data;
        if (*col != NULL && g_strcmp0((*col)->name, name) == 0) {
            return true;
        }
    }

    g_set_error(error, DLP_ERROR, EINVAL, "%s", g_strerror(EINVAL));
    return false;
}

/**
 * Helper around strlen() to retrieve integer widths for printf().
 *
 * @param str   String whose length to get.
 * @param len   String length.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_table_strlen(const char *str, int *len, GError **error)
{
    g_return_val_if_fail(str != NULL && len != NULL, false);

    if (dlp_overflow_add(strlen(str), 0, len)) {
        *len = 0;
        g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
        return false;
    }

    return true;
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_log.h"

#include <stdio.h>

#include <glib.h>

#include "dlp.h"
#include "dlp_mem.h"
#include "dlp_str.h"

static void dlp_log_init(void) DLP_CONSTRUCTOR;
static bool dlp_log_p(GLogLevelFlags level) DLP_NODISCARD;
static bool dlp_log_stream(GLogLevelFlags level, FILE **fp) DLP_NODISCARD;
static bool dlp_log_prefix(GLogLevelFlags level, bool color,
                           char **str) DLP_NODISCARD;
static bool dlp_log_format(GLogLevelFlags level, const GLogField *fields,
                           gsize nfields, char **str) DLP_NODISCARD;
static GLogWriterOutput dlp_log_writer(GLogLevelFlags level,
                                       const GLogField *fields, gsize nfields,
                                       gpointer data) DLP_NODISCARD;
static void dlp_log_handler(const gchar *domain, GLogLevelFlags level,
                            const gchar *msg, gpointer data) G_GNUC_NORETURN;
static void dlp_log_print_handler(const gchar *str);
static void dlp_log_printerr_handler(const gchar *str);

static bool dlp_log_verbose;

/**
 * Set log verbosity.
 *
 * @param enable Whether to enable verbose messages.
 */
void dlp_log_set_verbosity(bool enable)
{
    dlp_log_verbose = enable;
}

/**
 * Set GLib log and message callbacks.
 */
/* cppcheck-suppress unusedFunction */
static void dlp_log_init(void)
{
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    GLogLevelFlags lvl = (GLogLevelFlags)(G_LOG_LEVEL_MASK | G_LOG_FATAL_MASK);

    g_log_set_writer_func(dlp_log_writer, NULL, NULL);
    g_log_set_handler(NULL, lvl, dlp_log_handler, NULL);
    g_log_set_default_handler(dlp_log_handler, NULL);
    g_set_print_handler(dlp_log_print_handler);
    g_set_printerr_handler(dlp_log_printerr_handler);
}

/**
 * Check whether a message should be logged.
 *
 * @param level Log level for the message.
 * @return True if the message should be logged and false otherwise.
 */
static bool dlp_log_p(GLogLevelFlags level)
{
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (level & G_LOG_LEVEL_DEBUG) {
        return dlp_log_verbose;
    }
    return true;
}

/**
 * Retrieve the stream on which to show a message.
 *
 * @param level Log level for the message.
 * @param fp    Stream to use.
 * @return True on success and false on failure.
 */
static bool dlp_log_stream(GLogLevelFlags level, FILE **fp)
{
    g_return_val_if_fail(fp != NULL, false);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (level & (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE)) {
        *fp = stdout;
    } else {
        *fp = stderr;
    }

    return true;
}

/**
 * Set the message prefix.
 *
 * @param level Log level for the message.
 * @param color Whether to use colors.
 * @param str   Message prefix.
 */
static bool dlp_log_prefix(GLogLevelFlags level, bool color, char **str)
{
    g_return_val_if_fail(str != NULL, false);

    if (level & G_LOG_LEVEL_MESSAGE) { /* NOLINT(hicpp-signed-bitwise) */
        *str = "";
    } else if (level & G_LOG_LEVEL_DEBUG) { /* NOLINT(hicpp-signed-bitwise) */
        *str = color ? "\033[1;32mDEBUG\033[0m: " : "DEBUG: ";
    } else if (level & G_LOG_LEVEL_INFO) { /* NOLINT(hicpp-signed-bitwise) */
        *str = color ? "\033[1;32mINFO\033[0m: " : "INFO: ";
    } else if (level & G_LOG_LEVEL_WARNING) { /* NOLINT(hicpp-signed-bitwise) */
        *str = color ? "\033[1;33mWARNING\033[0m: " : "WARNING: ";
    } else {
        *str = color ? "\033[1;31mERROR\033[0m: " : "ERROR: ";
    }

    return true;
}

/**
 * Format a structured log message.
 *
 * @param level     Log level for the message.
 * @param fields    Structured data fields.
 * @param nfields   Number of available fields.
 * @param str       Log message that must be freed after use.
 * @return True on success and false on failure.
 */
static bool dlp_log_format(GLogLevelFlags level, const GLogField *fields,
                           gsize nfields, char **str)
{
    gsize i;
    const char *file = NULL;
    const char *line = NULL;
    const char *func = NULL;
    const char *msg = "<empty>";
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    GLogLevelFlags verbose = (GLogLevelFlags)(G_LOG_LEVEL_DEBUG |
                                              G_LOG_LEVEL_ERROR);

    g_return_val_if_fail(fields != NULL && str != NULL, false);
    *str = NULL;

    for (i = 0; i < nfields; i++) {
        if (fields[i].key != NULL && fields[i].length == -1) {
            if (strcmp(fields[i].key, "CODE_FILE") == 0) {
                file = g_strrstr(fields[i].value, G_DIR_SEPARATOR_S);
                if (file != NULL) {
                    file++;
                } else {
                    file = fields[i].value;
                }
            } else if (strcmp(fields[i].key, "CODE_LINE") == 0) {
                line = fields[i].value;
            } else if (strcmp(fields[i].key, "CODE_FUNC") == 0) {
                func = fields[i].value;
            } else if (strcmp(fields[i].key, "MESSAGE") == 0) {
                msg = fields[i].value;
            }
        }
    }

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (level & verbose && file != NULL && line != NULL && func != NULL) {
        *str = g_strdup_printf("%s:%s:%s(): %s", file, line, func, msg);
    } else {
        *str = g_strdup_printf("%s", msg);
    }

    return true;
}

/**
 * Callback for structured log messages.
 *
 * This function always returns G_LOG_WRITER_UNHANDLED to avoid chained writers
 * that may output unsanitized messages.
 *
 * TODO: Make sure that the documentation for g_log_structured() is correct.
 *       It states that "[...] If the log writer returns G_LOG_WRITER_UNHANDLED
 *       (failure), no other fallback writers will be tried."
 *
 * TODO: Make sure we don't recurse by calling GLib functions.
 *
 * @param level     Log level for the message.
 * @param fields    Structured data fields.
 * @param nfields   Number of available fields.
 * @param data      Not used.
 * @returns G_LOG_WRITER_UNHANDLED.
 */
static GLogWriterOutput dlp_log_writer(GLogLevelFlags level,
                                       const GLogField *fields, gsize nfields,
                                       gpointer data)
{
    FILE *fp;
    char *msg;
    char *pfx;

    (void)data;

    if (fields == NULL || !dlp_log_p(level) || !dlp_log_stream(level, &fp) ||
        !dlp_log_prefix(level, g_log_writer_supports_color(fileno(fp)), &pfx) ||
        !dlp_log_format(level, fields, nfields, &msg)) {
        return G_LOG_WRITER_UNHANDLED;
    }

    dlp_str_sanitize(msg);
    fprintf(fp, "%s%s\n", pfx, msg);
    dlp_mem_free(&msg);

    return G_LOG_WRITER_UNHANDLED;
}

/**
 * Handler for old-style logging.
 *
 * This function should never be called if structured logging is setup
 * properly.  It invokes abort() to avoid showing potentially bad output
 * (e.g. escape sequences) to the user.
 *
 * @param domain    Not used.
 * @param level     Not used.
 * @param msg       Not used.
 * @param data      Not used.
 */
static void dlp_log_handler(const gchar *domain, GLogLevelFlags level,
                            const gchar *msg, gpointer data)
{
    (void)domain;
    (void)level;
    (void)msg;
    (void)data;

    abort();
}

/**
 * Handler for g_print().
 *
 * @param str String to print.
 */
static void dlp_log_print_handler(const gchar *str)
{
    char *msg;

    if ((msg = g_strdup(str)) == NULL) {
        return;
    }

    dlp_str_sanitize(msg);
    fprintf(stdout, "%s\n", msg);
    g_free(msg);
}

/**
 * Handler for g_printerr().
 *
 * @param str String to print.
 */
static void dlp_log_printerr_handler(const gchar *str)
{
    char *msg;

    if ((msg = g_strdup(str)) == NULL) {
        return;
    }

    dlp_str_sanitize(msg);
    fprintf(stderr, "%s\n", msg);
    g_free(msg);
}

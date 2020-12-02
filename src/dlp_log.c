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

struct dlp_log_fields {
    const char *domain;
    const char *file;
    const char *line;
    const char *func;
    const char *msg;
};

static void dlp_log_ctor(void) DLP_CONSTRUCTOR;
static bool dlp_log_fields(const GLogField *fields, gsize nfields,
                           struct dlp_log_fields *lf) DLP_NODISCARD;
static bool dlp_log_p(GLogLevelFlags level,
                      const struct dlp_log_fields *lf) DLP_NODISCARD;
static bool dlp_log_stream(GLogLevelFlags level, FILE **fp) DLP_NODISCARD;
static bool dlp_log_prefix(GLogLevelFlags level, bool color,
                           char **str) DLP_NODISCARD;
static bool dlp_log_format(GLogLevelFlags level,
                           const struct dlp_log_fields *lf,
                           char **str) DLP_NODISCARD;
static GLogWriterOutput dlp_log_writer(GLogLevelFlags level,
                                       const GLogField *fields, gsize nfields,
                                       gpointer data) DLP_NODISCARD;
static void dlp_log_handler(const gchar *domain, GLogLevelFlags level,
                            const gchar *msg, gpointer data);
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
static void dlp_log_ctor(void)
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
 * Retrieve the fields for a structured log message.
 *
 * @param fields    Structured data fields.
 * @param nfields   Number of available fields.
 * @param lf        Field structure allocated by the caller.  The lifetime of
 *                  its members is that of the fields argument.
 * @return True on success and false on failure.
 */
static bool dlp_log_fields(const GLogField *fields, gsize nfields,
                           struct dlp_log_fields *lf)
{
    gsize i;

    g_return_val_if_fail(fields != NULL && lf != NULL, false);
    lf->file = lf->line = lf->func = lf->msg = lf->domain = NULL;

    for (i = 0; i < nfields; i++) {
        if (fields[i].key != NULL && fields[i].length == -1) {
            if (strcmp(fields[i].key, "CODE_FILE") == 0) {
                lf->file = g_strrstr(fields[i].value, G_DIR_SEPARATOR_S);
                if (lf->file != NULL) {
                    lf->file++;
                } else {
                    lf->file = fields[i].value;
                }
            } else if (strcmp(fields[i].key, "CODE_LINE") == 0) {
                lf->line = fields[i].value;
            } else if (strcmp(fields[i].key, "CODE_FUNC") == 0) {
                lf->func = fields[i].value;
            } else if (strcmp(fields[i].key, "MESSAGE") == 0) {
                lf->msg = fields[i].value;
            } else if (strcmp(fields[i].key, "GLIB_DOMAIN") == 0) {
                lf->domain = fields[i].value;
            }
        }
    }

    return true;
}

/**
 * Check whether a message should be logged.
 *
 * @param level Log level for the message.
 * @param lf    Log fields.
 * @return True if the message should be logged and false otherwise.
 */
static bool dlp_log_p(GLogLevelFlags level, const struct dlp_log_fields *lf)
{
    char *domain;

    g_return_val_if_fail(lf != NULL, false);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (dlp_log_verbose || (level & G_LOG_LEVEL_DEBUG) == 0) {
        return true;
    }

    domain = g_strdup(g_getenv("G_MESSAGES_DEBUG"));
    if (domain != NULL) {
        if (strstr(domain, "all") != NULL) {
            g_free(domain);
            return true;
        }
        if (lf->domain != NULL && strstr(lf->domain, domain) != NULL) {
            g_free(domain);
            return true;
        }
        g_free(domain);
    }

    return false;
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
 * @return True on success and false on failure.
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
 * @param level Log level for the message.
 * @param lf    Log fields.
 * @param str   Log message that must be freed after use.
 * @return True on success and false on failure.
 */
static bool dlp_log_format(GLogLevelFlags level,
                           const struct dlp_log_fields *lf, char **str)
{
    g_return_val_if_fail(lf != NULL && str != NULL, false);
    *str = NULL;

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if (level & (GLogLevelFlags)(G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_ERROR) &&
        lf->file != NULL && lf->line != NULL && lf->func != NULL) {
        *str = g_strdup_printf("%s:%s:%s(): %s", lf->file, lf->line, lf->func,
                               lf->msg != NULL ? lf->msg : "<empty>");
    } else {
        *str = g_strdup_printf("%s", lf->msg != NULL ? lf->msg : "<empty>");
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
    struct dlp_log_fields lf = { 0 };

    (void)data;

    if (fields == NULL || !dlp_log_fields(fields, nfields, &lf) ||
        !dlp_log_p(level, &lf) || !dlp_log_stream(level, &fp) ||
        !dlp_log_prefix(level, g_log_writer_supports_color(fileno(fp)), &pfx) ||
        !dlp_log_format(level, &lf, &msg)) {
        return G_LOG_WRITER_UNHANDLED;
    }

    dlp_str_sanitize(msg);
    fprintf(fp, "%s%s\n", pfx, msg);
    fflush(fp);
    dlp_mem_free(&msg);

    return G_LOG_WRITER_UNHANDLED;
}

/**
 * Handler for old-style logging.
 *
 * This function shouldn't be called if structured logging is setup properly.
 * However, it is called for some GLib debug messages; so they are sent to the
 * structured log handler.
 *
 * @param domain    Log domain.
 * @param level     Log level.
 * @param msg       Message.
 * @param data      Not used.
 */
static void dlp_log_handler(const gchar *domain, GLogLevelFlags level,
                            const gchar *msg, gpointer data)
{
    (void)data;

    if (domain != NULL && msg != NULL) {
        g_log_structured(domain, level, "MESSAGE", "%s", msg);
    }
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
    fflush(stdout);
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
    fflush(stderr);
    g_free(msg);
}

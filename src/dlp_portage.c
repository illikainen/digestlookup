/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_portage.h"

#include <errno.h>

#include <glib/gi18n.h>

#include "dlp_error.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

#define dlp_portage_unexp_token(scan, exp_token)                               \
    g_scanner_unexp_token(scan, exp_token, NULL, NULL, NULL, G_STRLOC, true)

enum dlp_portage_symbol {
    DLP_PORTAGE_SYMBOL_DIST = DLP_PORTAGE_TYPE_DIST,
    DLP_PORTAGE_SYMBOL_EBUILD = DLP_PORTAGE_TYPE_EBUILD,
    DLP_PORTAGE_SYMBOL_MISC = DLP_PORTAGE_TYPE_MISC,
    DLP_PORTAGE_SYMBOL_AUX = DLP_PORTAGE_TYPE_AUX,
    DLP_PORTAGE_SYMBOL_BLAKE2B,
    DLP_PORTAGE_SYMBOL_SHA512,
};

static void dlp_portage_entry_free(struct dlp_portage_entry **e);
static bool dlp_portage_parse_type(GScanner *scan,
                                   struct dlp_portage_entry *e) DLP_NODISCARD;
static bool dlp_portage_parse_file(GScanner *scan,
                                   struct dlp_portage_entry *e) DLP_NODISCARD;
static bool dlp_portage_parse_size(GScanner *scan,
                                   struct dlp_portage_entry *e) DLP_NODISCARD;
static bool dlp_portage_parse_digest(GScanner *scan,
                                     struct dlp_portage_entry *e) DLP_NODISCARD;
static void dlp_portage_error(GScanner *scan, gchar *msg, gboolean error);

static const GScannerConfig dlp_portage_config = {
    .cset_identifier_first = G_CSET_A_2_Z,
    .cset_identifier_nth = G_CSET_A_2_Z G_CSET_DIGITS,
    .case_sensitive = 1,
    .cset_skip_characters = " ",
    .store_int64 = 1,
    .identifier_2_string = 1,
    .scan_identifier = 1,
    .scan_identifier_1char = 1,
    .scan_symbols = 1,
};

/**
 * Read a portage manifest.
 *
 * @param data      Data to read.
 * @param len       Length of the data.
 * @param manifest  List of manifest entries that must be freed with
 *                  dlp_portage_manifest_free() after use.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_portage_manifest_read(const char *data, size_t len, GList **manifest,
                               GError **error)
{
    int sym;
    guint ulen;
    GScanner *scan;
    GTokenType tok;
    struct dlp_portage_entry *entry;

    g_return_val_if_fail(data != NULL && manifest != NULL, false);
    *manifest = NULL;

    if (dlp_overflow_add(len, 0, &ulen)) {
        g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
        return false;
    }

    scan = g_scanner_new(&dlp_portage_config);
    scan->user_data = error;
    scan->msg_handler = dlp_portage_error;

    g_scanner_scope_add_symbol(scan, 0, "DIST",
                               GINT_TO_POINTER(DLP_PORTAGE_SYMBOL_DIST));
    g_scanner_scope_add_symbol(scan, 0, "EBUILD",
                               GINT_TO_POINTER(DLP_PORTAGE_SYMBOL_EBUILD));
    g_scanner_scope_add_symbol(scan, 0, "MISC",
                               GINT_TO_POINTER(DLP_PORTAGE_SYMBOL_MISC));
    g_scanner_scope_add_symbol(scan, 0, "AUX",
                               GINT_TO_POINTER(DLP_PORTAGE_SYMBOL_AUX));
    g_scanner_scope_add_symbol(scan, 0, "BLAKE2B",
                               GINT_TO_POINTER(DLP_PORTAGE_SYMBOL_BLAKE2B));
    g_scanner_scope_add_symbol(scan, 0, "SHA512",
                               GINT_TO_POINTER(DLP_PORTAGE_SYMBOL_SHA512));
    g_scanner_input_text(scan, data, ulen);

    entry = dlp_mem_alloc(sizeof(*entry));
    while ((tok = g_scanner_get_next_token(scan)) != G_TOKEN_EOF) {
        if (tok == G_TOKEN_CHAR && scan->value.v_char == '\n') {
            if (entry->file == NULL || entry->blake2b == NULL ||
                entry->sha512 == NULL) {
                g_scanner_error(scan, "%s", _("missing required member(s)"));
                break;
            }

            *manifest = g_list_append(*manifest, entry);
            entry = dlp_mem_alloc(sizeof(*entry));
        } else if (tok == G_TOKEN_SYMBOL) {
            sym = GPOINTER_TO_INT(scan->value.v_symbol);
            if (sym == DLP_PORTAGE_SYMBOL_DIST ||
                sym == DLP_PORTAGE_SYMBOL_EBUILD ||
                sym == DLP_PORTAGE_SYMBOL_MISC ||
                sym == DLP_PORTAGE_SYMBOL_AUX) {
                if (!dlp_portage_parse_type(scan, entry) ||
                    !dlp_portage_parse_file(scan, entry) ||
                    !dlp_portage_parse_size(scan, entry)) {
                    break;
                }
            } else if (sym == DLP_PORTAGE_SYMBOL_BLAKE2B ||
                       sym == DLP_PORTAGE_SYMBOL_SHA512) {
                if (!dlp_portage_parse_digest(scan, entry)) {
                    break;
                }
            }
        } else {
            dlp_portage_unexp_token(scan, G_TOKEN_SYMBOL);
            break;
        }
    }

    dlp_portage_entry_free(&entry);
    g_scanner_destroy(scan);

    if (tok != G_TOKEN_EOF) {
        dlp_portage_manifest_free(manifest);
        return false;
    }
    return true;
}

/**
 * Free a list of dlp_portage_entry structures.
 *
 * @param manifest List to free.
 */
void dlp_portage_manifest_free(GList **manifest)
{
    GList *cur;
    struct dlp_portage_entry *e;

    if (manifest != NULL && *manifest != NULL) {
        for (cur = *manifest; cur != NULL; cur = cur->next) {
            e = cur->data;
            dlp_portage_entry_free(&e);
        }
        g_list_free(*manifest);
        *manifest = NULL;
    }
}

/**
 * Free a dlp_portage_entry structure.
 *
 * @param e Structure to free.
 */
static void dlp_portage_entry_free(struct dlp_portage_entry **e)
{
    if (e != NULL && *e != NULL) {
        dlp_mem_free(&(*e)->file);
        dlp_mem_free(&(*e)->blake2b);
        dlp_mem_free(&(*e)->sha512);
        dlp_mem_free(e);
    }
}

/**
 * Parse the type of an entry.
 *
 * @param scan  Scanner to use.
 * @param e     Destination.
 * @return True on success and false on failure.
 */
static bool dlp_portage_parse_type(GScanner *scan, struct dlp_portage_entry *e)
{
    g_return_val_if_fail(scan != NULL && e != NULL, false);

    e->type = (enum dlp_portage_type)GPOINTER_TO_INT(scan->value.v_symbol);
    return true;
}

/**
 * Parse the filename of an entry.
 *
 * @param scan  Scanner to use.
 * @param e     Destination.
 * @return True on success and false on failure.
 */
static bool dlp_portage_parse_file(GScanner *scan, struct dlp_portage_entry *e)
{
    GTokenType tok;

    g_return_val_if_fail(scan != NULL && e != NULL, false);

    scan->config->cset_identifier_first = G_CSET_A_2_Z G_CSET_a_2_z
        G_CSET_DIGITS "._-";
    scan->config->cset_identifier_nth = G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS
        "._-/%@!+~{}()[]";
    tok = g_scanner_get_next_token(scan);
    *scan->config = dlp_portage_config;

    if (tok != G_TOKEN_STRING) {
        dlp_portage_unexp_token(scan, G_TOKEN_STRING);
        return false;
    }

    if (e->file != NULL) {
        g_scanner_error(scan, "%s", _("duplicate filenames"));
        return false;
    }

    e->file = g_strdup(scan->value.v_string);
    return true;
}

/**
 * Parse the size of an entry.
 *
 * @param scan  Scanner to use.
 * @param e     Destination.
 * @return True on success and false on failure.
 */
static bool dlp_portage_parse_size(GScanner *scan, struct dlp_portage_entry *e)
{
    GTokenType tok;

    g_return_val_if_fail(scan != NULL && e != NULL, false);

    scan->config->cset_identifier_first = "";
    scan->config->cset_identifier_nth = "";
    tok = g_scanner_get_next_token(scan);
    *scan->config = dlp_portage_config;

    if (tok != G_TOKEN_INT) {
        dlp_portage_unexp_token(scan, G_TOKEN_INT);
        return false;
    }

    e->size = scan->value.v_int64;
    return true;
}

/**
 * Parse the digest of an entry.
 *
 * @param scan  Scanner to use.
 * @param e     Destination.
 * @return True on success and false on failure.
 */
static bool dlp_portage_parse_digest(GScanner *scan,
                                     struct dlp_portage_entry *e)
{
    int sym;
    GTokenType tok;

    g_return_val_if_fail(scan != NULL && e != NULL, false);

    sym = GPOINTER_TO_INT(scan->value.v_symbol);

    scan->config->cset_identifier_first = "01234567890abcdef";
    scan->config->cset_identifier_nth = "01234567890abcdef";
    tok = g_scanner_get_next_token(scan);
    *scan->config = dlp_portage_config;

    if (tok != G_TOKEN_STRING) {
        dlp_portage_unexp_token(scan, G_TOKEN_STRING);
        return false;
    }

    if (strlen(scan->value.v_string) != 128) {
        g_scanner_error(scan, "%s", _("invalid digest"));
        return false;
    }

    if (sym == DLP_PORTAGE_SYMBOL_BLAKE2B && e->blake2b == NULL) {
        e->blake2b = g_strdup(scan->value.v_string);
    } else if (sym == DLP_PORTAGE_SYMBOL_SHA512 && e->sha512 == NULL) {
        e->sha512 = g_strdup(scan->value.v_string);
    } else {
        g_scanner_error(scan, "%s", _("duplicate digests"));
        return false;
    }

    return true;
}

/**
 * Message handler for GScanner.
 *
 * @param scan  Source of the message.  Its user_data member must be NULL or
 *              a GError **.
 * @param msg   Message to assign to the error member of user_data.
 * @param error Unused; all invocations are treated as errors.
 */
static void dlp_portage_error(GScanner *scan, gchar *msg, gboolean error)
{
    GError **err;

    (void)error;

    g_return_if_fail(scan != NULL && msg != NULL);

    if ((err = scan->user_data) != NULL) {
        g_set_error(err, DLP_ERROR, DLP_PORTAGE_ERROR_LEX, "%u:%u: %s",
                    scan->line, scan->position, msg);
    }
}

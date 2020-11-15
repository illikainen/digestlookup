/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 *
 * References:
 * - Debian Policy Manual, version 4.3.0.3,
 *   https://debian.org/doc/debian-policy/policy.txt.
 * - Debian Repository Format,
 *   https://wiki.debian.org/DebianRepository/Format
 */

#include "dlp_apt.h"

#include <glib/gi18n.h>

#include "dlp_error.h"

#define dlp_apt_unexp_token(scanner, exp_token)                                \
    g_scanner_unexp_token(scanner, exp_token, NULL, NULL, NULL, G_STRLOC, true)

struct dlp_apt_symbol {
    const char *name;
    bool (*fn)(GScanner *scanner, GHashTable *ht, const char *key);
    guint scope;
    bool required;
};

static const GScannerConfig dlp_apt_config = {
    /*
     * Valid characters for field names as specified in section 5.1 of the
     * Debian Policy Manual.  Value parsers may override the scanner config
     * if they need to accept another set of characters.
     */
    .cset_identifier_first = "!\"$%&'()*+,./;<=>?@[\\]^_`{|}~" G_CSET_A_2_Z
        G_CSET_a_2_z G_CSET_DIGITS,
    .cset_identifier_nth = "!\"#$%&'()*+,-./;<=>?@[\\]^_`{|}~" G_CSET_A_2_Z
        G_CSET_a_2_z G_CSET_DIGITS,
    .case_sensitive = 1,
    .cset_skip_characters = " \t",
    .identifier_2_string = 1,
    .numbers_2_int = 1,
    .scan_identifier = 1,
    .scan_symbols = 1,
};

static void dlp_apt_ht_destroy(gpointer ptr);
static bool dlp_apt_read(int fd, struct dlp_apt_symbol *symbols, GList **list,
                         GError **error) DLP_NODISCARD;
static bool dlp_apt_parse_package(GScanner *scanner, GHashTable *ht,
                                  const char *key) DLP_NODISCARD;
static bool dlp_apt_parse_ignore(GScanner *scanner, GHashTable *ht,
                                 const char *key) DLP_NODISCARD;
static bool dlp_apt_check_required(struct dlp_apt_symbol *symbols, GList *list,
                                   GError **error) DLP_NODISCARD;
static void dlp_apt_error(GScanner *scanner, gchar *msg, gboolean error);

/**
 * Read an APT release file.
 *
 * @param fd      File descriptor to read.
 * @param release Hash table for the release fields.  It is allocated by dlp_apt
 *                and must be freed with dlp_apt_ht_free() after use.
 * @param error   Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_apt_read_release(int fd, GHashTable **release, GError **error)
{
    struct dlp_apt_symbol symbols[] = {
        /* clang-format off */
        { "Acquire-By-Hash",            dlp_apt_parse_ignore,       0,  false },
        { "Architectures",              dlp_apt_parse_ignore,       0,  false },
        { "Changelogs",                 dlp_apt_parse_ignore,       0,  false },
        { "Codename",                   dlp_apt_parse_ignore,       0,  false },
        { "Components",                 dlp_apt_parse_ignore,       0,  false },
        { "Date",                       dlp_apt_parse_ignore,       0,  false },
        { "Description",                dlp_apt_parse_ignore,       0,  false },
        { "Label",                      dlp_apt_parse_ignore,       0,  false },
        { "MD5Sum",                     dlp_apt_parse_ignore,       0,  false },
        { "Origin",                     dlp_apt_parse_ignore,       0,  false },
        { "SHA256",                     dlp_apt_parse_ignore,       0,  false },
        { "Suite",                      dlp_apt_parse_ignore,       0,  false },
        { "Version",                    dlp_apt_parse_ignore,       0,  false },
        { NULL,                         NULL,                       0,  false },
        /* clang-format on */
    };
    GList *list;

    g_return_val_if_fail(fd >= 0 && release != NULL, false);
    *release = NULL;

    if (!dlp_apt_read(fd, symbols, &list, error)) {
        return false;
    }

    if (g_list_length(list) != 1) {
        g_set_error(error, DLP_ERROR, DLP_APT_ERROR_DUPLICATE, "%s",
                    _("duplicate release entries"));
        dlp_apt_list_free(&list);
        return false;
    }

    *release = list->data;
    g_list_free(list);
    return true;
}

/**
 * Read an APT source file.
 *
 * Source files does not seem to have any field that is required to have a
 * unique value.  Even the value of the "Package" field may be used by multiple
 * packages (the same package may have multiple versions available; see e.g. acl
 * or grub2 in Debian Buster).
 *
 * For ease of implementation, every package in the source file is allocated a
 * new hash table, and they are returned in a linked list.
 *
 * @param fd    File descriptor to read.
 * @param pkgs  A linked list that contains one hash table per package.  It must
 *              be freed with dlp_apt_list_free() after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_apt_read_sources(int fd, GList **pkgs, GError **error)
{
    struct dlp_apt_symbol symbols[] = {
        /* clang-format off */
        { "Architecture",               dlp_apt_parse_ignore,       0,  false },
        { "Autobuild",                  dlp_apt_parse_ignore,       0,  false },
        { "Binary",                     dlp_apt_parse_ignore,       0,  false },
        { "Build-Conflicts",            dlp_apt_parse_ignore,       0,  false },
        { "Build-Conflicts-Indep",      dlp_apt_parse_ignore,       0,  false },
        { "Build-Depends",              dlp_apt_parse_ignore,       0,  false },
        { "Build-Depends-Arch",         dlp_apt_parse_ignore,       0,  false },
        { "Build-Depends-Indep",        dlp_apt_parse_ignore,       0,  false },
        { "Build-Indep-Architecture",   dlp_apt_parse_ignore,       0,  false },
        { "Checksums-Sha256",           dlp_apt_parse_ignore,       0,  false },
        { "Comment",                    dlp_apt_parse_ignore,       0,  false },
        { "Dgit",                       dlp_apt_parse_ignore,       0,  false },
        { "Directory",                  dlp_apt_parse_ignore,       0,  false },
        { "Dm-Upload-Allowed",          dlp_apt_parse_ignore,       0,  false },
        { "Extra-Source-Only",          dlp_apt_parse_ignore,       0,  false },
        { "Files",                      dlp_apt_parse_ignore,       0,  false },
        { "Format",                     dlp_apt_parse_ignore,       0,  false },
        { "Go-Import-Path",             dlp_apt_parse_ignore,       0,  false },
        { "Homepage",                   dlp_apt_parse_ignore,       0,  false },
        { "Maintainer",                 dlp_apt_parse_ignore,       0,  false },
        { "Original-Maintainer",        dlp_apt_parse_ignore,       0,  false },
        { "Package",                    dlp_apt_parse_package,      0,  true  },
        { "Package-List",               dlp_apt_parse_ignore,       0,  false },
        { "Priority",                   dlp_apt_parse_ignore,       0,  false },
        { "Python-Version",             dlp_apt_parse_ignore,       0,  false },
        { "Python3-Version",            dlp_apt_parse_ignore,       0,  false },
        { "Ruby-Versions",              dlp_apt_parse_ignore,       0,  false },
        { "Section",                    dlp_apt_parse_ignore,       0,  false },
        { "Standards-Version",          dlp_apt_parse_ignore,       0,  false },
        { "Testsuite",                  dlp_apt_parse_ignore,       0,  false },
        { "Testsuite-Triggers",         dlp_apt_parse_ignore,       0,  false },
        { "Uploaders",                  dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Arch",                   dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Browser",                dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Bzr",                    dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Cvs",                    dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Darcs",                  dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Git",                    dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Hg",                     dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Mtn",                    dlp_apt_parse_ignore,       0,  false },
        { "Vcs-Svn",                    dlp_apt_parse_ignore,       0,  false },
        { "Version",                    dlp_apt_parse_ignore,       0,  false },
        { NULL,                         NULL,                       0,  false },
        /* clang-format on */
    };

    g_return_val_if_fail(fd >= 0 && pkgs != NULL, false);

    return dlp_apt_read(fd, symbols, pkgs, error);
}

/**
 * Free a list that was allocated through dlp_apt.
 *
 * @param list List to free.
 */
void dlp_apt_list_free(GList **list)
{
    if (list != NULL && *list != NULL) {
        g_list_free_full(*list, dlp_apt_ht_destroy);
        *list = NULL;
    }
}

/**
 * Free a hash table that was allocated through dlp_apt.
 *
 * @param ht Hash table to free.
 */
void dlp_apt_ht_free(GHashTable **ht)
{
    if (ht != NULL && *ht != NULL) {
        dlp_apt_ht_destroy(*ht);
        *ht = NULL;
    }
}

/**
 * Destroy a hash table.
 *
 * This function is declared with a gpointer to avoid undefined behavior if
 * it's used as a GDestroyNotify function pointer.
 *
 * See:
 * - ISO/IEC 9899:201x 6.2.5 §28
 * - ISO/IEC 9899:201x 6.3.2.3 §8
 *
 * @param ptr Hash table to destroy.
 */
static void dlp_apt_ht_destroy(gpointer ptr)
{
    if (ptr != NULL) {
        g_hash_table_destroy(ptr);
    }
}

/**
 * Read an APT metadata file.
 *
 * @param fd        File descriptor to read.
 * @param symbols   Symbol names, scopes and handlers.
 * @param list      A linked list that contains one hash table per element.
 *                  It must be freed with dlp_apt_list_free() after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_read(int fd, struct dlp_apt_symbol *symbols, GList **list,
                         GError **error)
{
    struct dlp_apt_symbol *sym;
    GHashTable *ht;
    GScanner *scanner;
    GTokenType tok;
    GTokenType nexttok;
    GScannerConfig config = dlp_apt_config;

    g_return_val_if_fail(fd >= 0 && symbols != NULL && list != NULL, false);

    scanner = g_scanner_new(&config);
    scanner->user_data = error;
    scanner->msg_handler = dlp_apt_error;
    g_scanner_input_file(scanner, fd);

    for (sym = symbols; sym->name != NULL; sym++) {
        g_scanner_scope_add_symbol(scanner, sym->scope, sym->name, sym);
    }

    ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    *list = g_list_prepend(NULL, ht);

    while ((tok = g_scanner_get_next_token(scanner)) != G_TOKEN_EOF) {
        /*
         * Symbol to parse.
         */
        if (tok != G_TOKEN_SYMBOL) {
            dlp_apt_unexp_token(scanner, G_TOKEN_SYMBOL);
            break;
        }

        sym = scanner->value.v_symbol;
        if (g_hash_table_lookup_extended(ht, sym->name, NULL, NULL)) {
            g_set_error(error, DLP_ERROR, DLP_APT_ERROR_DUPLICATE,
                        "%u:%u: %s: %s", scanner->line, scanner->position,
                        _("duplicate symbol"), sym->name);
            break;
        }

        /*
         * Separator between the symbol name and its value.
         */
        nexttok = g_scanner_get_next_token(scanner);
        if (nexttok != G_TOKEN_CHAR || scanner->value.v_char != ':') {
            dlp_apt_unexp_token(scanner, G_TOKEN_CHAR);
            break;
        }

        /*
         * Parse the symbol value.
         */
        if (!sym->fn(scanner, ht, sym->name)) {
            break;
        }

        /*
         * Separator between elements.
         */
        nexttok = g_scanner_peek_next_token(scanner);
        if (nexttok == G_TOKEN_CHAR && scanner->next_value.v_char == '\n') {
            g_scanner_get_next_token(scanner);

            if (g_scanner_peek_next_token(scanner) != G_TOKEN_EOF) {
                ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                           g_free);
                *list = g_list_prepend(*list, ht);
            }
        }
    }

    for (sym = symbols; sym->name != NULL; sym++) {
        g_scanner_scope_remove_symbol(scanner, sym->scope, sym->name);
    }
    g_scanner_destroy(scanner);

    if (tok != G_TOKEN_EOF) {
        dlp_apt_list_free(list);
        return false;
    }

    if (!dlp_apt_check_required(symbols, *list, error)) {
        dlp_apt_list_free(list);
        return false;
    }

    return true;
}

/**
 * Parse a package field.
 *
 * See:
 * - Debian Policy Manual, 5.6.1.
 *
 * @param scanner   Scanner to use.
 * @param ht        Hash table to store the field and value.
 * @param key       Key for the field value in the hash table.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_package(GScanner *scanner, GHashTable *ht,
                                  const char *key)
{
    GTokenType tok;

    g_return_val_if_fail(scanner != NULL, false);

    scanner->config->cset_identifier_first = G_CSET_a_2_z G_CSET_DIGITS;
    scanner->config->cset_identifier_nth = G_CSET_a_2_z G_CSET_DIGITS "+-.";

    tok = g_scanner_get_next_token(scanner);
    *scanner->config = dlp_apt_config;

    if (tok != G_TOKEN_STRING || strlen(scanner->value.v_string) < 2) {
        dlp_apt_unexp_token(scanner, G_TOKEN_STRING);
        return false;
    }

    g_hash_table_insert(ht, g_strdup(key), g_strdup(scanner->value.v_string));

    tok = g_scanner_get_next_token(scanner);
    if (tok != G_TOKEN_CHAR || scanner->value.v_char != '\n') {
        dlp_apt_unexp_token(scanner, G_TOKEN_CHAR);
        return false;
    }

    return true;
}

/**
 * Ignore tokens.
 *
 * @param scanner   Scanner to use.
 * @param ht        Not used.
 * @param key       Not used.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_ignore(GScanner *scanner, GHashTable *ht,
                                 const char *key)
{
    GTokenType tok;

    (void)ht;
    (void)key;

    g_return_val_if_fail(scanner != NULL, false);

    while ((tok = g_scanner_peek_next_token(scanner)) != G_TOKEN_EOF) {
        if (tok == G_TOKEN_ERROR) {
            g_scanner_get_next_token(scanner);
            dlp_apt_unexp_token(scanner, G_TOKEN_IDENTIFIER);
            return false;
        }

        if (tok == G_TOKEN_SYMBOL && scanner->position == 0) {
            return true;
        }

        if (tok == G_TOKEN_CHAR && scanner->next_value.v_char == '\n' &&
            scanner->position == 0) {
            return true;
        }

        g_scanner_get_next_token(scanner);
    }

    return true;
}

/**
 * Make sure that all required symbols have a non-NULL value.
 *
 * @param symbols   Symbol source.
 * @param list      List to check.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_check_required(struct dlp_apt_symbol *symbols, GList *list,
                                   GError **error)
{
    struct dlp_apt_symbol *sym;

    for (; list != NULL; list = list->next) {
        for (sym = symbols; sym->name != NULL; sym++) {
            if (sym->required && !g_hash_table_lookup(list->data, sym->name)) {
                g_set_error(error, DLP_ERROR, DLP_APT_ERROR_REQUIRED, "%s %s",
                            _("missing required field"), sym->name);
                return false;
            }
        }
    }
    return true;
}

/**
 * Message handler for GScanner.
 *
 * @param scanner   Source of the message.  Its user_data member must be
 *                  NULL or GError **.
 * @param msg       Message to assign to the user_data member if it's non-NULL.
 * @param error     Unused; all invocations are treated as errors.
 */
static void dlp_apt_error(GScanner *scanner, gchar *msg, gboolean error)
{
    (void)error;

    g_return_if_fail(scanner != NULL && msg != NULL);

    g_set_error(scanner->user_data, DLP_ERROR, DLP_APT_ERROR_LEX, "%u:%u: %s",
                scanner->line, scanner->position, msg);
}

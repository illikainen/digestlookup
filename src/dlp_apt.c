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
#include "dlp_mem.h"

#define dlp_apt_unexp_token(scan, exp_token)                                   \
    g_scanner_unexp_token(scan, exp_token, NULL, NULL, NULL, G_STRLOC, true)

struct dlp_apt_data {
    void *dst;
    GError **error;
};

struct dlp_apt_symbol {
    const char *name;
    bool (*fn)(GScanner *scanner, void *dst);
    glong offset;
    guint scope;
    bool required;
    bool seen;
};

static void dlp_apt_sources_free_1(gpointer ptr);
static void dlp_apt_files_free(GList **files);
static void dlp_apt_symbols_add(GScanner *scan, struct dlp_apt_symbol *syms);
static void dlp_apt_symbols_remove(GScanner *scan, struct dlp_apt_symbol *syms);
static bool dlp_apt_symbols_reset(struct dlp_apt_symbol *syms,
                                  GError **error) DLP_NODISCARD;
static bool dlp_apt_symbols_read(GScanner *scan, GError **error) DLP_NODISCARD;
static bool dlp_apt_parse_package(GScanner *scan, void *dst) DLP_NODISCARD;
static bool dlp_apt_parse_files(GScanner *scan, void *dst) DLP_NODISCARD;
static bool dlp_apt_parse_word(GScanner *scan, void *dst) DLP_NODISCARD;
static bool dlp_apt_parse_ignore(GScanner *scan, void *dst) DLP_NODISCARD;
static void dlp_apt_error(GScanner *scan, gchar *msg, gboolean error);

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
    .store_int64 = 1,
    .identifier_2_string = 1,
    .scan_identifier = 1,
    .scan_symbols = 1,
};

/**
 * Read an APT release file.
 *
 * @param fd      File descriptor to read.
 * @param release Structure with the release fields.  It is allocated by dlp_apt
 *                and must be freed with dlp_apt_release_free() after use.
 * @param error   Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_apt_release_read(int fd, struct dlp_apt_release **release,
                          GError **error)
{
    struct dlp_apt_symbol symbols[] = {
        /* clang-format off */
        { .name = "Acquire-By-Hash",          .fn = dlp_apt_parse_ignore },
        { .name = "Architectures",            .fn = dlp_apt_parse_ignore },
        { .name = "Changelogs",               .fn = dlp_apt_parse_ignore },
        { .name = "Codename",                 .fn = dlp_apt_parse_word,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, codename),
          .required = true },
        { .name = "Components",               .fn = dlp_apt_parse_ignore },
        { .name = "Date",                     .fn = dlp_apt_parse_ignore },
        { .name = "Description",              .fn = dlp_apt_parse_ignore },
        { .name = "Label",                    .fn = dlp_apt_parse_ignore },
        { .name = "MD5Sum",                   .fn = dlp_apt_parse_files,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, md5sum),
          .required = true },
        { .name = "Origin",                   .fn = dlp_apt_parse_ignore },
        { .name = "SHA256",                   .fn = dlp_apt_parse_files,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, sha256),
          .required = true },
        { .name = "Suite",                    .fn = dlp_apt_parse_word,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, suite),
          .required = true },
        { .name = "Version",                  .fn = dlp_apt_parse_ignore },
        { .name = NULL                                                   },
        /* clang-format on */
    };
    struct dlp_apt_data data;
    GTokenType tok;
    GScanner *scan;

    g_return_val_if_fail(fd >= 0 && release != NULL, false);

    data.error = error;
    data.dst = dlp_mem_alloc(sizeof(struct dlp_apt_release));

    scan = g_scanner_new(&dlp_apt_config);
    scan->user_data = &data;
    scan->msg_handler = dlp_apt_error;
    g_scanner_input_file(scan, fd);

    dlp_apt_symbols_add(scan, symbols);

    while ((tok = g_scanner_get_next_token(scan)) != G_TOKEN_EOF) {
        if (!dlp_apt_symbols_read(scan, error)) {
            break;
        }
    }

    dlp_apt_symbols_remove(scan, symbols);
    g_scanner_destroy(scan);

    *release = data.dst;
    if (tok != G_TOKEN_EOF || !dlp_apt_symbols_reset(symbols, error)) {
        dlp_apt_release_free(release);
        return false;
    }

    return true;
}

/**
 * Free a dlp_apt_release structure.
 *
 * @param release Structure to free.
 */
void dlp_apt_release_free(struct dlp_apt_release **release)
{
    if (release != NULL && *release != NULL) {
        dlp_apt_files_free(&(*release)->md5sum);
        dlp_apt_files_free(&(*release)->sha256);

        dlp_mem_free(&(*release)->codename);
        dlp_mem_free(&(*release)->suite);
        dlp_mem_free(release);
    }
}

/**
 * Read an APT source file.
 *
 * Note that source files does not seem to have any field that is required to
 * have a unique value.  Even the value of the "Package" field may be used by
 * multiple packages (the same package may have multiple versions available;
 * see e.g. acl or grub2 in Debian Buster).
 *
 * @param fd      File descriptor to read.
 * @param sources A linked list with one dlp_apt_source structure per element in
 *                the source file.  It must be freed with dlp_apt_sources_free()
 *                after use.
 * @param error   Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_apt_sources_read(int fd, GList **sources, GError **error)
{
    struct dlp_apt_symbol symbols[] = {
        /* clang-format off */
        { .name = "Architecture",             .fn = dlp_apt_parse_ignore },
        { .name = "Autobuild",                .fn = dlp_apt_parse_ignore },
        { .name = "Binary",                   .fn = dlp_apt_parse_ignore },
        { .name = "Build-Conflicts",          .fn = dlp_apt_parse_ignore },
        { .name = "Build-Conflicts-Indep",    .fn = dlp_apt_parse_ignore },
        { .name = "Build-Depends",            .fn = dlp_apt_parse_ignore },
        { .name = "Build-Depends-Arch",       .fn = dlp_apt_parse_ignore },
        { .name = "Build-Depends-Indep",      .fn = dlp_apt_parse_ignore },
        { .name = "Build-Indep-Architecture", .fn = dlp_apt_parse_ignore },
        { .name = "Checksums-Sha256",         .fn = dlp_apt_parse_files,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_source, checksums_sha256),
          .required = true },
        { .name = "Comment",                  .fn = dlp_apt_parse_ignore },
        { .name = "Dgit",                     .fn = dlp_apt_parse_ignore },
        { .name = "Directory",                .fn = dlp_apt_parse_ignore },
        { .name = "Dm-Upload-Allowed",        .fn = dlp_apt_parse_ignore },
        { .name = "Extra-Source-Only",        .fn = dlp_apt_parse_ignore },
        { .name = "Files",                    .fn = dlp_apt_parse_files,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_source, files),
          .required = true },
        { .name = "Format",                   .fn = dlp_apt_parse_ignore },
        { .name = "Go-Import-Path",           .fn = dlp_apt_parse_ignore },
        { .name = "Homepage",                 .fn = dlp_apt_parse_ignore },
        { .name = "Maintainer",               .fn = dlp_apt_parse_ignore },
        { .name = "Original-Maintainer",      .fn = dlp_apt_parse_ignore },
        { .name = "Package",                  .fn = dlp_apt_parse_package,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_source, package),
          .required = true },
        { .name = "Package-List",             .fn = dlp_apt_parse_ignore },
        { .name = "Priority",                 .fn = dlp_apt_parse_ignore },
        { .name = "Python-Version",           .fn = dlp_apt_parse_ignore },
        { .name = "Python3-Version",          .fn = dlp_apt_parse_ignore },
        { .name = "Ruby-Versions",            .fn = dlp_apt_parse_ignore },
        { .name = "Section",                  .fn = dlp_apt_parse_ignore },
        { .name = "Standards-Version",        .fn = dlp_apt_parse_ignore },
        { .name = "Testsuite",                .fn = dlp_apt_parse_ignore },
        { .name = "Testsuite-Triggers",       .fn = dlp_apt_parse_ignore },
        { .name = "Uploaders",                .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Arch",                 .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Browser",              .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Bzr",                  .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Cvs",                  .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Darcs",                .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Git",                  .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Hg",                   .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Mtn",                  .fn = dlp_apt_parse_ignore },
        { .name = "Vcs-Svn",                  .fn = dlp_apt_parse_ignore },
        { .name = "Version",                  .fn = dlp_apt_parse_ignore },
        { .name = NULL                                                   },
        /* clang-format on */
    };
    struct dlp_apt_data data;
    GTokenType tok;
    GTokenType nexttok;
    GScanner *scan;

    g_return_val_if_fail(fd >= 0 && sources != NULL, false);
    *sources = NULL;

    data.error = error;
    data.dst = dlp_mem_alloc(sizeof(struct dlp_apt_source));

    scan = g_scanner_new(&dlp_apt_config);
    scan->user_data = &data;
    scan->msg_handler = dlp_apt_error;
    g_scanner_input_file(scan, fd);

    dlp_apt_symbols_add(scan, symbols);

    while ((tok = g_scanner_get_next_token(scan)) != G_TOKEN_EOF) {
        if (!dlp_apt_symbols_read(scan, error)) {
            break;
        }

        nexttok = g_scanner_peek_next_token(scan);
        if (nexttok == G_TOKEN_CHAR && scan->next_value.v_char == '\n') {
            g_scanner_get_next_token(scan);

            *sources = g_list_prepend(*sources, data.dst);
            data.dst = dlp_mem_alloc(sizeof(struct dlp_apt_source));

            if (!dlp_apt_symbols_reset(symbols, error)) {
                break;
            }
        } else if (nexttok == G_TOKEN_EOF) {
            *sources = g_list_prepend(*sources, data.dst);
            data.dst = NULL;

            if (!dlp_apt_symbols_reset(symbols, error)) {
                break;
            }
        }
    }

    dlp_apt_sources_free_1(data.dst);
    dlp_apt_symbols_remove(scan, symbols);
    g_scanner_destroy(scan);

    if (tok != G_TOKEN_EOF) {
        dlp_apt_sources_free(sources);
        return false;
    }

    if (g_list_length(*sources) == 0) {
        g_set_error(error, DLP_ERROR, DLP_APT_ERROR_REQUIRED, _("no elements"));
        dlp_apt_sources_free(sources);
        return false;
    }

    return true;
}

/**
 * Free a list of dlp_apt_source structures.
 *
 * @param sources List to free.
 */
void dlp_apt_sources_free(GList **sources)
{
    if (sources != NULL && *sources != NULL) {
        g_list_free_full(*sources, dlp_apt_sources_free_1);
        *sources = NULL;
    }
}

/**
 * Free a dlp_apt_source structure.
 *
 * This function is declared with a gpointer to avoid undefined behavior if
 * it's used as a GDestroyNotify function pointer.
 *
 * See:
 * - ISO/IEC 9899:201x 6.2.5 §28
 * - ISO/IEC 9899:201x 6.3.2.3 §8
 *
 * @param ptr Structure to free.
 */
static void dlp_apt_sources_free_1(gpointer ptr)
{
    struct dlp_apt_source *s = ptr;

    if (s != NULL) {
        dlp_apt_files_free(&s->files);
        dlp_apt_files_free(&s->checksums_sha256);

        dlp_mem_free(&s->package);
        dlp_mem_free(&s);
    }
}

/**
 * Free a list of dlp_apt_file structures.
 *
 * @param files List to free.
 */
static void dlp_apt_files_free(GList **files)
{
    GList *elt;
    struct dlp_apt_file *f;

    if (files != NULL && *files != NULL) {
        for (elt = *files; elt != NULL; elt = elt->next) {
            f = elt->data;
            dlp_mem_free(&f->name);
            dlp_mem_free(&f->digest);
            dlp_mem_free(&f);
        }
        g_list_free(*files);
        *files = NULL;
    }
}

/**
 * Add symbols to the scanner.
 *
 * @param scan  Scanner to add the symbols to.
 * @param syms  Symbols to add.
 */
static void dlp_apt_symbols_add(GScanner *scan, struct dlp_apt_symbol *syms)
{
    g_return_if_fail(scan != NULL && syms != NULL);

    for (; syms->name != NULL; syms++) {
        g_scanner_scope_add_symbol(scan, syms->scope, syms->name, syms);
    }
}

/**
 * Remove symbols from the scanner.
 *
 * @param scan  Scanner to remove the symbols from.
 * @param syms  Symbols to remove.
 */
static void dlp_apt_symbols_remove(GScanner *scan, struct dlp_apt_symbol *syms)
{
    g_return_if_fail(scan != NULL && syms != NULL);

    for (; syms->name != NULL; syms++) {
        g_scanner_scope_remove_symbol(scan, syms->scope, syms->name);
    }
}

/**
 * Check and reset symbols.
 *
 * @param syms  Symbols to check and reset.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_symbols_reset(struct dlp_apt_symbol *syms, GError **error)
{
    g_return_val_if_fail(syms != NULL, false);

    for (; syms->name != NULL; syms++) {
        if (syms->required && !syms->seen) {
            g_set_error(error, DLP_ERROR, DLP_APT_ERROR_REQUIRED, "%s %s",
                        _("missing required field"), syms->name);
            return false;
        }
        syms->seen = false;
    }
    return true;
}

/**
 * Read a symbol and invoke its handler.
 *
 * @param scan  Scanner to use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_symbols_read(GScanner *scan, GError **error)
{
    GTokenType tok;
    struct dlp_apt_data *data;
    struct dlp_apt_symbol *sym;

    g_return_val_if_fail(scan != NULL && scan->user_data != NULL, false);

    /*
     * Symbol to parse.
     */
    tok = scan->token;
    if (tok != G_TOKEN_SYMBOL) {
        dlp_apt_unexp_token(scan, G_TOKEN_SYMBOL);
        return false;
    }

    sym = scan->value.v_symbol;
    if (sym->seen) {
        g_set_error(error, DLP_ERROR, DLP_APT_ERROR_DUPLICATE, "%u:%u: %s: %s",
                    scan->line, scan->position, _("duplicate symbol"),
                    sym->name);
        return false;
    }
    sym->seen = true;

    /*
     * Separator between the symbol name and its value.
     */
    tok = g_scanner_get_next_token(scan);
    if (tok != G_TOKEN_CHAR || scan->value.v_char != ':') {
        dlp_apt_unexp_token(scan, G_TOKEN_CHAR);
        return false;
    }

    /*
     * Parse the symbol value.
     */
    data = scan->user_data;
    return sym->fn(scan, G_STRUCT_MEMBER_P(data->dst, sym->offset));
}

/**
 * Parse a package field.
 *
 * See:
 * - Debian Policy Manual, 5.6.1.
 *
 * @param scan  Scanner to use.
 * @param dst   Destination for the field value.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_package(GScanner *scan, void *dst)
{
    GTokenType tok;
    char **pkg = dst;

    g_return_val_if_fail(scan != NULL && pkg != NULL, false);

    scan->config->cset_identifier_first = G_CSET_a_2_z G_CSET_DIGITS;
    scan->config->cset_identifier_nth = G_CSET_a_2_z G_CSET_DIGITS "+-.";

    tok = g_scanner_get_next_token(scan);
    *scan->config = dlp_apt_config;

    if (tok != G_TOKEN_STRING || strlen(scan->value.v_string) < 2) {
        dlp_apt_unexp_token(scan, G_TOKEN_STRING);
        return false;
    }

    *pkg = g_strdup(scan->value.v_string);

    tok = g_scanner_get_next_token(scan);
    if (tok != G_TOKEN_CHAR || scan->value.v_char != '\n') {
        dlp_apt_unexp_token(scan, G_TOKEN_CHAR);
        return false;
    }

    return true;
}

/**
 * Parse a field with file information.
 *
 * @param scan  Scanner to use.
 * @param dst   Destination for the field value.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_files(GScanner *scan, void *dst)
{
    GTokenType tok;
    bool success = false;
    struct dlp_apt_file *file = NULL;
    GList **files = dst;

    g_return_val_if_fail(scan != NULL && files != NULL, false);
    *files = NULL;

    /*
     * A newline is required between the field separator and the first value.
     */
    tok = g_scanner_get_next_token(scan);
    if (tok != G_TOKEN_CHAR || scan->value.v_char != '\n') {
        dlp_apt_unexp_token(scan, G_TOKEN_CHAR);
        return false;
    }

    do {
        /*
         * End tokens.
         */
        tok = g_scanner_peek_next_token(scan);
        if (tok == G_TOKEN_EOF || tok == G_TOKEN_SYMBOL ||
            (tok == G_TOKEN_CHAR && scan->value.v_char == '\n')) {
            success = true;
            break;
        }

        file = dlp_mem_alloc(sizeof(*file));
        *files = g_list_prepend(*files, file);

        /*
         * Digest.
         *
         * FIXME: the field type should be taken into account in order to
         * enforce a strict length requirement based on the digest algorithm.
         */
        tok = g_scanner_get_next_token(scan);
        if (tok != G_TOKEN_STRING || scan->value.v_string == NULL ||
            strlen(scan->value.v_string) < 32) {
            dlp_apt_unexp_token(scan, G_TOKEN_STRING);
            break;
        }
        file->digest = g_strdup(scan->value.v_string);

        /*
         * Size.
         */
        scan->config->cset_identifier_first = "";
        scan->config->cset_identifier_nth = "";
        tok = g_scanner_get_next_token(scan);
        *scan->config = dlp_apt_config;

        if (tok != G_TOKEN_INT) {
            dlp_apt_unexp_token(scan, G_TOKEN_INT);
            break;
        }
        file->size = scan->value.v_int64;

        /*
         * Name.
         */
        tok = g_scanner_get_next_token(scan);
        if (tok != G_TOKEN_STRING || scan->value.v_string == NULL) {
            dlp_apt_unexp_token(scan, G_TOKEN_STRING);
            break;
        }
        file->name = g_strdup(scan->value.v_string);

        /*
         * Separator.
         */
        if (g_scanner_get_next_token(scan) != G_TOKEN_CHAR ||
            scan->value.v_char != '\n') {
            dlp_apt_unexp_token(scan, G_TOKEN_CHAR);
            break;
        }
    } while (true);

    if (!success) {
        dlp_apt_files_free(files);
        return false;
    }

    if (*files == NULL) {
        struct dlp_apt_data *data = scan->user_data;
        g_set_error(data->error, DLP_ERROR, DLP_APT_ERROR_REQUIRED, "%s",
                    _("no elements"));
        return false;
    }

    return true;
}

/**
 * Parse a word.
 *
 * @param scan  Scanner to use.
 * @param dst   Destination for the field value.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_word(GScanner *scan, void *dst)
{
    GTokenType tok;
    char **word = dst;

    g_return_val_if_fail(scan != NULL && word != NULL, false);

    tok = g_scanner_get_next_token(scan);
    if (tok != G_TOKEN_STRING) {
        dlp_apt_unexp_token(scan, G_TOKEN_STRING);
        return false;
    }

    *word = g_strdup(scan->value.v_string);

    tok = g_scanner_get_next_token(scan);
    if (tok != G_TOKEN_CHAR || scan->value.v_char != '\n') {
        dlp_apt_unexp_token(scan, G_TOKEN_CHAR);
        return false;
    }

    return true;
}

/**
 * Ignore tokens.
 *
 * @param scan  Scanner to use.
 * @param dst   Not used.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_ignore(GScanner *scan, void *dst)
{
    GTokenType tok;

    g_return_val_if_fail(scan != NULL && dst != NULL, false);

    while ((tok = g_scanner_peek_next_token(scan)) != G_TOKEN_EOF) {
        if (tok == G_TOKEN_ERROR) {
            g_scanner_get_next_token(scan);
            dlp_apt_unexp_token(scan, G_TOKEN_IDENTIFIER);
            return false;
        }

        if (tok == G_TOKEN_SYMBOL && scan->position == 0) {
            return true;
        }

        if (tok == G_TOKEN_CHAR && scan->next_value.v_char == '\n' &&
            scan->position == 0) {
            return true;
        }

        g_scanner_get_next_token(scan);
    }

    return true;
}

/**
 * Message handler for GScanner.
 *
 * @param scan  Source of the message.  Its user_data member must be NULL or
 *              a dlp_apt_data structure.
 * @param msg   Message to assign to the error member of user_data.
 * @param error Unused; all invocations are treated as errors.
 */
static void dlp_apt_error(GScanner *scan, gchar *msg, gboolean error)
{
    struct dlp_apt_data *data;

    (void)error;

    g_return_if_fail(scan != NULL && msg != NULL);

    if ((data = scan->user_data) != NULL) {
        g_set_error(data->error, DLP_ERROR, DLP_APT_ERROR_LEX, "%u:%u: %s",
                    scan->line, scan->position, msg);
    }
}

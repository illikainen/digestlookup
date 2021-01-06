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

#include "dlp_apt.h"
#include "dlp_backend.h"
#include "dlp_curl.h"
#include "dlp_date.h"
#include "dlp_digest.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_gpg.h"
#include "dlp_lzma.h"
#include "dlp_mem.h"
#include "dlp_str.h"

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
static bool dlp_apt_parse_words(GScanner *scan, void *dst) DLP_NODISCARD;
static bool dlp_apt_parse_date(GScanner *scan, void *dst) DLP_NODISCARD;
static bool dlp_apt_parse_ignore(GScanner *scan, void *dst) DLP_NODISCARD;
static void dlp_apt_error(GScanner *scan, gchar *msg, gboolean error);
static bool dlp_apt_lookup(const struct dlp_cfg_repo *cfg,
                           const GPtrArray *regex, struct dlp_table *table,
                           GError **error) DLP_NODISCARD;
static bool dlp_apt_release_download(const char *path,
                                     const struct dlp_cfg_repo *cfg,
                                     GError **error) DLP_NODISCARD;
static bool dlp_apt_sources_download(const char *path,
                                     const struct dlp_cfg_repo *cfg,
                                     const struct dlp_apt_file *file,
                                     GError **error) DLP_NODISCARD;
static bool dlp_apt_sources_find(const struct dlp_cfg_repo *cfg,
                                 const GList *sources, const GPtrArray *regex,
                                 struct dlp_table *table,
                                 GError **error) DLP_NODISCARD;
static void dlp_apt_ctor(void) DLP_CONSTRUCTOR;
static void dlp_apt_dtor(void) DLP_DESTRUCTOR;

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
        { .name = "Date",                     .fn = dlp_apt_parse_date,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, date),
          .required = true },
        { .name = "Description",              .fn = dlp_apt_parse_ignore },
        { .name = "Label",                    .fn = dlp_apt_parse_ignore },
        { .name = "MD5Sum",                   .fn = dlp_apt_parse_files,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, md5sum),
          .required = false },
        { .name = "Origin",                   .fn = dlp_apt_parse_ignore },
        { .name = "SHA256",                   .fn = dlp_apt_parse_files,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, sha256),
          .required = true },
        { .name = "Suite",                    .fn = dlp_apt_parse_word,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, suite),
          .required = true },
        { .name = "Valid-Until",              .fn = dlp_apt_parse_date,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_release, valid_until),
          .required = false },
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
 *                after use.  Note that the list may be empty (i.e. NULL) if the
 *                file descriptor is empty.
 * @param error   Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_apt_sources_read(int fd, GList **sources, GError **error)
{
    struct dlp_apt_symbol symbols[] = {
        /* clang-format off */
        { .name = "Architecture",             .fn = dlp_apt_parse_ignore },
        { .name = "Autobuild",                .fn = dlp_apt_parse_ignore },
        { .name = "Binary",                   .fn = dlp_apt_parse_words,
          .offset = G_STRUCT_OFFSET(struct dlp_apt_source, binary),
          .required = true },
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
          .required = false },
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

    while (true) {
        /*
         * End tokens.
         */
        tok = g_scanner_peek_next_token(scan);
        if (tok == G_TOKEN_EOF || tok == G_TOKEN_SYMBOL ||
            (tok == G_TOKEN_CHAR && scan->next_value.v_char == '\n')) {
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
    }

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
 * Parse a list of folded words.
 *
 * See:
 * - Debian Policy Manual, 5.1.
 *
 * @param scan  Scanner to use.
 * @param dst   Destination for the field value.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_words(GScanner *scan, void *dst)
{
    guint scope;
    GTokenType tok;
    GPtrArray **words = dst;
    bool success = false;

    g_return_val_if_fail(scan != NULL && words != NULL, false);

    scan->config->cset_identifier_first = G_CSET_A_2_Z G_CSET_a_2_z
        G_CSET_DIGITS "!\"$%&'()*+-./;<=>?@[\\]^_`{|}~";
    scan->config->cset_identifier_nth = scan->config->cset_identifier_first;
    scan->config->cset_skip_characters = "\n,";

    scope = g_scanner_set_scope(scan, 1);
    *words = g_ptr_array_new_full(0, g_free);

    while (true) {
        /*
         * Leading whitespace used as a separator between the field name and
         * its first value as well as an indicator of a continuation line.
         */
        tok = g_scanner_get_next_token(scan);
        if (tok != G_TOKEN_CHAR || scan->value.v_char != ' ') {
            dlp_apt_unexp_token(scan, G_TOKEN_CHAR);
            break;
        }

        /*
         * Single word.
         */
        tok = g_scanner_get_next_token(scan);
        if (tok != G_TOKEN_STRING || scan->value.v_string == NULL) {
            dlp_apt_unexp_token(scan, G_TOKEN_STRING);
            break;
        }
        g_ptr_array_add(*words, g_strdup(scan->value.v_string));

        /*
         * Possible end-of-field token.
         */
        scan->config->scope_0_fallback = true;
        tok = g_scanner_peek_next_token(scan);
        if (tok != G_TOKEN_CHAR) {
            success = true;
            break;
        }
        scan->config->scope_0_fallback = false;
    }

    *scan->config = dlp_apt_config;
    g_scanner_set_scope(scan, scope);

    if (!success) {
        dlp_mem_ptr_array_unref(words);
        return false;
    }

    return true;
}

/**
 * Parse a date.
 *
 * @param scan  Scanner to use.
 * @param dst   Destination for the field value.
 * @return True on success and false on failure.
 */
static bool dlp_apt_parse_date(GScanner *scan, void *dst)
{
    GTokenType tok;
    GError *err = NULL;
    time_t *t = dst;

    g_return_val_if_fail(scan != NULL && dst != NULL, false);

    scan->config->cset_identifier_first = G_CSET_A_2_Z G_CSET_a_2_z;
    scan->config->cset_identifier_nth = G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS
        ",:+ ";
    tok = g_scanner_get_next_token(scan);
    *scan->config = dlp_apt_config;

    if (tok != G_TOKEN_STRING) {
        dlp_apt_unexp_token(scan, G_TOKEN_STRING);
        return false;
    }

    /*
     * The timezone may be specified as +0000, UTC, GMT or Z.
     */
    if (!dlp_date_parse(scan->value.v_string, "%a, %d %b %Y %H:%M:%S %z", t,
                        &err)) {
        if (g_error_matches(err, DLP_ERROR, DLP_DATE_ERROR_FORMAT)) {
            g_clear_error(&err);
            if (!dlp_date_parse(scan->value.v_string,
                                "%a, %d %b %Y %H:%M:%S %Z", t, NULL)) {
                dlp_apt_unexp_token(scan, G_TOKEN_STRING);
                return false;
            }
        } else {
            dlp_apt_unexp_token(scan, G_TOKEN_STRING);
            return false;
        }
    }

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

/**
 * Lookup one or more regular expressions.
 *
 * @param cfg   Configuration.
 * @param regex Regular expressions to lookup.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_lookup(const struct dlp_cfg_repo *cfg,
                           const GPtrArray *regex, struct dlp_table *table,
                           GError **error)
{
    bool stale;
    bool rv = false;
    int fd = -1;
    int tmpfd = -1;
    GList *sources = NULL;
    GList *sha256 = NULL;
    char *path = NULL;
    char *tmp = NULL;
    char *dir = NULL;
    struct dlp_apt_release *release = NULL;
    struct dlp_apt_file *file = NULL;

    g_return_val_if_fail(cfg != NULL && regex != NULL && table != NULL, false);

    if (!dlp_fs_data_path(&path, error, cfg->name, "Release", NULL) ||
        !dlp_fs_stale_p(path, cfg->cache, &stale, error) ||
        (stale && !dlp_fs_remove(path, error)) ||
        !dlp_apt_release_download(path, cfg, error) ||
        !dlp_fs_open(path, O_RDONLY, S_IRUSR, &fd, error) ||
        !dlp_apt_release_read(fd, &release, error) ||
        !dlp_fs_close(&fd, NULL)) {
        goto out;
    }
    dlp_mem_free(&path);

    if (!dlp_fs_data_path(&dir, error, cfg->name, "sources", NULL) ||
        (stale && !dlp_fs_remove(dir, error)) || !dlp_fs_mkdir(dir, error)) {
        goto out;
    }

    for (sha256 = release->sha256; sha256 != NULL; sha256 = sha256->next) {
        file = sha256->data;
        if (g_str_has_suffix(file->name, "/Sources.xz")) {
            /*
             * The unsanitized parts of the path originates from the config
             * file and the user-specific data directory.
             */
            tmp = g_strdup(file->name);
            dlp_str_sanitize_filename(tmp);
            path = g_build_filename(dir, tmp, NULL);
            dlp_mem_free(&tmp);

            if (!dlp_apt_sources_download(path, cfg, file, error) ||
                !dlp_fs_open(path, O_RDONLY, S_IRUSR, &fd, error) ||
                !dlp_fs_mkstemp(&tmpfd, error) ||
                !dlp_lzma_decompress(fd, tmpfd, error) ||
                !dlp_apt_sources_read(tmpfd, &sources, error) ||
                !dlp_apt_sources_find(cfg, sources, regex, table, error) ||
                !dlp_fs_close(&fd, NULL) || !dlp_fs_close(&tmpfd, NULL)) {
                break;
            }

            dlp_mem_free(&path);
            dlp_apt_sources_free(&sources);
        }
    }

    rv = sha256 == NULL;

out:
    rv = dlp_fs_close(&fd, rv ? error : NULL) && rv;
    rv = dlp_fs_close(&tmpfd, rv ? error : NULL) && rv;

    dlp_apt_release_free(&release);
    dlp_apt_sources_free(&sources);

    dlp_mem_free(&path);
    dlp_mem_free(&dir);

    return rv;
}

/**
 * Download and verify a 'Release' file.
 *
 * The output of the signature verification is stored in the destination path.
 * That is, the inline signature and any potential data outside of the PGP
 * header and/or footer are not written to the destination path.  The rationale
 * is that GPG and GPGME happily ignores any unsigned and potentially malicious
 * data outside of the PGP header and/or footer during signature verification;
 * see dlp_gpg_verify_attached().
 *
 * Unfortunately, a consequence of only storing the verified data is that it
 * cannot be re-verified when reusing already-downloaded release files.
 *
 * @param path  Destination path.
 * @param cfg   Configuration.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_release_download(const char *path,
                                     const struct dlp_cfg_repo *cfg,
                                     GError **error)
{
    int trusted_fd = -1;
    int tmp_fd = -1;
    int untrusted_fd = -1;
    char *url = NULL;
    CURL *curl = NULL;
    struct dlp_gpg *gpg = NULL;
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    bool rv = false;

    g_return_val_if_fail(path != NULL && cfg != NULL, false);

    if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
        url = g_strconcat(cfg->url, "/InRelease", NULL);
        g_info("%s: InRelease: downloading %s", cfg->name, url);

        if (!dlp_fs_mkstemp(&untrusted_fd, error) ||
            !dlp_curl_init(&curl, error) ||
            !dlp_curl_set(curl, CURLOPT_URL, url) ||
            !dlp_curl_set(curl, CURLOPT_CAINFO, cfg->ca_file) ||
            !dlp_curl_set(curl, CURLOPT_PINNEDPUBLICKEY, cfg->tls_key) ||
            !dlp_curl_set(curl, CURLOPT_USERAGENT, cfg->user_agent) ||
            !dlp_curl_set(curl, CURLOPT_WRITEDATA, &untrusted_fd)) {
            goto out;
        }

        if (!dlp_curl_perform(curl, error)) {
            goto out;
        }

        if (!dlp_fs_mkstemp(&tmp_fd, error) || !dlp_gpg_init(&gpg, error) ||
            !dlp_gpg_import_keys(gpg, cfg->verify_keys, trust, error) ||
            !dlp_gpg_verify_attached(gpg, untrusted_fd, tmp_fd, error)) {
            goto out;
        }
        g_info("%s: InRelease: verified signature", cfg->name);

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        if (!dlp_fs_open(path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR,
                         &trusted_fd, error) ||
            !dlp_fs_copy(tmp_fd, trusted_fd, error)) {
            goto out;
        }
    }

    rv = true;

out:
    rv = dlp_gpg_free(&gpg, rv ? error : NULL) && rv;
    rv = dlp_fs_close(&trusted_fd, rv ? error : NULL) && rv;
    rv = dlp_fs_close(&untrusted_fd, rv ? error : NULL) && rv;
    rv = dlp_fs_close(&tmp_fd, rv ? error : NULL) && rv;
    if (!rv) {
        /*
         * The release file isn't written here unless its signature is
         * successfully verified; so discarding errors is OK-ish.
         */
        DLP_DISCARD(dlp_fs_remove(path, NULL));
    }

    dlp_mem_free(&url);
    dlp_curl_free(&curl);

    return rv;
}

/**
 * Download and verify a 'Sources' file.
 *
 * @param path  Destination path.
 * @param cfg   Configuration.
 * @param file  File structure that originates from a PGP-verified Release file.
 *              This is used to build a URL and to verify the sha256 digest of
 *              the downloaded data.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_apt_sources_download(const char *path,
                                     const struct dlp_cfg_repo *cfg,
                                     const struct dlp_apt_file *file,
                                     GError **error)
{
    int trusted_fd = -1;
    int untrusted_fd = -1;
    char *url = NULL;
    CURL *curl = NULL;
    bool rv = false;
    GChecksumType algo = G_CHECKSUM_SHA256;
    enum dlp_digest_encode enc = DLP_DIGEST_ENCODE_HEX;

    g_return_val_if_fail(path != NULL && cfg != NULL && file != NULL, false);

    if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
        url = g_strconcat(cfg->url, "/", file->name, NULL);
        g_info("%s: %s: downloading %s (%.2fM)", cfg->name, file->name, url,
               file->size / 1024.0 / 1024);

        if (!dlp_fs_mkstemp(&untrusted_fd, error) ||
            !dlp_curl_init(&curl, error) ||
            !dlp_curl_set(curl, CURLOPT_URL, url) ||
            !dlp_curl_set(curl, CURLOPT_CAINFO, cfg->ca_file) ||
            !dlp_curl_set(curl, CURLOPT_PINNEDPUBLICKEY, cfg->tls_key) ||
            !dlp_curl_set(curl, CURLOPT_USERAGENT, cfg->user_agent) ||
            !dlp_curl_set(curl, CURLOPT_WRITEDATA, &untrusted_fd)) {
            goto out;
        }

        if (!dlp_curl_perform(curl, error)) {
            goto out;
        }

        if (!dlp_digest_cmp(untrusted_fd, algo, enc, file->digest, error)) {
            goto out;
        }
        g_info("%s: %s: verified sha256 (%s)", cfg->name, file->name,
               file->digest);

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        if (!dlp_fs_open(path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR,
                         &trusted_fd, error) ||
            !dlp_fs_copy(untrusted_fd, trusted_fd, error)) {
            goto out;
        }
    } else {
        if (!dlp_fs_open(path, O_RDONLY, S_IRUSR, &untrusted_fd, error) ||
            !dlp_digest_cmp(untrusted_fd, algo, enc, file->digest, error)) {
            goto out;
        }
        g_info("%s: %s: verified sha256 (%s)", cfg->name, file->name,
               file->digest);
    }

    rv = true;

out:
    rv = dlp_fs_close(&trusted_fd, rv ? error : NULL) && rv;
    rv = dlp_fs_close(&untrusted_fd, rv ? error : NULL) && rv;
    if (!rv) {
        /*
         * The source file isn't written here unless its digest (which
         * originates from a PGP-verified release file) is successfully
         * verified; so discarding errors is OK-ish.
         */
        DLP_DISCARD(dlp_fs_remove(path, NULL));
    }

    dlp_mem_free(&url);
    dlp_curl_free(&curl);

    return rv;
}

/**
 * Search a list of source structures for an array of regular expressions.
 *
 * @param cfg       Configuration.
 * @param sources   Source structures to search.
 * @param regex     Regular expressions to find.
 * @param table     Destination table for any matches.
 * @param error     Optional error information.
 * @return True on success (including 0 matches) and false on failure.
 */
static bool dlp_apt_sources_find(const struct dlp_cfg_repo *cfg,
                                 const GList *sources, const GPtrArray *regex,
                                 struct dlp_table *table, GError **error)
{
    guint i;
    GList *elt;
    struct dlp_apt_file *f;
    struct dlp_apt_source *s;
    GRegex *rx;
    GRegexMatchFlags flags = (GRegexMatchFlags)0;
    bool match = false;

    g_return_val_if_fail(cfg != NULL && regex != NULL && table != NULL, false);

    for (; sources != NULL; sources = sources->next) {
        s = sources->data;

        for (i = 0; i < regex->len; i++) {
            rx = regex->pdata[i];
            if (!(match = g_regex_match(rx, s->package, flags, NULL))) {
                for (elt = s->checksums_sha256; elt != NULL; elt = elt->next) {
                    f = elt->data;
                    if ((match = g_regex_match(rx, f->name, flags, NULL))) {
                        break;
                    }
                }
            }

            if (match) {
                for (elt = s->checksums_sha256; elt != NULL; elt = elt->next) {
                    f = elt->data;
                    if (!dlp_table_add_row(table, error, "repository",
                                           cfg->name, "package", s->package,
                                           "file", f->name, "algorithm",
                                           "sha256", "digest", f->digest,
                                           NULL)) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

/**
 * Constructor for the APT backend.
 */
/* cppcheck-suppress unusedFunction */
static void dlp_apt_ctor(void)
{
    static struct dlp_backend *be;

    be = dlp_mem_alloc(sizeof(*be));
    be->name = "apt";
    be->lookup = dlp_apt_lookup;

    dlp_backend_add(be);
}

/**
 * Destructor for the APT backend.
 */
/* cppcheck-suppress unusedFunction */
static void dlp_apt_dtor(void)
{
    static struct dlp_backend *be;

    if (dlp_backend_find("apt", &be, NULL)) {
        dlp_backend_remove(be);
        dlp_mem_free(&be);
    }
}

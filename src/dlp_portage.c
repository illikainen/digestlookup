/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_portage.h"

#include <errno.h>

#include <glib/gi18n.h>

#include "dlp_archive.h"
#include "dlp_backend.h"
#include "dlp_curl.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_gpg.h"
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
static bool dlp_portage_lookup(const struct dlp_cfg_repo *cfg,
                               const GPtrArray *regex, struct dlp_table *table,
                               GError **error) DLP_NODISCARD;
static bool dlp_portage_cleanup(const struct dlp_cfg_repo *cfg, const char *tar,
                                const char *sig, GError **error) DLP_NODISCARD;
static bool dlp_portage_download(const struct dlp_cfg_repo *cfg,
                                 const char *tar, const char *sig,
                                 GError **error) DLP_NODISCARD;
static bool dlp_portage_find(const struct dlp_cfg_repo *cfg, const char *tar,
                             const GPtrArray *regex, struct dlp_table *table,
                             GError **error) DLP_NODISCARD;
static void dlp_portage_ctor(void) DLP_CONSTRUCTOR;
static void dlp_portage_dtor(void) DLP_DESTRUCTOR;

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

/**
 * Lookup one or more regular expressions.
 *
 * @param cfg   Configuration.
 * @param regex Regular expressions to lookup.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_portage_lookup(const struct dlp_cfg_repo *cfg,
                               const GPtrArray *regex, struct dlp_table *table,
                               GError **error)
{
    bool rv;
    char *tar = NULL;
    char *sig = NULL;

    g_return_val_if_fail(cfg != NULL && regex != NULL && table != NULL, false);

    rv = dlp_fs_data_path(&tar, error, cfg->name, "portage.tar.xz", NULL) &&
         dlp_fs_data_path(&sig, error, cfg->name, "portage.tar.xz.sig", NULL) &&
         dlp_portage_cleanup(cfg, tar, sig, error) &&
         dlp_portage_download(cfg, tar, sig, error) &&
         dlp_portage_find(cfg, tar, regex, table, error);

    dlp_mem_free(&tar);
    dlp_mem_free(&sig);

    return rv;
}

/**
 * Cleanup stale files.
 *
 * @param cfg   Configuration.
 * @param tar   Path to the portage archive.
 * @param sig   Path to the portage archive signature.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_portage_cleanup(const struct dlp_cfg_repo *cfg, const char *tar,
                                const char *sig, GError **error)
{
    bool tar_stale;
    bool sig_stale;

    g_return_val_if_fail(cfg != NULL && tar != NULL && sig != NULL, false);

    if (!dlp_fs_stale_p(tar, cfg->cache, &tar_stale, error) ||
        !dlp_fs_stale_p(sig, cfg->cache, &sig_stale, error)) {
        return false;
    }

    if (tar_stale || sig_stale) {
        return dlp_fs_remove(tar, error) && dlp_fs_remove(sig, error);
    }

    return true;
}

/**
 * Download and verify the latest portage archive.
 *
 * The archive and the accompanying signature are written to the specified
 * paths if the signature verification succeeds after the files have been
 * downloaded.  Storing the signature file allows for re-verification when
 * using cached archives; however, it also means that potentially malicious
 * data is stored on disk because GPG ignores content outside of the PGP header
 * and/or footer in the signature; see dlp_gpg_verify_detached().
 *
 * TODO: reconsider whether to store and re-verify the signature file.
 *
 * @param cfg   Configuration.
 * @param tar   Destination path for the portage archive.
 * @param sig   Destination path for the portage archive signature.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_portage_download(const struct dlp_cfg_repo *cfg,
                                 const char *tar, const char *sig,
                                 GError **error)
{
    size_t i;
    const char *path[2] = { tar, sig };
    char *url[2] = { NULL };
    CURL *curl[3] = { NULL };
    struct dlp_gpg *gpg = NULL;
    int fd[2] = { -1 };
    int dstfd = -1;
    gpgme_validity_t trust = GPGME_VALIDITY_ULTIMATE;
    bool rv = false;

    g_return_val_if_fail(cfg != NULL && tar != NULL && sig != NULL, false);

    if (!g_file_test(tar, G_FILE_TEST_IS_REGULAR) ||
        !g_file_test(sig, G_FILE_TEST_IS_REGULAR)) {
        url[0] = g_strconcat(cfg->url, "/portage-latest.tar.xz", NULL);
        url[1] = g_strconcat(cfg->url, "/portage-latest.tar.xz.gpgsig", NULL);

        for (i = 0; i < G_N_ELEMENTS(url); i++) {
            if (!dlp_fs_mkstemp(&fd[i], error) ||
                !dlp_curl_init(&curl[i], error) ||
                !dlp_curl_set(curl[i], CURLOPT_URL, url[i]) ||
                !dlp_curl_set(curl[i], CURLOPT_CAINFO, cfg->ca_file) ||
                !dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, cfg->tls_key) ||
                !dlp_curl_set(curl[i], CURLOPT_USERAGENT, cfg->user_agent) ||
                !dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &fd[i])) {
                goto out;
            }
            g_info("%s: downloading %s", cfg->name, url[i]);
        }

        if (!dlp_curl_perform(curl, error)) {
            goto out;
        }

        if (!dlp_gpg_init(&gpg, error) ||
            !dlp_gpg_import_keys(gpg, cfg->verify_keys, trust, error) ||
            !dlp_gpg_verify_detached(gpg, fd[0], fd[1], error)) {
            goto out;
        }
        g_info("%s: verified signature", cfg->name);

        for (i = 0; i < G_N_ELEMENTS(path); i++) {
            int flags = O_RDWR | O_CREAT | O_EXCL; /* NOLINT */
            mode_t mode = S_IRUSR | S_IWUSR; /* NOLINT */

            if (!dlp_fs_open(path[i], flags, mode, &dstfd, error) ||
                !dlp_fs_copy(fd[i], dstfd, error) ||
                !dlp_fs_close(&dstfd, error)) {
                goto out;
            }
        }
    } else {
        for (i = 0; i < G_N_ELEMENTS(path); i++) {
            if (!dlp_fs_open(path[i], O_RDONLY, 0, &fd[i], error)) {
                goto out;
            }
        }

        if (!dlp_gpg_init(&gpg, error) ||
            !dlp_gpg_import_keys(gpg, cfg->verify_keys, trust, error) ||
            !dlp_gpg_verify_detached(gpg, fd[0], fd[1], error)) {
            goto out;
        }
        g_info("%s: verified signature", cfg->name);
    }

    rv = true;

out:
    rv = dlp_gpg_free(&gpg, rv ? error : NULL) && rv;
    rv = dlp_fs_close(&dstfd, rv ? error : NULL) && rv;

    for (i = 0; i < G_N_ELEMENTS(url); i++) {
        rv = dlp_fs_close(&fd[i], rv ? error : NULL) && rv;
        dlp_curl_free(&curl[i]);
        dlp_mem_free(&url[i]);
    }

    if (!rv) {
        /*
         * The files aren't written here unless the signature for the archive
         * is successfully verified after it's been downloaded; so discarding
         * errors is OK-ish.
         */
        DLP_DISCARD(dlp_fs_remove(tar, NULL));
        DLP_DISCARD(dlp_fs_remove(sig, NULL));
    }

    return rv;
}

/**
 * Search a portage archive for an array of regular expressions.
 *
 * @param cfg   Configuration.
 * @param tar   Path to the portage archive.
 * @param regex Regular expressions to search.
 * @param table Destination table for any matches.
 * @param error Optional error information.
 * @return True on success (including 0 matches) and false on failure.
 */
static bool dlp_portage_find(const struct dlp_cfg_repo *cfg, const char *tar,
                             const GPtrArray *regex, struct dlp_table *table,
                             GError **error)
{
    guint i;
    guint ntok;
    size_t len;
    char *buf = NULL;
    char *pkg = NULL;
    char **tok = NULL;
    GList *elt = NULL;
    GList *mnfst = NULL;
    struct dlp_portage_entry *e = NULL;
    struct archive *archive = NULL;
    struct archive_entry *entry = NULL;
    bool eof = false;
    bool rv = false;
    GRegexMatchFlags flags = (GRegexMatchFlags)0;

    g_return_val_if_fail(cfg != NULL && tar != NULL, false);
    g_return_val_if_fail(regex != NULL && table != NULL, false);

    if (!dlp_archive_read_new(&archive, error) ||
        !dlp_archive_read_format_tar(archive, error) ||
        !dlp_archive_read_filter_xz(archive, error) ||
        !dlp_archive_read_open_filename(archive, tar, 512, error)) {
        goto out;
    }

    while ((rv = dlp_archive_read_next_header(archive, &entry, &eof, error))) {
        if (eof) {
            break;
        }

        if (!dlp_archive_entry_tokenized_path(entry, &tok, &ntok, error)) {
            goto out;
        }

        if (ntok == 4 && g_strcmp0(tok[1], "metadata") != 0 &&
            g_strcmp0(tok[3], "Manifest") == 0) {
            pkg = g_strjoin("/", tok[1], tok[2], NULL);

            for (i = 0; i < regex->len; i++) {
                if (g_regex_match(regex->pdata[i], pkg, flags, NULL)) {
                    if (!dlp_archive_read_text(archive, &buf, &len, error) ||
                        !dlp_portage_manifest_read(buf, len, &mnfst, error)) {
                        goto out;
                    }

                    for (elt = mnfst; elt != NULL; elt = elt->next) {
                        e = elt->data;
                        if (e->type == DLP_PORTAGE_TYPE_DIST) {
                            if (!dlp_table_add_row(table, error, "repository",
                                                   cfg->name, "package", pkg,
                                                   "file", e->file, "algorithm",
                                                   "sha512", "digest",
                                                   e->sha512, NULL)) {
                                goto out;
                            }
                        }
                    }
                    dlp_mem_free(&buf);
                    dlp_portage_manifest_free(&mnfst);
                }
            }
            dlp_mem_free(&pkg);
        }
        g_strfreev(g_steal_pointer(&tok));
    }

    rv = true;

out:
    g_strfreev(g_steal_pointer(&tok));
    dlp_mem_free(&buf);
    dlp_mem_free(&pkg);
    dlp_portage_manifest_free(&mnfst);
    rv = dlp_archive_read_free(&archive, rv ? error : NULL) && rv;

    return rv && eof;
}

/**
 * Constructor for the portage backend.
 */
/* cppcheck-suppress unusedFunction */
static void dlp_portage_ctor(void)
{
    static struct dlp_backend *be;

    be = dlp_mem_alloc(sizeof(*be));
    be->name = "portage";
    be->lookup = dlp_portage_lookup;

    dlp_backend_add(be);
}

/**
 * Destructor for the portage backend.
 */
/* cppcheck-suppress unusedFunction */
static void dlp_portage_dtor(void)
{
    static struct dlp_backend *be;

    if (dlp_backend_find("portage", &be, NULL)) {
        dlp_backend_remove(be);
        dlp_mem_free(&be);
    }
}

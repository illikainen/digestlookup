/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_cli.h"

#include <glib.h>
#include <glib/gi18n.h>

#include "dlp_cfg.h"
#include "dlp_curl.h"
#include "dlp_gpg.h"
#include "dlp_log.h"
#include "dlp_mem.h"
#include "dlp_opts.h"
#include "dlp_table.h"

struct dlp_cli_thread {
    GThread *thread;
    GError *err;
    struct dlp_cfg_repo *repo;
    struct dlp_opts *opts;
    struct dlp_table *table;
};

static bool dlp_cli_lookup_p(const struct dlp_cfg_repo *repo,
                             char **strv) DLP_NODISCARD;
static void *dlp_cli_lookup(gpointer data) DLP_NODISCARD;

/**
 * Run the command-line interface.
 *
 * @param argc  Number of available arguments.
 * @param argv  Command-line arguments.
 * @return True on success and false on failure.
 */
bool dlp_cli(int argc, char **argv)
{
    guint i;
    GList *repos;
    struct dlp_opts *opts = NULL;
    struct dlp_cfg *cfg = NULL;
    struct dlp_cfg_repo *repo = NULL;
    struct dlp_table *table = NULL;
    struct dlp_cli_thread *thread = NULL;
    GPtrArray *threads = NULL;
    GError *err = NULL;
    bool rv = false;

    g_return_val_if_fail(argc > 0 && argv != NULL, false);

    if (!dlp_gpg_global_init(&err) || !dlp_curl_global_init(&err)) {
        goto out;
    }

    dlp_table_init(&table);
    if (!dlp_opts_parse(argc, argv, &opts, &err) ||
        !dlp_cfg_read(opts->config, &cfg, &err) ||
        !dlp_table_add_columns(table, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL)) {
        goto out;
    }
    dlp_log_set_verbosity(opts->verbose);

    threads = g_ptr_array_new_full(0, g_free);
    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        repo = repos->data;
        if (opts->repos == NULL || dlp_cli_lookup_p(repo, opts->repos)) {
            thread = dlp_mem_alloc(sizeof(*thread));
            thread->opts = opts;
            thread->table = table;
            thread->repo = repo;
            thread->thread = g_thread_new(repo->name, dlp_cli_lookup, thread);
            g_ptr_array_add(threads, thread);
        }
    }

    rv = true;
    for (i = 0; i < threads->len; i++) {
        thread = threads->pdata[i];
        if (!GPOINTER_TO_INT(g_thread_join(thread->thread))) {
            if (err == NULL) {
                err = thread->err;
            }
            rv = false;
        }
    }

    if (rv) {
        dlp_table_print(table);
    }

out:
    dlp_cfg_free(&cfg);
    dlp_opts_free(&opts);
    dlp_table_free(&table);
    dlp_mem_ptr_array_unref(&threads);

    if (!rv) {
        g_critical("%s", err != NULL ? err->message : _("unknown error"));
        g_clear_error(&err);
    }

    return rv;
}

/**
 * Check if a repository should be included in the lookup.
 *
 * @param repo  A repository to check for inclusion.
 * @param strv  A NULL-terminated array of strings.
 * @return True if the string is found and false otherwise.
 */
static bool dlp_cli_lookup_p(const struct dlp_cfg_repo *repo, char **strv)
{
    g_return_val_if_fail(strv != NULL && repo != NULL, false);

    for (; *strv != NULL; strv++) {
        if (g_strcmp0(*strv, repo->name) == 0 ||
            g_strcmp0(*strv, repo->backend->name) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Lookup one or more regular expressions.
 *
 * @param data A dlp_cli_thread structure.
 * @return True on success and false on failure as a gpointer.
 */
static void *dlp_cli_lookup(gpointer data)
{
    char *patterns;
    struct dlp_cli_thread *t = data;

    g_return_val_if_fail(t != NULL, GINT_TO_POINTER(false));

    patterns = g_strjoinv(", ", t->opts->patterns);
    g_debug("%s: looking up %s", t->repo->name, patterns);
    dlp_mem_free(&patterns);

    if (t->repo->backend->lookup != NULL &&
        !t->repo->backend->lookup(t->repo, t->opts, t->table, &t->err)) {
        g_prefix_error(&t->err, "%s: ", t->repo->name);
        return GINT_TO_POINTER(false);
    }
    return GINT_TO_POINTER(true);
}

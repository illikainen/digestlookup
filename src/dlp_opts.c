/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_opts.h"

#include <glib/gi18n.h>

#include "dlp_error.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

/**
 * Parse command-line arguments.
 *
 * @param argc  Number of available arguments.
 * @param argv  Arguments to parse.
 * @param opts  Structure with the option values that must be freed with
 *              dlp_opts_free() after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_opts_parse(int argc, char **argv, struct dlp_opts **opts,
                    GError **error)
{
    struct dlp_opts o = { 0 };
    GOptionEntry elts[] = {
        { .long_name = "config",
          .short_name = 'c',
          .arg = G_OPTION_ARG_FILENAME,
          .arg_data = &o.config,
          .description = "Configuration file",
          .arg_description = "path" },
        { .long_name = "repos",
          .short_name = 'r',
          .arg = G_OPTION_ARG_STRING_ARRAY,
          .arg_data = &o.repos,
          .description = "Restrict the lookup to one or more repositories",
          .arg_description = "repo" },
        { .long_name = "verbose",
          .short_name = 'v',
          .arg = G_OPTION_ARG_NONE,
          .arg_data = &o.verbose,
          .description = "Show verbose messages" },
        { .long_name = NULL },
    };
    GOptionContext *ctx;

    g_return_val_if_fail(argc > 0 && argv != NULL && opts != NULL, false);
    *opts = NULL;

    ctx = g_option_context_new("patterns...");
    g_option_context_add_main_entries(ctx, elts, NULL);

    if (!g_option_context_parse(ctx, &argc, &argv, error)) {
        g_option_context_free(ctx);
        return false;
    }
    g_option_context_free(ctx);

    *opts = dlp_mem_alloc(sizeof(**opts));
    **opts = o;

    if (argv == NULL || *argv == NULL || *(argv + 1) == NULL) {
        g_set_error(error, DLP_ERROR, G_OPTION_ERROR_BAD_VALUE, "%s",
                    _("nothing to lookup"));
        dlp_opts_free(opts);
        return false;
    }

    (*opts)->patterns = g_strdupv(argv + 1);
    (*opts)->regex = g_ptr_array_new_full(0, dlp_mem_regex_destroy);

    for (argv++; *argv != NULL; argv++) {
        GRegex *rx = g_regex_new(*argv,
                                 /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
                                 (GRegexCompileFlags)(G_REGEX_CASELESS |
                                                      G_REGEX_DOLLAR_ENDONLY |
                                                      G_REGEX_OPTIMIZE),
                                 (GRegexMatchFlags)0, error);
        if (rx == NULL) {
            dlp_opts_free(opts);
            return false;
        }
        g_ptr_array_add((*opts)->regex, rx);
    }

    return true;
}

/**
 * Free a dlp_opts structure.
 *
 * @param opts Structure to free.
 */
void dlp_opts_free(struct dlp_opts **opts)
{
    if (opts != NULL && *opts != NULL) {
        g_strfreev((*opts)->repos);
        g_strfreev((*opts)->patterns);
        dlp_mem_ptr_array_unref(&(*opts)->regex);
        dlp_mem_free(&(*opts)->config);
        dlp_mem_free(opts);
    }
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_backend.h"

#include <glib/gi18n.h>

#include "dlp_error.h"

static GList *dlp_backends;

/**
 * Add a backend.
 *
 * @param be Backend to add.
 */
void dlp_backend_add(struct dlp_backend *be)
{
    struct dlp_backend *old;

    g_return_if_fail(be != NULL && be->name != NULL);

    if (!dlp_backend_find(be->name, &old, NULL)) {
        dlp_backends = g_list_prepend(dlp_backends, be);
    }
}

/**
 * Remove a backend.
 *
 * @param be Backend to remove.
 */
void dlp_backend_remove(struct dlp_backend *be)
{
    GList *elt;

    g_return_if_fail(be != NULL);

    if ((elt = g_list_find(dlp_backends, be)) != NULL) {
        dlp_backends = g_list_delete_link(dlp_backends, elt);
    }
}

/**
 * Find a backend.
 *
 * @param name  Name of the backend to find.
 * @param be    Backend that was found.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_backend_find(const char *name, struct dlp_backend **be, GError **error)
{
    GList *elt;
    struct dlp_backend *cur;

    g_return_val_if_fail(name != NULL && be != NULL, false);
    *be = NULL;

    for (elt = dlp_backends; elt != NULL; elt = elt->next) {
        cur = elt->data;
        if (g_strcmp0(cur->name, name) == 0) {
            *be = cur;
            return true;
        }
    }

    g_set_error(error, DLP_ERROR, DLP_BACKEND_ERROR_NOT_FOUND, "%s: %s", name,
                _("unknown backend"));
    return false;
}

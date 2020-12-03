/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_GPG_H
#define DLP_GPG_H

#include <stdbool.h>

#include <glib.h>
#include <gpgme.h>

#include "config.h"
#include "dlp.h"

enum dlp_gpg_error {
    DLP_GPG_ERROR_FAILED = 1,
};

struct dlp_gpg_verify {
    char *fpr;
};

struct dlp_gpg;

bool dlp_gpg_global_init(GError **error) DLP_NODISCARD;
bool dlp_gpg_init(struct dlp_gpg **gpg, GError **error) DLP_NODISCARD;
bool dlp_gpg_free(struct dlp_gpg **gpg, GError **error) DLP_NODISCARD;
bool dlp_gpg_import_key(struct dlp_gpg *gpg, const char *path,
                        gpgme_validity_t trust, GError **error) DLP_NODISCARD;
bool dlp_gpg_import_keys(struct dlp_gpg *gpg, const GPtrArray *paths,
                         gpgme_validity_t trust, GError **error) DLP_NODISCARD;
bool dlp_gpg_check_keyring(struct dlp_gpg *gpg, rsize_t *count,
                           GError **error) DLP_NODISCARD;
bool dlp_gpg_verify_attached(struct dlp_gpg *gpg, int msgfd, int outfd,
                             GError **error) DLP_NODISCARD;
bool dlp_gpg_verify_detached(struct dlp_gpg *gpg, int msgfd, int sigfd,
                             GError **error) DLP_NODISCARD;

#endif /* DLP_GPG_H */

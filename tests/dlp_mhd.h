/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_MHD_H
#define DLP_MHD_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <glib.h>

#include "config.h"
#include "dlp.h"

enum dlp_mhd_error {
    DLP_MHD_ERROR_FAILED = 1,
};

struct dlp_mhd;

bool dlp_mhd_init(struct dlp_mhd **mhd) DLP_NODISCARD;
bool dlp_mhd_free(struct dlp_mhd *mhd) DLP_NODISCARD;
bool dlp_mhd_start(struct dlp_mhd *mhd, const char *addr, uint16_t port,
                   const char *key, const char *cert,
                   GError **error) DLP_NODISCARD;
bool dlp_mhd_stop(struct dlp_mhd *mhd) DLP_NODISCARD;
bool dlp_mhd_session_add(struct dlp_mhd *mhd, const char *method,
                         const char *version, const char *path,
                         const char *user_agent, const void *content,
                         size_t content_len, time_t mtime, unsigned int status,
                         GError **error) DLP_NODISCARD;
bool dlp_mhd_session_remove_all(struct dlp_mhd *mhd) DLP_NODISCARD;

#endif /* DLP_MHD_H */

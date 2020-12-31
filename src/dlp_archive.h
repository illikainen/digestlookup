/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_ARCHIVE_H
#define DLP_ARCHIVE_H

#include <stdbool.h>

#include <archive.h>
#include <archive_entry.h>
#include <glib.h>

#include "dlp.h"

enum dlp_archive_error {
    DLP_ARCHIVE_ERROR_FAILED = 1,
};

bool dlp_archive_read_new(struct archive **archive,
                          GError **error) DLP_NODISCARD;
bool dlp_archive_read_free(struct archive **archive,
                           GError **error) DLP_NODISCARD;
bool dlp_archive_read_format_tar(struct archive *archive,
                                 GError **error) DLP_NODISCARD;
bool dlp_archive_read_filter_xz(struct archive *archive,
                                GError **error) DLP_NODISCARD;
bool dlp_archive_read_open_filename(struct archive *archive, const char *path,
                                    size_t blksize,
                                    GError **error) DLP_NODISCARD;
bool dlp_archive_read_next_header(struct archive *archive,
                                  struct archive_entry **entry, bool *eof,
                                  GError **error) DLP_NODISCARD;
bool dlp_archive_read_data(struct archive *archive, void *buf, size_t len,
                           la_ssize_t *outlen, GError **error) DLP_NODISCARD;
bool dlp_archive_read_text(struct archive *archive, char **buf, size_t *len,
                           GError **error) DLP_NODISCARD;
bool dlp_archive_entry_path(struct archive_entry *entry, const char **path,
                            GError **error) DLP_NODISCARD;
bool dlp_archive_entry_tokenized_path(struct archive_entry *entry, char ***tok,
                                      guint *len, GError **error) DLP_NODISCARD;

#endif /* DLP_ARCHIVE_H */

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_archive.h"

#include <errno.h>

#include "dlp_error.h"

static void dlp_archive_set_error(struct archive *archive, GError **error);

/**
 * Initialize an archive for reading.
 *
 * @param archive   Structure to initialize.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_new(struct archive **archive, GError **error)
{
    g_return_val_if_fail(archive != NULL, false);

    *archive = archive_read_new();
    if (*archive == NULL) {
        g_set_error(error, DLP_ERROR, ENOMEM, "%s", g_strerror(ENOMEM));
        return false;
    }
    return true;
}

/**
 * Free an archive opened for reading.
 *
 * @param archive   Structure to free.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_free(struct archive **archive, GError **error)
{
    if (archive != NULL && *archive != NULL) {
        if (archive_read_free(*archive) != ARCHIVE_OK) {
            /*
             * It's not documented in archive_read_free(3) whether the archive
             * structure is guaranteed to be in a state to read error messages
             * on failure.
             */
            g_set_error(error, DLP_ERROR, DLP_ARCHIVE_ERROR_FAILED,
                        "archive_read_free()");
            *archive = NULL;
            return false;
        }
        *archive = NULL;
    }

    return true;
}

/**
 * Enable support for tar archives.
 *
 * @param archive   Archive to use.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_format_tar(struct archive *archive, GError **error)
{
    g_return_val_if_fail(archive != NULL, false);

    if (archive_read_support_format_tar(archive) != ARCHIVE_OK) {
        dlp_archive_set_error(archive, error);
        return false;
    }
    return true;
}

/**
 * Enable support for xz-compressed archives.
 *
 * @param archive   Archive to use.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_filter_xz(struct archive *archive, GError **error)
{
    g_return_val_if_fail(archive != NULL, false);

    if (archive_read_support_filter_xz(archive) != ARCHIVE_OK) {
        dlp_archive_set_error(archive, error);
        return false;
    }
    return true;
}

/**
 * Open a file for reading.
 *
 * @param archive   Archive to use.
 * @param path      File to open.
 * @param blksize   Block size to use.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_open_filename(struct archive *archive, const char *path,
                                    size_t blksize, GError **error)
{
    g_return_val_if_fail(archive != NULL && path != NULL, false);

    if (archive_read_open_filename(archive, path, blksize) != ARCHIVE_OK) {
        dlp_archive_set_error(archive, error);
        return false;
    }
    return true;
}

/**
 * Read the next entry header.
 *
 * @param archive   Archive to read.
 * @param entry     Entry that was read.
 * @param eof       Whether this is the last entry.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_next_header(struct archive *archive,
                                  struct archive_entry **entry, bool *eof,
                                  GError **error)
{
    int rv;

    g_return_val_if_fail(archive != NULL && entry != NULL && eof != NULL,
                         false);

    rv = archive_read_next_header(archive, entry);
    if (rv == ARCHIVE_OK || rv == ARCHIVE_EOF) {
        *eof = rv == ARCHIVE_EOF;
        return true;
    }

    dlp_archive_set_error(archive, error);
    return false;
}

/**
 * Read the content of an entry.
 *
 * @param archive   Archive to read.
 * @param buf       Destination buffer.
 * @param len       Bytes to read.
 * @param outlen    Number of bytes that was read.  This is always >=0 if the
 *                  return value signifies success.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_data(struct archive *archive, void *buf, size_t len,
                           la_ssize_t *outlen, GError **error)
{
    g_return_val_if_fail(archive != NULL && buf != NULL && outlen != NULL,
                         false);
    *outlen = 0;
    if (len == 0 || len > SSIZE_MAX) {
        g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
        return false;
    }

    *outlen = archive_read_data(archive, buf, len);
    if (*outlen < 0) {
        dlp_archive_set_error(archive, error);
        return false;
    }

    return true;
}

/**
 * Read the content of an entry as a NUL-terminated string.
 *
 * Unlike dlp_archive_read_data(), this function reads the complete entry.
 *
 * @param archive   Archive to read.
 * @param buf       Destination buffer.
 * @param len       Optional length of the buffer.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_read_text(struct archive *archive, char **buf, size_t *len,
                           GError **error)
{
    char tmp[DLP_BUFSIZ];
    GString *str;
    la_ssize_t n;
    bool rv;

    g_return_val_if_fail(archive != NULL && buf != NULL, false);

    *buf = NULL;
    str = g_string_new(NULL);

    while ((rv = dlp_archive_read_data(archive, tmp, sizeof(tmp), &n, error))) {
        if (n == 0) {
            break;
        }
        g_string_append_len(str, tmp, n);
    }

    if (rv && str->len > 0) {
        if (len != NULL) {
            *len = str->len;
        }
        *buf = g_string_free(str, false);
        return true;
    }

    g_string_free(str, true);
    return false;
}

/**
 * Retrieve the path of an entry.
 *
 * @param entry Entry to read.
 * @param path  Path of the entry.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_entry_path(struct archive_entry *entry, const char **path,
                            GError **error)
{
    g_return_val_if_fail(entry != NULL && path != NULL, false);

    if ((*path = archive_entry_pathname(entry)) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_ARCHIVE_ERROR_FAILED, "bad path");
        return false;
    }
    return true;
}

/**
 * Retrieve the path of an entry separated by /.
 *
 * @param entry Entry to read.
 * @param tok   NULL-terminated array.
 * @param len   Number of elements in tok.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_archive_entry_tokenized_path(struct archive_entry *entry, char ***tok,
                                      guint *len, GError **error)
{
    const char *path;

    g_return_val_if_fail(entry != NULL && tok != NULL && len != NULL, false);
    *tok = NULL;
    *len = 0;

    if (!dlp_archive_entry_path(entry, &path, error)) {
        return false;
    }

    *tok = g_strsplit(path, "/", -1);
    *len = g_strv_length(*tok);
    return true;
}

/**
 * Propagate an error from libarchive to a GError.
 *
 * @param archive   Archive to read.
 * @param error     Optional error information.
 */
static void dlp_archive_set_error(struct archive *archive, GError **error)
{
    int code;
    const char *str;

    g_return_if_fail(archive != NULL);

    code = archive_errno(archive);
    str = archive_error_string(archive);
    g_set_error(error, DLP_ERROR, code, "%s", str ? str : "archive error");
}

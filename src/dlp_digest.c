/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_digest.h"

#include <errno.h>

#include <glib/gi18n.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

static bool dlp_digest_update(GChecksum *cksum, int fd, size_t size,
                              GError **error) DLP_NODISCARD;
static bool dlp_digest_encode(GChecksum *cksum, enum dlp_digest_encode enc,
                              char **digest, GError **error) DLP_NODISCARD;

/**
 * Compare the content of a file descriptor against a digest.
 *
 * @param fd        File descriptor to read.
 * @param type      Digest algorithm.
 * @param enc       Digest encoding.
 * @param digest    Digest to compare.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_digest_cmp(int fd, GChecksumType type, enum dlp_digest_encode enc,
                    char *digest, GError **error)
{
    char *cmpdigest;

    g_return_val_if_fail(fd >= 0 && digest != NULL, false);

    if (!dlp_digest_compute(fd, type, enc, &cmpdigest, error)) {
        return false;
    }

    if (g_strcmp0(digest, cmpdigest) != 0) {
        g_set_error(error, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH, "%s: %s != %s",
                    _("digest mismatch"), digest, cmpdigest);
        dlp_mem_free(&cmpdigest);
        return false;
    }

    dlp_mem_free(&cmpdigest);
    return true;
}

/**
 * Compute the message digest for the content of a file descriptor.
 *
 * The file descriptor is positioned at the 0th offset before the digest of its
 * content is computed.  It is repositioned at the 0th offset if the operation
 * succeeds.
 *
 * @param fd        File descriptor to read.
 * @param type      Digest algorithm.
 * @param enc       Digest encoding.
 * @param digest    Message digest.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_digest_compute(int fd, GChecksumType type, enum dlp_digest_encode enc,
                        char **digest, GError **error)
{
    GChecksum *cksum;
    size_t size;

    g_return_val_if_fail(fd >= 0 && digest != NULL, false);
    *digest = NULL;

    if (!dlp_fs_seek(fd, 0, SEEK_SET, error) ||
        !dlp_fs_size(fd, &size, error)) {
        return false;
    }

    cksum = g_checksum_new(type);
    if (cksum == NULL) {
        g_set_error(error, DLP_ERROR, DLP_DIGEST_ERROR_ALGORITHM, "%s",
                    _("unknown type"));
        return false;
    }

    if (!dlp_digest_update(cksum, fd, size, error) ||
        !dlp_digest_encode(cksum, enc, digest, error) ||
        !dlp_fs_seek(fd, 0, SEEK_SET, error)) {
        dlp_mem_free(digest);
        g_checksum_free(cksum);
        return false;
    }

    g_checksum_free(cksum);
    return true;
}

/**
 * Invoke g_checksum_update() until a file descriptor has been read.
 *
 * @param cksum Digest object to update.
 * @param fd    File descriptor to read.
 * @param size  Number of bytes to read.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_digest_update(GChecksum *cksum, int fd, size_t size,
                              GError **error)
{
    size_t len;
    gssize cklen;
    guchar buf[DLP_BUFSIZ] = { 0 };

    g_return_val_if_fail(cksum != NULL && fd >= 0, false);

    /*
     * An initial size of 0 is OK because the GChecksum structure is properly
     * initialized by GLib afaict (and both digestlookup and glib has test cases
     * for empty messages).
     */
    while (size != 0) {
        len = MIN(sizeof(buf), size);

        if (!dlp_fs_read_bytes(fd, buf, len, error)) {
            return false;
        }

        if (dlp_overflow_add(len, 0, &cklen)) {
            g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
            return false;
        }

        g_checksum_update(cksum, buf, cklen);
        size -= len;
    }

    if (!dlp_fs_read(fd, buf, 1, &len, NULL) || len != 0) {
        g_set_error(error, DLP_ERROR, DLP_DIGEST_ERROR_EOF, "%s",
                    _("expected EOF"));
        return false;
    }

    return size == 0;
}

/**
 * Encode a message digest.
 *
 * @param cksum     Digest object to encode
 * @param enc       Digest encoding.
 * @param digest    Message digest.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_digest_encode(GChecksum *cksum, enum dlp_digest_encode enc,
                              char **digest, GError **error)
{
    g_return_val_if_fail(cksum != NULL && digest != NULL, false);
    *digest = NULL;

    if (enc == DLP_DIGEST_ENCODE_HEX) {
        *digest = g_strdup(g_checksum_get_string(cksum));
    }

    if (*digest == NULL) {
        g_set_error(error, DLP_ERROR, DLP_DIGEST_ERROR_ENCODE,
                    _("cannot encode digest"));
        return false;
    }

    return true;
}

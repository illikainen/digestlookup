/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_lzma.h"

#include <errno.h>
#include <stdio.h>

#include <glib/gi18n.h>
#include <lzma.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_overflow.h"

static bool dlp_lzma_code(lzma_stream *strm, int infd, int outfd, size_t size,
                          GError **error) DLP_NODISCARD;

/**
 * Decompress LZMA or XZ data from a file descriptor.
 *
 * Both file descriptors are positioned at the 0th offset before the content
 * is decompressed.  The output file descriptor is also truncated to 0 bytes.
 * On success, both file descriptors are repositioned at the 0th offset.
 *
 * @param infd  File descriptor to read compressed data from.
 * @param outfd File descriptor to write decompressed data to.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_lzma_decompress(int infd, int outfd, GError **error)
{
    size_t size;
    bool rv;
    lzma_stream strm = LZMA_STREAM_INIT;

    g_return_val_if_fail(infd >= 0 && outfd >= 0 && infd != outfd, false);

    if (!dlp_fs_seek(infd, 0, SEEK_SET, error) ||
        !dlp_fs_seek(outfd, 0, SEEK_SET, error) ||
        !dlp_fs_truncate(outfd, 0, error) || !dlp_fs_size(infd, &size, error)) {
        return false;
    }

    if (lzma_auto_decoder(&strm, 1024 * 1024 * 256, 0) != LZMA_OK) {
        g_set_error(error, DLP_ERROR, DLP_LZMA_ERROR_FAILED,
                    "lzma_stream_decoder()");
        return false;
    }

    rv = dlp_lzma_code(&strm, infd, outfd, size, error) &&
         dlp_fs_seek(infd, 0, SEEK_SET, error) &&
         dlp_fs_seek(outfd, 0, SEEK_SET, error);

    lzma_end(&strm);

    return rv;
}

/**
 * Encode or decode data.
 *
 * @param strm  Stream to use.
 * @param infd  File descriptor to read from.
 * @param outfd File descriptor to write to.
 * @param size  Number of bytes to read from the input file descriptor.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_lzma_code(lzma_stream *strm, int infd, int outfd, size_t size,
                          GError **error)
{
    size_t len;
    lzma_ret rv;
    uint8_t inbuf[BUFSIZ] = { 0 };
    uint8_t outbuf[BUFSIZ] = { 0 };

    g_return_val_if_fail(strm != NULL && infd >= 0 && outfd >= 0, false);
    g_return_val_if_fail(infd != outfd && size != 0, false);

    strm->next_out = outbuf;
    strm->avail_out = sizeof(outbuf);

    do {
        if (strm->avail_in == 0) {
            len = MIN(sizeof(inbuf), size);

            if (!dlp_fs_read_bytes(infd, inbuf, len, error)) {
                return false;
            }

            size -= len;
            strm->next_in = inbuf;
            strm->avail_in = len;
        }

        rv = lzma_code(strm, LZMA_RUN);
        if (rv != LZMA_OK && rv != LZMA_STREAM_END) {
            g_set_error(error, DLP_ERROR, DLP_LZMA_ERROR_FAILED, "lzma_code()");
            return false;
        }

        if (strm->avail_out == 0 || rv == LZMA_STREAM_END) {
            if (dlp_overflow_sub(sizeof(outbuf), strm->avail_out, &len)) {
                g_set_error(error, DLP_ERROR, ERANGE, "%s", g_strerror(ERANGE));
                return false;
            }

            if (len > 0) {
                if (!dlp_fs_write_bytes(outfd, outbuf, len, error)) {
                    return false;
                }
            }

            strm->next_out = outbuf;
            strm->avail_out = sizeof(outbuf);
        }
    } while (rv != LZMA_STREAM_END);

    if (!dlp_fs_read(infd, inbuf, 1, &len, error) || len != 0) {
        g_prefix_error(error, "%s: ", _("expected EOF"));
        return false;
    }

    return rv == LZMA_STREAM_END && size == 0;
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp.h"
#include "dlp_fs.h"
#include "dlp_lzma.h"
#include "test.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) DLP_NODISCARD;

/* cppcheck-suppress unusedFunction */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int infd = -1;
    int outfd = -1;
    bool rv = false;

    rv = test_setup_home(NULL) && dlp_fs_mkstemp(&infd, NULL) &&
         dlp_fs_mkstemp(&outfd, NULL) &&
         dlp_fs_write_bytes(infd, data, size, NULL) &&
         dlp_lzma_decompress(infd, outfd, NULL);

    DLP_DISCARD(dlp_fs_close(&infd, NULL));
    DLP_DISCARD(dlp_fs_close(&outfd, NULL));

    return rv != true;
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_mem.h"

/**
 * Allocate a region of zero-initialized memory.
 *
 * This is a stricter version of g_malloc0().  The main difference is that
 * g_error() is invoked if the size is 0 or unreasonably large.  Similar to
 * g_malloc0(), g_error() is also invoked if the allocation fails.
 *
 * @param size Allocation size.
 * @return A pointer to the allocated memory.
 */
void *dlp_mem_alloc(rsize_t size)
{
    if (size == 0 || size >= RSIZE_MAX) {
        g_error("invalid size (%zu)", size);
    }

    return g_malloc0(size);
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_MEM_H
#define DLP_MEM_H

#include <glib.h>

#include "config.h"
#include "dlp.h"

#define dlp_mem_clear(ptr, fn) g_clear_pointer(ptr, fn)
#define dlp_mem_free(ptr) dlp_mem_clear(ptr, g_free)

void *dlp_mem_alloc(rsize_t size) DLP_NODISCARD DLP_MALLOC DLP_ALLOC_SIZE(1);
void *dlp_mem_alloc_n(rsize_t size, rsize_t nmemb) DLP_NODISCARD DLP_MALLOC
    DLP_ALLOC_SIZE_2(1, 2);
void dlp_mem_ptr_array_unref(GPtrArray **array);
void dlp_mem_ptr_array_destroy(gpointer ptr);

#endif /* DLP_MEM_H */

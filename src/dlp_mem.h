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

void *dlp_mem_alloc(rsize_t size) DLP_NODISCARD DLP_ALLOC_SIZE(1);

#endif /* DLP_MEM_H */

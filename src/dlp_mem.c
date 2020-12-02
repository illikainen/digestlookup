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
 * g_error() is invoked if the size is 0 or unreasonably large, unlike
 * g_malloc0() which returns NULL if the size is 0.  Similar to g_malloc0(),
 * g_error() is also invoked if the allocation fails.
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

/**
 * Decrease the refcount and clear the pointer to a GPtrArray.
 *
 * This function is created in similar spirit to g_clear_pointer(), whereas
 * g_ptr_array_unref() uses g_return_if_fail() on NULL pointers.
 *
 * @param array Pointer to a GPtrArray pointer to unref.
 */
void dlp_mem_ptr_array_unref(GPtrArray **array)
{
    if (array != NULL && *array != NULL) {
        g_ptr_array_unref(*array);
        *array = NULL;
    }
}

/**
 * Decrease the refcount for a GPtrArray.
 *
 * This function is declared with a gpointer to avoid undefined behavior if
 * it's used as a GDestroyNotify function pointer.
 *
 * Because it takes a void pointer it should only be used as a GDestroyNotify
 * callback.  Prefer dlp_mem_ptr_array_unref() for other use cases.
 *
 * See:
 * - ISO/IEC 9899:201x 6.2.5 §28
 * - ISO/IEC 9899:201x 6.3.2.3 §8
 *
 * @param ptr GPtrArray to unref.
 */
void dlp_mem_ptr_array_destroy(gpointer ptr)
{
    GPtrArray *array = ptr;

    dlp_mem_ptr_array_unref(&array);
}

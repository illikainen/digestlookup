/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_CURL_H
#define DLP_CURL_H

#include <stdbool.h>

#include <curl/curl.h>
#include <glib.h>

#include "dlp.h"

#define dlp_curl_set(easy, option, value)                                      \
    (curl_easy_setopt(easy, option, value) == CURLE_OK)

#define dlp_curl_info(easy, info, value)                                       \
    (curl_easy_getinfo(easy, info, value) == CURLE_OK)

enum dlp_curl_error {
    DLP_CURL_ERROR_FAILED = 1,
};

bool dlp_curl_global_init(GError **error) DLP_NODISCARD;
bool dlp_curl_init(CURL **easy, GError **error) DLP_NODISCARD;
void dlp_curl_free(CURL **easy);
void dlp_curl_destroy(gpointer ptr);
bool dlp_curl_perform(CURL **easy, GError **error) DLP_NODISCARD;
size_t dlp_curl_write_fd(char *ptr, size_t size, size_t nmemb,
                         void *data) DLP_NODISCARD;

#endif /* DLP_CURL_H */

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

#define dlp_curl_set(easy, option, value)                                      \
    (curl_easy_setopt(easy, option, value) == CURLE_OK)

#define dlp_curl_info(easy, info, value)                                       \
    (curl_easy_getinfo(easy, info, value) == CURLE_OK)

enum dlp_curl_error {
    DLP_CURL_ERROR_FAILED = 1,
};

bool dlp_curl_global_init(GError **error);
bool dlp_curl_init(CURL **easy, GError **error);
bool dlp_curl_free(CURL *easy);
bool dlp_curl_perform(CURL **easy, GError **error);
size_t dlp_curl_write_fd(char *ptr, size_t size, size_t nmemb, void *data);

#endif /* DLP_CURL_H */

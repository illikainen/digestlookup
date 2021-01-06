/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_str.h"

#include <glib.h>

#define DLP_STR_ASCII_DIGITS "0123456789"
#define DLP_STR_ASCII_A_Z "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DLP_STR_ASCII_OTHER " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~\n"
#define DLP_STR_ASCII_PRINTABLE                                                \
    DLP_STR_ASCII_DIGITS DLP_STR_ASCII_A_Z DLP_STR_ASCII_OTHER

/**
 * Simple string sanitizer.
 *
 * @param str String to sanitize.
 */
void dlp_str_sanitize(char *str)
{
    g_return_if_fail(str != NULL);

    g_strcanon(str, DLP_STR_ASCII_PRINTABLE, '_');
}

/**
 * Sanitize a filename.
 *
 * @param str String to sanitize.
 */
void dlp_str_sanitize_filename(char *str)
{
    g_return_if_fail(str != NULL);

    g_strcanon(str, DLP_STR_ASCII_A_Z DLP_STR_ASCII_DIGITS, '_');
}

/**
 * Match an array of patterns against a string.
 *
 * @param regex Array of compiled regular expressions.
 * @param str   String to match against.
 * @return True if a match was found and false otherwise.
 */
bool dlp_str_match_plain(const GPtrArray *regex, const char *str)
{
    guint i;
    GRegexMatchFlags flags = (GRegexMatchFlags)0;

    g_return_val_if_fail(regex != NULL && str != NULL, false);

    for (i = 0; i < regex->len; i++) {
        if (g_regex_match(regex->pdata[i], str, flags, NULL)) {
            return true;
        }
    }
    return false;
}

/**
 * Match an array of patterns against an array of strings.
 *
 * @param regex Array of compiled regular expressions.
 * @param strs  Array of string to match against.
 * @return True if a match was found and false otherwise.
 */
bool dlp_str_match_parray(const GPtrArray *regex, const GPtrArray *strs)
{
    guint i;
    guint j;
    GRegexMatchFlags flags = (GRegexMatchFlags)0;

    g_return_val_if_fail(regex != NULL && strs != NULL, false);

    for (i = 0; i < regex->len; i++) {
        for (j = 0; j < strs->len; j++) {
            if (g_regex_match(regex->pdata[i], strs->pdata[j], flags, NULL)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Match an array of patterns against a string in a list of structures.
 *
 * @param regex Array of compiled regular expressions.
 * @param list  List of structures.
 * @param off   Offset in each structure to match against.
 * @return True if a match was found and false otherwise.
 */
bool dlp_str_match_list(const GPtrArray *regex, const GList *list, glong off)
{
    guint i;
    const char *str;
    GRegexMatchFlags flags = (GRegexMatchFlags)0;

    g_return_val_if_fail(regex != NULL && list != NULL && off >= 0, false);

    for (; list != NULL; list = list->next) {
        for (i = 0; i < regex->len; i++) {
            str = G_STRUCT_MEMBER(const char *, list->data, off);
            if (g_regex_match(regex->pdata[i], str, flags, NULL)) {
                return true;
            }
        }
    }
    return false;
}

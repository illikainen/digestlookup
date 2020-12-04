/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_date.h"

#include <errno.h>
#include <locale.h>

#include <glib/gi18n.h>

#include "dlp_error.h"

/**
 * Parse a date string.
 *
 * POSIX.1-2017 does not specify any errors for strptime() but an error code of
 * DLP_DATE_ERROR_FORMAT is reserved for failures in strptime().  This allows
 * callers to retry with different format strings while avoiding other errors.
 *
 * @param str   String to parse.
 * @param fmt   Date format.
 * @param t     Resulting timestamp since epoch.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_date_parse(const char *str, const char *fmt, time_t *t, GError **error)
{
    struct tm tm;
    locale_t oldloc;
    locale_t newloc;

    g_return_val_if_fail(str != NULL && fmt != NULL && t != NULL, false);
    *t = -1;

    errno = 0;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if ((newloc = newlocale(LC_ALL_MASK, "C", 0)) == 0) {
        g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
        return false;
    }

    errno = 0;
    if ((oldloc = uselocale(newloc)) == 0) {
        g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
        freelocale(newloc);
        return false;
    }

    if (strptime(str, fmt, &tm) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_DATE_ERROR_FORMAT, "%s",
                    _("invalid format"));
        /* fallthrough */
    } else {
        errno = 0;
        if ((*t = timegm(&tm)) == (time_t)-1) {
            g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
            /* fallthrough */
        }
    }

    /*
     * Note that newloc isn't freed unless oldloc is successfully reset below.
     * POSIX.1-2017 says the following about freelocale():
     *
     * "Any use of a locale object that has been freed results in undefined
     * behavior."
     *
     * The specification doesn't mention the required lifetime of locale
     * objects set with uselocale(), so newloc is allowed to leak to avoid UAF
     * if the original locale can't be restored.
     */
    errno = 0;
    if (uselocale(oldloc) == 0) {
        if (error != NULL && *error == NULL) {
            g_set_error(error, DLP_ERROR, errno, "%s", g_strerror(errno));
        }
        return false;
    }

    freelocale(newloc);
    return *t != (time_t)-1;
}

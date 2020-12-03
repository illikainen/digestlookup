/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_curl.h"

#include <errno.h>
#include <signal.h>

#include <unistd.h>

#include <curl/curl.h>
#include <glib/gi18n.h>

#include "config.h"
#include "dlp_error.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"

#ifdef HAVE_OPENSSL
#    include <openssl/opensslconf.h>
#endif

struct dlp_curl_private {
    CURLM *multi;
    char errbuf[CURL_ERROR_SIZE];
};

static bool dlp_curl_multi_init(CURLM **multi, const GPtrArray *easy,
                                int *handles, GError **error) DLP_NODISCARD;
static bool dlp_curl_multi_free(CURLM *multi,
                                const GPtrArray *easy) DLP_NODISCARD;
static bool dlp_curl_multi_check_result(CURLM *multi,
                                        GError **error) DLP_NODISCARD;

/**
 * Prepare cURL for threaded use.
 *
 * This function should be called as early as possible.  It checks for threaded
 * OpenSSL support, installs an ignoring SIGPIPE handler and initializes cURL.
 * The other concerns laid out in the cURL documentation are (hopefully)
 * handled in the CMake setup.
 *
 * See:
 * - https://curl.haxx.se/libcurl/c/threadsafe.html
 * - https://curl.haxx.se/libcurl/c/curl_global_init.html
 *
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_curl_global_init(GError **error)
{
    CURLcode cc;

#if defined(HAVE_OPENSSL) && !defined(OPENSSL_THREADS)
    g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                _("OpenSSL is built without thread support"));
    return false;
#endif

    errno = 0;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                    dlp_error_str("signal"));
        return false;
    }

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK) {
        g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                    curl_easy_strerror(cc));
        return false;
    }

    return true;
}

/**
 * Initialize a curl easy handle.
 *
 * This function allocates memory that should be freed with dlp_curl_free()
 * after use.
 *
 * @param easy  Handle to initialize.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_curl_init(CURL **easy, GError **error)
{
    CURL *e;
    struct dlp_curl_private *priv;

    g_return_val_if_fail(easy != NULL, false);
    *easy = NULL;

    if ((e = curl_easy_init()) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                    _("cannot allocate easy handle"));
        return false;
    }

    priv = dlp_mem_alloc(sizeof(*priv));

    if (!dlp_curl_set(e, CURLOPT_NOSIGNAL, 1L) ||
        !dlp_curl_set(e, CURLOPT_FOLLOWLOCATION, 0L) ||
        !dlp_curl_set(e, CURLOPT_MAXREDIRS, 0L) ||
        !dlp_curl_set(e, CURLOPT_NOPROXY, "*") ||
        !dlp_curl_set(e, CURLOPT_FAILONERROR, 1L) ||
        !dlp_curl_set(e, CURLOPT_FILETIME, 1L) ||
        !dlp_curl_set(e, CURLOPT_LOW_SPEED_LIMIT, 1024L) ||
        !dlp_curl_set(e, CURLOPT_LOW_SPEED_TIME, 120L) ||
        !dlp_curl_set(e, CURLOPT_DEFAULT_PROTOCOL, "https") ||
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        !dlp_curl_set(e, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS) ||
        !dlp_curl_set(e, CURLOPT_SSL_VERIFYPEER, 1L) ||
        !dlp_curl_set(e, CURLOPT_SSL_VERIFYHOST, 2L) ||
        !dlp_curl_set(e, CURLOPT_PROXY_SSL_VERIFYPEER, 1L) ||
        !dlp_curl_set(e, CURLOPT_PROXY_SSL_VERIFYHOST, 2L) ||
        !dlp_curl_set(e, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2) ||
        !dlp_curl_set(e, CURLOPT_PROXY_SSLVERSION, CURL_SSLVERSION_TLSv1_2) ||
        !dlp_curl_set(e, CURLOPT_PRIVATE, priv) ||
        !dlp_curl_set(e, CURLOPT_ERRORBUFFER, priv->errbuf) ||
        !dlp_curl_set(e, CURLOPT_WRITEFUNCTION, dlp_curl_write_fd)) {
        dlp_mem_free(&priv);
        curl_easy_cleanup(e);
        g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                    _("invalid option"));
        return false;
    }

    *easy = e;
    return true;
}

/**
 * Free the memory associated with a curl easy handle.
 *
 * @param easy  Handle whose resources should be deallocated.
 */
void dlp_curl_free(CURL **easy)
{
    struct dlp_curl_private *priv;

    if (easy != NULL && *easy != NULL) {
        if (dlp_curl_info(*easy, CURLINFO_PRIVATE, &priv) && priv != NULL) {
            dlp_mem_free(&priv);
        }
        curl_easy_cleanup(*easy);
        *easy = NULL;
    }
}

/**
 * Free the memory associated with a curl easy handle.
 *
 * This function is declared with a gpointer to avoid undefined behavior if
 * it's used as a GDestroyNotify function pointer.
 *
 * Because it takes a void pointer it should only be used as a GDestroyNotify
 * callback.  Prefer dlp_curl_free() for other use cases.
 */
void dlp_curl_destroy(gpointer ptr)
{
    CURL *easy = ptr;

    if (easy != NULL) {
        dlp_curl_free(&easy);
    }
}

/**
 * Perform a blocking request on a curl handle.
 *
 * The dlp_curl_perform() generic macro may be used to invoke this function.
 *
 * @param easy  A handle to perform the request on.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_curl_perform_one(CURL *easy, GError **error)
{
    GPtrArray *array;
    bool rv;

    g_return_val_if_fail(easy != NULL, false);

    array = g_ptr_array_new();
    g_ptr_array_add(array, easy);
    rv = dlp_curl_perform_parray(array, error);
    g_ptr_array_unref(array);

    return rv;
}

/**
 * Perform one or more requests.
 *
 * The requests are performed with the multi interface.  This function blocks
 * until every request has finished successfully or until the first error is
 * encountered.
 *
 * The dlp_curl_perform() generic macro may be used to invoke this function.
 *
 * @param easy  NULL-terminated array of handles to perform requests on.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_curl_perform_array(CURL **easy, GError **error)
{
    GPtrArray *array;
    bool rv;

    g_return_val_if_fail(easy != NULL && *easy != NULL, false);

    array = g_ptr_array_new();
    for (; *easy != NULL; easy++) {
        g_ptr_array_add(array, *easy);
    }

    rv = dlp_curl_perform_parray(array, error);
    g_ptr_array_unref(array);
    return rv;
}

/**
 * Perform one or more requests.
 *
 * The requests are performed with the multi interface.  This function blocks
 * until every request has finished successfully or until the first error is
 * encountered.
 *
 * The dlp_curl_perform() generic macro may be used to invoke this function.
 *
 * @param easy  A GPtrArray with handles to perform requests on.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_curl_perform_parray(const GPtrArray *easy, GError **error)
{
    CURLM *multi;
    CURLMcode mc;
    int handles = 0;

    g_return_val_if_fail(easy != NULL && easy->len != 0, false);

    if (!dlp_curl_multi_init(&multi, easy, &handles, error)) {
        return false;
    }

    while (handles != 0) {
        int tmp = handles;

        if ((mc = curl_multi_perform(multi, &handles)) != CURLM_OK ||
            (mc = curl_multi_wait(multi, NULL, 0, 1000, NULL)) != CURLM_OK) {
            DLP_DISCARD(dlp_curl_multi_free(multi, easy));
            g_set_error(error, DLP_ERROR, mc, "%s", curl_multi_strerror(mc));
            return false;
        }

        if (handles < tmp && !dlp_curl_multi_check_result(multi, error)) {
            DLP_DISCARD(dlp_curl_multi_free(multi, easy));
            return false;
        }
    }

    if (!dlp_curl_multi_free(multi, easy)) {
        return false;
    }

    return true;
}

/**
 * Callback for CURLOPT_WRITEFUNCTION.
 *
 * The CURLOPT_WRITEDATA setting must point to a file descriptor in order to
 * use this function as the write callback.
 */
size_t dlp_curl_write_fd(char *ptr, size_t size, size_t nmemb, void *data)
{
    int fd;
    rsize_t total_size;
    ssize_t total_ssize;

    if (ptr == NULL || size == 0 || nmemb == 0 || data == NULL) {
        return 0;
    }

    if ((fd = *(int *)data) <= 0) {
        return 0;
    }

    if (dlp_overflow_mul(size, nmemb, &total_size) ||
        dlp_overflow_add(total_size, 0, &total_ssize) ||
        total_size > RSIZE_MAX) {
        return 0;
    }

    if (write(fd, ptr, total_size) != total_ssize) {
        return 0;
    }

    return total_size;
}

/**
 * Initialize a curl multi handle.
 *
 * This function allocates memory that should be freed with
 * dlp_curl_multi_free() after use.
 *
 * @param multi     Handle to initialize.
 * @param easy      A GPtrArray with easy handles to associate with the multi
 *                  handle.
 * @param handles   Number of easy handles associated with the multi handle.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_curl_multi_init(CURLM **multi, const GPtrArray *easy,
                                int *handles, GError **error)
{
    CURLM *m;
    guint i;

    g_return_val_if_fail(multi != NULL && easy != NULL && handles != NULL,
                         false);
    *multi = NULL;
    *handles = 0;

    if ((m = curl_multi_init()) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                    _("cannot allocate multi handle"));
        return false;
    }

    for (i = 0; i < easy->len; i++) {
        struct dlp_curl_private *priv;
        CURLMcode mc;
        CURL *e = easy->pdata[i];

        if (!dlp_curl_info(e, CURLINFO_PRIVATE, &priv) || priv == NULL) {
            DLP_DISCARD(dlp_curl_multi_free(m, easy));
            g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                        _("unknown easy handle"));
            return false;
        }

        if ((mc = curl_multi_add_handle(m, e)) != CURLM_OK) {
            DLP_DISCARD(dlp_curl_multi_free(m, easy));
            g_set_error(error, DLP_ERROR, mc, "%s", curl_multi_strerror(mc));
            return false;
        }

        priv->multi = m;
    }

    if (dlp_overflow_add(i, 0, handles)) {
        DLP_DISCARD(dlp_curl_multi_free(m, easy));
        g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                    g_strerror(EOVERFLOW));
        return false;
    }

    *multi = m;
    return true;
}

/**
 * Free the memory associated with a curl multi handle.
 *
 * Note that the easy handles aren't freed.  However, they are disassociated
 * from the multi handle.
 *
 * @param multi Handle whose resources should be deallocated.
 * @param easy  GPtrArray with easy handles to disassociate from the multi
 *              handle.
 * @return True on success and false on failure.
 */
static bool dlp_curl_multi_free(CURLM *multi, const GPtrArray *easy)
{
    guint i;
    size_t errors = 0;

    g_return_val_if_fail(multi != NULL && easy != NULL, false);

    for (i = 0; i < easy->len; i++) {
        struct dlp_curl_private *priv;
        CURL *e = easy->pdata[i];

        if (dlp_curl_info(e, CURLINFO_PRIVATE, &priv) && priv != NULL) {
            if (priv->multi == multi) {
                errors += curl_multi_remove_handle(multi, e) != CURLM_OK;
                priv->multi = NULL;
            } else if (priv->multi != NULL) {
                errors += 1;
            }
        } else {
            errors += 1;
        }
    }

    errors += curl_multi_cleanup(multi) != CURLM_OK;
    return errors == 0;
}

/**
 * Check the result for one or more completed requests in a multi handle.
 *
 * @param multi Handle to check.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_curl_multi_check_result(CURLM *multi, GError **error)
{
    long status;
    int err;
    int num = 0;
    struct dlp_curl_private *priv = NULL;

    g_return_val_if_fail(multi != NULL, false);

    do {
        CURLMsg *msg;

        if ((msg = curl_multi_info_read(multi, &num)) == NULL) {
            g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED, "%s",
                        _("cannot read multi handle"));
            return false;
        }

        if (msg->msg == CURLMSG_DONE) {
            if (!dlp_curl_info(msg->easy_handle, CURLINFO_PRIVATE, &priv) ||
                priv == NULL) {
                g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED,
                            _("unknown easy handle"));
                return false;
            }

            if (msg->data.result != CURLE_OK) {
                if (dlp_overflow_add(msg->data.result, 0, &err)) {
                    err = DLP_CURL_ERROR_FAILED;
                }
                g_set_error(error, DLP_ERROR, err, "%s",
                            *priv->errbuf != '\0' ?
                                priv->errbuf :
                                curl_easy_strerror(msg->data.result));
                return false;
            }

            if (!dlp_curl_info(msg->easy_handle, CURLINFO_RESPONSE_CODE,
                               &status)) {
                g_set_error(error, DLP_ERROR, DLP_CURL_ERROR_FAILED,
                            _("missing status"));
                return false;
            }

            if (status != 200) {
                g_set_error(error, DLP_ERROR, CURLE_HTTP_RETURNED_ERROR,
                            "%s %lu", _("invalid status"), status);
                return false;
            }
        }
    } while (num > 0);

    return true;
}

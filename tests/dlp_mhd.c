/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_mhd.h"

#include <errno.h>
#include <locale.h>

#include <arpa/inet.h>

#include <glib/gi18n.h>
#include <microhttpd.h>

#include "dlp_error.h"
#include "dlp_mem.h"

struct dlp_mhd {
    struct MHD_Daemon *daemon;
    GList *sessions;
    GRWLock sessions_lock;

    /* Kept because their lifetimes aren't documented. */
    struct sockaddr_in sa;
    char *key;
    char *cert;
};

struct dlp_mhd_request {
    char *method;
    char *version;
    char *path;
    char *user_agent;
};

struct dlp_mhd_response {
    char *content;
    char *lmtime;
    unsigned int status;
};

struct dlp_mhd_session {
    struct dlp_mhd_request req;
    struct dlp_mhd_response res;
    struct MHD_Response *mhd_res;
};

static void dlp_mhd_session_free(gpointer data);
static bool dlp_mhd_lmtime(time_t time, char **str,
                           GError **error) DLP_NODISCARD;
static int dlp_mhd_request_cb(void *cls, struct MHD_Connection *con,
                              const char *url, const char *method,
                              const char *version, const char *upload_data,
                              size_t *upload_data_size,
                              void **con_cls) DLP_NODISCARD;

bool dlp_mhd_init(struct dlp_mhd **mhd)
{
    if (mhd != NULL) {
        *mhd = dlp_mem_alloc(sizeof(**mhd));
        g_rw_lock_init(&(*mhd)->sessions_lock);
        return true;
    }

    return false;
}

bool dlp_mhd_free(struct dlp_mhd *mhd)
{
    if (mhd != NULL) {
        g_rw_lock_writer_lock(&mhd->sessions_lock);
        g_list_free_full(mhd->sessions, dlp_mhd_session_free);
        g_rw_lock_writer_unlock(&mhd->sessions_lock);

        g_rw_lock_clear(&mhd->sessions_lock);
        dlp_mem_free(&mhd->key);
        dlp_mem_free(&mhd->cert);
        dlp_mem_free(&mhd);

        return true;
    }

    return false;
}

bool dlp_mhd_start(struct dlp_mhd *mhd, const char *addr, uint16_t port,
                   const char *key, const char *cert, GError **error)
{
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    unsigned int flags = MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_PEDANTIC_CHECKS;

    g_return_val_if_fail(mhd != NULL && addr != NULL, false);

    if (key != NULL && cert != NULL) {
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        flags |= MHD_USE_TLS;

        if (g_file_get_contents(key, &mhd->key, NULL, error) != TRUE) {
            return false;
        }

        if (g_file_get_contents(cert, &mhd->cert, NULL, error) != TRUE) {
            return false;
        }
    }

    mhd->sa.sin_family = AF_INET;
    mhd->sa.sin_port = htons(port);

    errno = 0;
    if (inet_pton(AF_INET, addr, &mhd->sa.sin_addr.s_addr) != 1) {
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED, "%s",
                    dlp_error_str("inet_pton"));
        return false;
    }

    mhd->daemon = MHD_start_daemon(flags, 0, NULL, NULL, dlp_mhd_request_cb,
                                   mhd, MHD_OPTION_SOCK_ADDR, &mhd->sa,
                                   MHD_OPTION_HTTPS_MEM_KEY, mhd->key,
                                   MHD_OPTION_HTTPS_MEM_CERT, mhd->cert,
                                   MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
                                   MHD_OPTION_END);
    if (mhd->daemon == NULL) {
        return false;
    }

    return true;
}

bool dlp_mhd_stop(struct dlp_mhd *mhd)
{
    if (mhd != NULL && mhd->daemon != NULL) {
        MHD_stop_daemon(mhd->daemon);
        return true;
    }
    return false;
}

bool dlp_mhd_session_add(struct dlp_mhd *mhd, const char *method,
                         const char *version, const char *path,
                         const char *user_agent, const void *content,
                         size_t content_len, time_t mtime, unsigned int status,
                         GError **error)
{
    struct dlp_mhd_session *s;

    g_return_val_if_fail(mhd != NULL && method != NULL && version != NULL &&
                             path != NULL && user_agent != NULL &&
                             content != NULL,
                         false);

    s = dlp_mem_alloc(sizeof(*s));
    s->req.method = g_strdup(method);
    s->req.version = g_strdup(version);
    s->req.path = g_strdup(path);
    s->req.user_agent = g_strdup(user_agent);
    s->res.status = status;

    if (content_len == 0) {
        s->res.content = g_strdup(content);
        content_len = strlen(s->res.content);
    } else {
        s->res.content = dlp_mem_alloc(content_len);
        if (memcpy(s->res.content, content, content_len) != s->res.content) {
            return false;
        }
    }

    if (!dlp_mhd_lmtime(mtime, &s->res.lmtime, error)) {
        dlp_mhd_session_free(s);
        return false;
    }

    s->mhd_res = MHD_create_response_from_buffer(content_len, s->res.content,
                                                 MHD_RESPMEM_PERSISTENT);
    if (s->mhd_res == NULL) {
        dlp_mhd_session_free(s);
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED,
                    _("cannot create response"));
        return false;
    }

    if (MHD_add_response_header(s->mhd_res, MHD_HTTP_HEADER_LAST_MODIFIED,
                                s->res.lmtime) == MHD_NO) {
        dlp_mhd_session_free(s);
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED,
                    _("cannot set header"));
        return false;
    }

    g_rw_lock_writer_lock(&mhd->sessions_lock);
    mhd->sessions = g_list_prepend(mhd->sessions, s);
    g_rw_lock_writer_unlock(&mhd->sessions_lock);

    return true;
}

bool dlp_mhd_session_remove_all(struct dlp_mhd *mhd)
{
    g_return_val_if_fail(mhd != NULL, false);

    g_rw_lock_writer_lock(&mhd->sessions_lock);
    g_list_free_full(mhd->sessions, dlp_mhd_session_free);
    mhd->sessions = NULL;
    g_rw_lock_writer_unlock(&mhd->sessions_lock);

    return true;
}

static void dlp_mhd_session_free(gpointer data)
{
    struct dlp_mhd_session *s = data;

    if (s) {
        dlp_mem_free(&s->req.method);
        dlp_mem_free(&s->req.path);
        dlp_mem_free(&s->req.version);
        dlp_mem_free(&s->req.user_agent);

        dlp_mem_free(&s->res.content);
        dlp_mem_free(&s->res.lmtime);

        if (s->mhd_res) {
            MHD_destroy_response(s->mhd_res);
        }

        dlp_mem_free(&s);
    }
}

static bool dlp_mhd_lmtime(time_t time, char **str, GError **error)
{
    struct tm tm;
    locale_t loc, nloc;
    rsize_t len = 30; /* strlen("Thu, 01 Jan 1970 00:00:00 GMT") + 1 */

    g_return_val_if_fail(str != NULL, false);
    *str = NULL;

    errno = 0;
    if (gmtime_r(&time, &tm) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED, "%s",
                    dlp_error_str("gmtime"));
        return false;
    }

    errno = 0;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    if ((nloc = newlocale(LC_ALL_MASK, "C", 0)) == 0) {
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED, "%s",
                    dlp_error_str("newlocale"));
        return false;
    }

    errno = 0;
    if ((loc = uselocale(nloc)) == 0) {
        freelocale(nloc);
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED, "%s",
                    dlp_error_str("uselocale"));
        return false;
    }

    *str = dlp_mem_alloc(len);
    if (strftime(*str, len, "%a, %d %b %Y %H:%M:%S GMT", &tm) != len - 1) {
        dlp_mem_free(str);
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED, "strftime");
        /* fall through */
    }

    /*
     * Note that if nloc is set, then it isn't freed until loc is successfully
     * reset below.  POSIX.1-2017 says:
     *
     * "Any use of a locale object that has been freed results in undefined
     * behavior."
     *
     * The specification doesn't mention the required lifetime of locale
     * objects set with uselocale(), so this leaks if the original locale can't
     * be restored.
     */
    errno = 0;
    if (uselocale(loc) == 0) {
        dlp_mem_free(str);
        g_set_error(error, DLP_ERROR, DLP_MHD_ERROR_FAILED, "%s",
                    dlp_error_str("uselocale"));
        return false;
    }

    freelocale(nloc);
    return *str != NULL;
}

static int dlp_mhd_request_cb(void *cls, struct MHD_Connection *con,
                              const char *url, const char *method,
                              const char *version, const char *upload_data,
                              size_t *upload_data_size, /* NOLINT */
                              void **con_cls)
{
    GList *elt;
    const char *user_agent;
    struct dlp_mhd *mhd = cls;
    int rv = MHD_NO;

    (void)upload_data;
    (void)upload_data_size;
    (void)con_cls;

    g_return_val_if_fail(cls != NULL && con != NULL && url != NULL &&
                             method != NULL && version != NULL,
                         false);

    user_agent = MHD_lookup_connection_value(con, MHD_HEADER_KIND,
                                             MHD_HTTP_HEADER_USER_AGENT);

    g_rw_lock_reader_lock(&mhd->sessions_lock);
    for (elt = mhd->sessions; elt != NULL; elt = elt->next) {
        struct dlp_mhd_session *s = elt->data;
        if (g_strcmp0(s->req.method, method) == 0 &&
            g_strcmp0(s->req.path, url) == 0 &&
            g_strcmp0(s->req.version, version) == 0 &&
            g_strcmp0(s->req.user_agent, user_agent) == 0) {
            rv = MHD_queue_response(con, s->res.status, s->mhd_res);
            break;
        }
    }
    g_rw_lock_reader_unlock(&mhd->sessions_lock);

    return rv;
}

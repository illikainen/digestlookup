/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <microhttpd.h>

#include "dlp_curl.h"
#include "dlp_mem.h"
#include "dlp_mhd.h"
#include "test.h"

struct tmpfile {
    int fd;
    char *name;
};

struct state {
    gchar *host;
    uint16_t port;
    gchar *key;
    gchar *cert;
    gchar *sha256;
    struct tmpfile tmp[20];
    struct dlp_mhd *mhd;
};

static int group_setup(void **state)
{
    struct state *s;

    s = dlp_mem_alloc(sizeof(*s));
    *state = s;

    s->host = "127.0.0.1";
    s->port = 1234;
    s->sha256 = "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/o6fCDtm59VBQ8=";
    s->key = g_build_filename(PROJECT_DIR, "tests", "data", "tls", "key.pem",
                              NULL);
    s->cert = g_build_filename(PROJECT_DIR, "tests", "data", "tls", "cert.pem",
                               NULL);

    if (!dlp_mhd_init(&s->mhd) ||
        !dlp_mhd_start(s->mhd, s->host, s->port, s->key, s->cert, NULL)) {
        return -1;
    }
    return 0;
}

static int group_teardown(void **state)
{
    struct state *s = *state;
    struct dlp_mhd *mhd = s->mhd;

    dlp_mem_free(&s->key);
    dlp_mem_free(&s->cert);
    dlp_mem_free(&s);

    DLP_DISCARD(dlp_mhd_stop(mhd));
    if (!dlp_mhd_free(mhd)) {
        return -1;
    }
    return 0;
}

static int setup(void **state)
{
    size_t i;
    struct state *s = *state;

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        s->tmp[i].name = g_strdup("tmp-XXXXXX");
        if ((s->tmp[i].fd = g_mkstemp(s->tmp[i].name)) == -1) {
            return -1;
        }
    }
    return 0;
}

static int teardown(void **state)
{
    size_t i;
    struct state *s = *state;
    int rv = 0;

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        if (s->tmp[i].fd > 0) {
            if (close(s->tmp[i].fd) != 0) {
                rv += 1;
            }
        }

        if (s->tmp[i].name) {
            if (remove(s->tmp[i].name) != 0) {
                rv += 1;
            }
            dlp_mem_free(&s->tmp[i].name);
        }
    }

    if (!dlp_mhd_session_remove_all(s->mhd)) {
        rv += 1;
    }

    return rv ? -1 : 0;
}

static void test_global_init(void **state)
{
    CURLcode cc;
    GError *err = NULL;

    (void)state;

    if (test_wrap_p()) {
        cc = CURLE_FAILED_INIT;
        test_wrap_push(curl_global_init, true, &cc);
        assert_false(dlp_curl_global_init(&err));
        TEST_ASSERT_ERR(err, DLP_CURL_ERROR_FAILED, "*");
        g_clear_error(&err);
    }
}

static void test_init(void **state)
{
    CURL *curl;
    GError *err = NULL;

    (void)state;

    if (test_wrap_p()) {
        test_wrap_push(curl_easy_init, true, NULL);
        assert_false(dlp_curl_init(&curl, &err));
        assert_null(curl);
        TEST_ASSERT_ERR(err, DLP_CURL_ERROR_FAILED, "*");
    }
}

static void test_curl_free(void **state)
{
    CURL *curl = NULL;

    (void)state;

    dlp_curl_free(NULL);
    dlp_curl_free(&curl);

    assert_true(dlp_curl_init(&curl, NULL));
    assert_non_null(curl);
    dlp_curl_free(&curl);
    assert_null(curl);
}

static void test_curl_destroy(void **state)
{
    CURL *curl = NULL;
    GList *l = NULL;

    (void)state;

    dlp_curl_destroy(NULL);
    dlp_curl_destroy(curl);

    assert_true(dlp_curl_init(&curl, NULL));
    assert_non_null(curl);
    dlp_curl_destroy(curl);

    assert_true(dlp_curl_init(&curl, NULL));
    assert_non_null(curl);
    l = g_list_prepend(l, curl);
    assert_true(dlp_curl_init(&curl, NULL));
    assert_non_null(curl);
    l = g_list_prepend(l, curl);
    g_list_free_full(l, dlp_curl_destroy);
}

static void test_success_array(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/success",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/success", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "foobar");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_success_array_direct(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/success",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/success", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_true(dlp_curl_perform_array(curl, &err));
    assert_null(err);
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "foobar");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_success_ptr_array(void **state)
{
    gchar *url;
    GPtrArray *array;
    CURL *curl;
    GError *err = NULL;
    struct state *s = *state;

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/success",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    array = g_ptr_array_new_full(0, dlp_curl_destroy);
    url = g_strdup_printf("https://%s:%u/success", s->host, s->port);
    assert_true(dlp_curl_init(&curl, NULL));
    assert_true(dlp_curl_set(curl, CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl, CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl, CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl, CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl, CURLOPT_WRITEDATA, &s->tmp[0].fd));
    g_ptr_array_add(array, curl);

    assert_true(dlp_curl_perform(array, &err));
    assert_null(err);
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "foobar");

    dlp_mem_free(&url);
    g_ptr_array_unref(array);
}

static void test_success_one(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl;

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/success",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/success", s->host, s->port);
    assert_true(dlp_curl_init(&curl, NULL));
    assert_true(dlp_curl_set(curl, CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl, CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl, CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl, CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl, CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "foobar");
    dlp_curl_free(&curl);

    dlp_mem_free(&url);
}

static void test_success_one_direct(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl;

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/success",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/success", s->host, s->port);
    assert_true(dlp_curl_init(&curl, NULL));
    assert_true(dlp_curl_set(curl, CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl, CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl, CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl, CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl, CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_true(dlp_curl_perform_one(curl, &err));
    assert_null(err);
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "foobar");
    dlp_curl_free(&curl);

    dlp_mem_free(&url);
}

static void test_bad_ca(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/bad-ca",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/bad-ca", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_PEER_FAILED_VERIFICATION, "*self signed*");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_bad_fqdn(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/bad-fqdn",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://localhost:%u/bad-fqdn", s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_PEER_FAILED_VERIFICATION, "*subject name*");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_bad_pin(void **state)
{
    gchar *url;
    gchar *sha256;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/bad-pin",
                                    "agent", "foobar", 0, 0, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/bad-pin", s->host, s->port);
    sha256 = "sha256//hQCB8c6ZQftPpThbwMC0MDL1Jye+3IZnzqfobXbCFXa=";
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_SSL_PINNEDPUBKEYNOTMATCH, "*pinned*");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_301(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/301", "agent",
                                    "foobar", 0, 0, MHD_HTTP_MOVED_PERMANENTLY,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/301", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_HTTP_RETURNED_ERROR, "*invalid status*");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_404(void **state)
{
    gchar *url;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/404", "agent",
                                    "foobar", 0, 0, MHD_HTTP_NOT_FOUND, NULL));

    url = g_strdup_printf("https://%s:%u/404", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_HTTP_RETURNED_ERROR, "*Not Found*");
    dlp_curl_free(&curl[0]);

    dlp_mem_free(&url);
}

static void test_get_mtime(void **state)
{
    gchar *url;
    long mtime;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/get-mtime",
                                    "agent", "foobar", 0, 12345, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/get-mtime", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);
    assert_true(dlp_curl_info(curl[0], CURLINFO_FILETIME, &mtime));
    assert_true(mtime == 12345);
    dlp_curl_free(&curl[0]);
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "foobar");

    dlp_mem_free(&url);
}

static void test_head_mtime(void **state)
{
    gchar *url;
    long mtime;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[2] = { NULL };

    assert_true(dlp_mhd_session_add(s->mhd, "HEAD", "HTTP/1.1", "/head-mtime",
                                    "agent", "foobar", 0, 12345, MHD_HTTP_OK,
                                    NULL));

    url = g_strdup_printf("https://%s:%u/head-mtime", s->host, s->port);
    assert_true(dlp_curl_init(&curl[0], NULL));
    assert_true(dlp_curl_set(curl[0], CURLOPT_URL, url));
    assert_true(dlp_curl_set(curl[0], CURLOPT_CAINFO, s->cert));
    assert_true(dlp_curl_set(curl[0], CURLOPT_PINNEDPUBLICKEY, s->sha256));
    assert_true(dlp_curl_set(curl[0], CURLOPT_USERAGENT, "agent"));
    assert_true(dlp_curl_set(curl[0], CURLOPT_NOBODY, 1L));
    assert_true(dlp_curl_set(curl[0], CURLOPT_WRITEDATA, &s->tmp[0].fd));

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);
    assert_true(dlp_curl_info(curl[0], CURLINFO_FILETIME, &mtime));
    assert_true(mtime == 12345);
    dlp_curl_free(&curl[0]);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
    TEST_ASSERT_FD_CONTENT(s->tmp[0].fd, "");
#pragma GCC diagnostic pop

    dlp_mem_free(&url);
}

static void test_multi_success_array(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-success-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, s->sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        TEST_ASSERT_FD_CONTENT(s->tmp[i].fd, "content-%zu", i);
        dlp_curl_free(&curl[i]);
    }
}

static void test_multi_success_ptr_array(void **state)
{
    size_t i;
    GPtrArray *array;
    CURL *curl;
    GError *err = NULL;
    struct state *s = *state;

    array = g_ptr_array_new_full(0, dlp_curl_destroy);

    for (i = 0; i < G_N_ELEMENTS(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-success-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl, NULL));
        assert_true(dlp_curl_set(curl, CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl, CURLOPT_CAINFO, s->cert));
        assert_true(dlp_curl_set(curl, CURLOPT_PINNEDPUBLICKEY, s->sha256));
        assert_true(dlp_curl_set(curl, CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl, CURLOPT_WRITEDATA, &s->tmp[i].fd));
        g_ptr_array_add(array, curl);

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_true(dlp_curl_perform(array, &err));
    assert_null(err);

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        TEST_ASSERT_FD_CONTENT(s->tmp[i].fd, "content-%zu", i);
    }
    g_ptr_array_unref(array);
}

static void test_multi_bad_ca(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-bad-ca-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);
        gchar *sha256 = s->sha256;

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        if (i != TEST_ARRAY_LEN(s->tmp) - 1) {
            assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        }
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_PEER_FAILED_VERIFICATION, "*self signed*");

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        dlp_curl_free(&curl[i]);
    }
}

static void test_multi_bad_fqdn(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-bad-fqdn-%zu", i);
        gchar *url = g_strdup_printf("https://localhost:%u%s", s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);
        gchar *sha256 = s->sha256;

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        if (i != TEST_ARRAY_LEN(s->tmp) - 1) {
            assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        }
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_PEER_FAILED_VERIFICATION, "*subject name*");

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        dlp_curl_free(&curl[i]);
    }
}

static void test_multi_bad_pin(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-bad-pin-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);
        gchar *sha256 = s->sha256;

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        if (i == TEST_ARRAY_LEN(s->tmp) - 1) {
            sha256 = "sha256//hQCB8c6ZQftPpThbwMC0MDL1Jye+3IZnzqfobXbCFXa=";
        }
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_SSL_PINNEDPUBKEYNOTMATCH, "*pinned*");

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        dlp_curl_free(&curl[i]);
    }
}

static void test_multi_301(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-301-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);
        unsigned int status = MHD_HTTP_OK;

        if (i == TEST_ARRAY_LEN(s->tmp) - 1) {
            status = MHD_HTTP_MOVED_PERMANENTLY;
        }
        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, status, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, s->sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_HTTP_RETURNED_ERROR, "*invalid status*");

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        dlp_curl_free(&curl[i]);
    }
}

static void test_multi_404(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-404-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-%zu", i);
        gchar *content = g_strdup_printf("content-%zu", i);
        unsigned int status = MHD_HTTP_OK;

        if (i == TEST_ARRAY_LEN(s->tmp) - 1) {
            status = MHD_HTTP_NOT_FOUND;
        }
        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, status, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, s->sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_false(dlp_curl_perform(curl, &err));
    TEST_ASSERT_ERR(err, CURLE_HTTP_RETURNED_ERROR, "*Not Found*");

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        dlp_curl_free(&curl[i]);
    }
}

static void test_multi_reuse(void **state)
{
    size_t i;
    GError *err = NULL;
    struct state *s = *state;
    CURL *curl[TEST_ARRAY_LEN(s->tmp) + 1] = { NULL };

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-reuse-0-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-0-%zu", i);
        gchar *content = g_strdup_printf("content-0-%zu", i);

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, s->sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        TEST_ASSERT_FD_CONTENT(s->tmp[i].fd, "content-0-%zu", i);
        assert_int_equal(ftruncate(s->tmp[i].fd, 0), 0);
        dlp_curl_free(&curl[i]);
    }

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        gchar *path = g_strdup_printf("/test-multi-reuse-1-%zu", i);
        gchar *url = g_strdup_printf("https://%s:%u%s", s->host, s->port, path);
        gchar *agent = g_strdup_printf("agent-1-%zu", i);
        gchar *content = g_strdup_printf("content-1-%zu", i);

        assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", path, agent,
                                        content, 0, 0, MHD_HTTP_OK, NULL));

        assert_true(dlp_curl_init(&curl[i], NULL));
        assert_true(dlp_curl_set(curl[i], CURLOPT_URL, url));
        assert_true(dlp_curl_set(curl[i], CURLOPT_CAINFO, s->cert));
        assert_true(dlp_curl_set(curl[i], CURLOPT_PINNEDPUBLICKEY, s->sha256));
        assert_true(dlp_curl_set(curl[i], CURLOPT_USERAGENT, agent));
        assert_true(dlp_curl_set(curl[i], CURLOPT_WRITEDATA, &s->tmp[i].fd));

        dlp_mem_free(&path);
        dlp_mem_free(&url);
        dlp_mem_free(&agent);
        dlp_mem_free(&content);
    }

    assert_true(dlp_curl_perform(curl, &err));
    assert_null(err);

    for (i = 0; i < TEST_ARRAY_LEN(s->tmp); i++) {
        TEST_ASSERT_FD_CONTENT(s->tmp[i].fd, "content-1-%zu", i);
        dlp_curl_free(&curl[i]);
    }
}

static void test_write_fd(void **state)
{
    char *buf;
    int fd = 0;
    struct state *s = *state;

    buf = g_strdup("foo");
    assert_int_equal(dlp_curl_write_fd(NULL, 1, 1, &s->tmp[0].fd), 0);
    assert_int_equal(dlp_curl_write_fd(buf, 1, 1, NULL), 0);
    assert_int_equal(dlp_curl_write_fd(buf, 0, 1, &s->tmp[0].fd), 0);
    assert_int_equal(dlp_curl_write_fd(buf, 1, 0, &s->tmp[0].fd), 0);
    assert_int_equal(dlp_curl_write_fd(buf, RSIZE_MAX, 2, &s->tmp[0].fd), 0);
    assert_int_equal(dlp_curl_write_fd(buf, 1, 1, &fd), 0);
    dlp_mem_free(&buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_global_init),
        cmocka_unit_test(test_init),
        cmocka_unit_test(test_curl_free),
        cmocka_unit_test(test_curl_destroy),
        cmocka_unit_test_setup_teardown(test_success_array, setup, teardown),
        cmocka_unit_test_setup_teardown(test_success_array_direct, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_success_ptr_array, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_success_one, setup, teardown),
        cmocka_unit_test_setup_teardown(test_success_one_direct, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_success_array_direct, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_bad_ca, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bad_fqdn, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bad_pin, setup, teardown),
        cmocka_unit_test_setup_teardown(test_301, setup, teardown),
        cmocka_unit_test_setup_teardown(test_404, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_mtime, setup, teardown),
        cmocka_unit_test_setup_teardown(test_head_mtime, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi_success_array, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_multi_success_ptr_array, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_multi_bad_ca, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi_bad_fqdn, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi_bad_pin, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi_301, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi_404, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi_reuse, setup, teardown),
        cmocka_unit_test_setup_teardown(test_write_fd, setup, teardown),
    };

    assert_true(dlp_curl_global_init(NULL));

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

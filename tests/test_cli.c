/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <microhttpd.h>

#include "dlp_cli.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mhd.h"
#include "test.h"

struct state {
    char *home;
    char *cwd;
    char orig_cwd[PATH_MAX];
};

static void setup(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(test_setup_home(&s->home));
    g_assert_true(getcwd(s->orig_cwd, sizeof(s->orig_cwd)) != NULL);
    g_assert_nonnull((s->cwd = g_strdup(g_getenv("DLP_TEST_HOME"))));
    g_assert_true(chdir(s->cwd) == 0);
}

static void teardown(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(chdir(s->orig_cwd) == 0);
    g_assert_true(dlp_fs_rmdir(s->cwd, NULL));

    dlp_mem_free(&s->cwd);
    dlp_mem_free(&s->home);
}

static void test_cli(gpointer data, gconstpointer user_data)
{
    GTestSubprocessFlags flags;

    (void)data;
    (void)user_data;

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    flags = (GTestSubprocessFlags)(G_TEST_SUBPROCESS_INHERIT_STDOUT |
                                   G_TEST_SUBPROCESS_INHERIT_STDERR);

    g_test_trap_subprocess("/cli/subprocess/success", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr_unmatched("*ERROR*");
    g_test_trap_assert_stdout("* "
                              "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0"
                              "f98a5e886266e7ae *");
    g_test_trap_assert_stdout("* "
                              "787deebb9026378ed6906a42f18bb83b85e9e3e469178e68"
                              "d4d83522d11c4d87 *");
    g_test_trap_assert_stdout("* "
                              "de3e578aa582af6e1d7729f39626892fb72dc6573658a221"
                              "e0905f42a65433da *");
    g_test_trap_assert_stdout("* "
                              "576c7288395653bf3082e4a08db5215509eeaeae71b2de90"
                              "99590a1224535981 *");

    g_test_trap_subprocess("/cli/subprocess/bad-signature", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*Bad signature*");

    g_test_trap_subprocess("/cli/subprocess/bad-option", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*option*");

    g_test_trap_subprocess("/cli/subprocess/missing-config", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*enoent*");

    if (test_wrap_p()) {
        g_test_trap_subprocess("/cli/subprocess/failed-curl-init", 0, flags);
        g_test_trap_assert_passed();
        g_test_trap_assert_stderr("*ERROR*initialization*");
    }
}

static void test_cli_success(void)
{
    gsize size;
    char *data;
    char *host = "127.0.0.1";
    uint16_t port = 5555;
    const char *key;
    const char *cert;
    const char *path;
    struct dlp_mhd *mhd = NULL;
    char *argv[] = {
        "prog", "--config=test-cli", "--repos=test-cli-success",
        "foo",  "libdisasm",         NULL,
    };

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    data = g_strdup_printf("[test-cli-success]\n"
                           "backend = apt\n"
                           "url = %s:%u\n"
                           "ca-file = %s\n"
                           "tls-key = "
                           "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                           "o6fCDtm59VBQ8=\n"
                           "verify-keys = %s\n"
                           "user-agent = agent\n",
                           host, port, cert,
                           g_test_get_filename(G_TEST_DIST, "tests", "data",
                                               "gpg", "ed25519-pub.asc", NULL));
    g_assert_true(g_file_set_contents("test-cli", data, -1, NULL));
    dlp_mem_free(&data);

    g_assert_true(dlp_mhd_init(&mhd));
    g_assert_true(dlp_mhd_start(mhd, host, port, key, cert, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_signed.asc", NULL);
    g_assert_true(g_file_get_contents(path, &data, NULL, NULL));
    g_assert_true(dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease",
                                      "agent", data, 0, 0, MHD_HTTP_OK, NULL));
    dlp_mem_free(&data);

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_main.xz", NULL);
    g_assert_true(g_file_get_contents(path, &data, &size, NULL));
    g_assert_true(dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                                      "/main/source/Sources.xz", "agent", data,
                                      size, 0, MHD_HTTP_OK, NULL));
    dlp_mem_free(&data);

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_contrib.xz", NULL);
    g_assert_true(g_file_get_contents(path, &data, &size, NULL));
    g_assert_true(dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                                      "/contrib/source/Sources.xz", "agent",
                                      data, size, 0, MHD_HTTP_OK, NULL));
    dlp_mem_free(&data);

    g_assert_true(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));

    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_cli_bad_signature(void)
{
    gsize size;
    char *data;
    char *tmp;
    char *host = "127.0.0.1";
    uint16_t port = 5555;
    const char *key;
    const char *cert;
    const char *path;
    struct dlp_mhd *mhd = NULL;
    char *argv[] = {
        "prog", "--config=test-cli", "--repos=test-cli-bad-signature",
        "foo",  "libdisasm",         NULL,
    };

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    data = g_strdup_printf("[test-cli-bad-signature]\n"
                           "backend = apt\n"
                           "url = %s:%u\n"
                           "ca-file = %s\n"
                           "tls-key = "
                           "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                           "o6fCDtm59VBQ8=\n"
                           "verify-keys = %s\n"
                           "user-agent = agent\n",
                           host, port, cert,
                           g_test_get_filename(G_TEST_DIST, "tests", "data",
                                               "gpg", "ed25519-pub.asc", NULL));
    g_assert_true(g_file_set_contents("test-cli", data, -1, NULL));
    dlp_mem_free(&data);

    g_assert_true(dlp_mhd_init(&mhd));
    g_assert_true(dlp_mhd_start(mhd, host, port, key, cert, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_signed.asc", NULL);
    g_assert_true(g_file_get_contents(path, &data, NULL, NULL));
    g_assert_nonnull(tmp = strstr(data, "Debian"));
    *tmp = 'd';
    g_assert_true(dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease",
                                      "agent", data, 0, 0, MHD_HTTP_OK, NULL));
    dlp_mem_free(&data);

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_main.xz", NULL);
    g_assert_true(g_file_get_contents(path, &data, &size, NULL));
    g_assert_true(dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                                      "/main/source/Sources.xz", "agent", data,
                                      size, 0, MHD_HTTP_OK, NULL));
    dlp_mem_free(&data);

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_contrib.xz", NULL);
    g_assert_true(g_file_get_contents(path, &data, &size, NULL));
    g_assert_true(dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                                      "/contrib/source/Sources.xz", "agent",
                                      data, size, 0, MHD_HTTP_OK, NULL));
    dlp_mem_free(&data);

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));

    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_cli_bad_option(void)
{
    char *argv[] = {
        "prog", "--repos=repo", "--foo", "rx", NULL,
    };

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_missing_config(void)
{
    char *argv[] = {
        "prog", "--repos=repo", "--config=enoent", "rx", NULL,
    };

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_failed_curl_init(void)
{
    if (test_wrap_p()) {
        char *argv[] = {
            "prog", "--repos=repo", "--foo", "rx", NULL,
        };
        CURLcode code = CURLE_FAILED_INIT;
        test_wrap_push(curl_global_init, true, &code);
        g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
    }
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/cli/main", sizeof(struct state), NULL, setup, test_cli,
                      teardown);
    g_test_add_func("/cli/subprocess/success", test_cli_success);
    g_test_add_func("/cli/subprocess/bad-signature", test_cli_bad_signature);
    g_test_add_func("/cli/subprocess/bad-option", test_cli_bad_option);
    g_test_add_func("/cli/subprocess/missing-config", test_cli_missing_config);
    g_test_add_func("/cli/subprocess/failed-curl-init",
                    test_cli_failed_curl_init);

    return g_test_run();
}

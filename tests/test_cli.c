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

#define TEST_SHA256_FOO                                                        \
    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

#define TEST_SHA256_LIBDISASM_DSC                                              \
    "576c7288395653bf3082e4a08db5215509eeaeae71b2de9099590a1224535981"

#define TEST_SHA256_LIBDISASM_ORIG                                             \
    "de3e578aa582af6e1d7729f39626892fb72dc6573658a221e0905f42a65433da"

#define TEST_SHA256_LIBDISASM_DEB                                              \
    "787deebb9026378ed6906a42f18bb83b85e9e3e469178e68d4d83522d11c4d87"

#define TEST_SHA512_FOO                                                        \
    "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41" \
    "be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"

#define TEST_SHA512_BAR                                                        \
    "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5" \
    "b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"

#define TEST_SHA512_QUUX                                                       \
    "8c6be9ed448a34883a13a13f4ead4aefa036b67dcda59020c01e57ea075ea8a4792d428f" \
    "2c6fd0c09d1c49994d6c22789336e062188df29572ed07e7f9779c52"

struct state {
    char *home;
    char *cwd;
    char orig_cwd[PATH_MAX];
};

struct subprocess {
    const char *host;
    uint16_t port;
    char *cert;
    char *key;
    char *ed25519;
    char *apt_release;
    char *apt_main;
    gsize apt_main_size;
    char *apt_contrib;
    gsize apt_contrib_size;
    char *portage_good_tar;
    gsize portage_good_tar_size;
    char *portage_good_sig;
    char *portage_invalid_tar;
    gsize portage_invalid_tar_size;
    char *portage_invalid_sig;
    char *portage_bad_manifest_tar;
    gsize portage_bad_manifest_tar_size;
    char *portage_bad_manifest_sig;
    struct dlp_mhd *mhd;
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

static void setup_subprocess(gpointer data, gconstpointer user_data)
{
    const char *path;
    struct subprocess *s = data;

    (void)user_data;

    s->host = "127.0.0.1";
    s->port = 5555;
    s->cert = g_test_build_filename(G_TEST_DIST, "tests", "data", "tls",
                                    "cert.pem", NULL);
    s->key = g_test_build_filename(G_TEST_DIST, "tests", "data", "tls",
                                   "key.pem", NULL);
    s->ed25519 = g_test_build_filename(G_TEST_DIST, "tests", "data", "gpg",
                                       "ed25519-pub.asc", NULL);

    g_assert_true(dlp_mhd_init(&s->mhd));
    g_assert_true(
        dlp_mhd_start(s->mhd, s->host, s->port, s->key, s->cert, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_signed.asc", NULL);
    g_assert_true(g_file_get_contents(path, &s->apt_release, NULL, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_main.xz", NULL);
    g_assert_true(
        g_file_get_contents(path, &s->apt_main, &s->apt_main_size, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_contrib.xz", NULL);
    g_assert_true(
        g_file_get_contents(path, &s->apt_contrib, &s->apt_contrib_size, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage.tar.xz.base64", NULL);
    g_assert_true(g_file_get_contents(path, &s->portage_good_tar, NULL, NULL));
    g_assert_true(g_base64_decode_inplace(s->portage_good_tar,
                                          &s->portage_good_tar_size));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage.tar.xz.asc", NULL);
    g_assert_true(g_file_get_contents(path, &s->portage_good_sig, NULL, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage-invalid.tar.xz", NULL);
    g_assert_true(g_file_get_contents(path, &s->portage_invalid_tar,
                                      &s->portage_invalid_tar_size, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage-invalid.tar.xz.asc", NULL);
    g_assert_true(
        g_file_get_contents(path, &s->portage_invalid_sig, NULL, NULL));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage-bad-manifest.tar.xz.base64", NULL);
    g_assert_true(
        g_file_get_contents(path, &s->portage_bad_manifest_tar, NULL, NULL));
    g_assert_true(g_base64_decode_inplace(s->portage_bad_manifest_tar,
                                          &s->portage_bad_manifest_tar_size));

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage-bad-manifest.tar.xz.asc", NULL);
    g_assert_true(
        g_file_get_contents(path, &s->portage_bad_manifest_sig, NULL, NULL));
}

static void teardown_subprocess(gpointer data, gconstpointer user_data)
{
    struct subprocess *s = data;

    (void)user_data;

    g_assert_true(dlp_mhd_stop(s->mhd));
    g_assert_true(dlp_mhd_free(s->mhd));
    dlp_mem_free(&s->cert);
    dlp_mem_free(&s->key);
    dlp_mem_free(&s->ed25519);
    dlp_mem_free(&s->apt_release);
    dlp_mem_free(&s->apt_main);
    dlp_mem_free(&s->apt_contrib);
    dlp_mem_free(&s->portage_good_tar);
    dlp_mem_free(&s->portage_good_sig);
    dlp_mem_free(&s->portage_invalid_tar);
    dlp_mem_free(&s->portage_invalid_sig);
    dlp_mem_free(&s->portage_bad_manifest_tar);
    dlp_mem_free(&s->portage_bad_manifest_sig);
}

static void test_cli(gpointer data, gconstpointer user_data)
{
    GTestSubprocessFlags flags;

    (void)data;
    (void)user_data;

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    flags = (GTestSubprocessFlags)(G_TEST_SUBPROCESS_INHERIT_STDOUT |
                                   G_TEST_SUBPROCESS_INHERIT_STDERR);

    g_test_trap_subprocess("/cli/subprocess/apt/success", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr_unmatched("*ERROR*");
    g_test_trap_assert_stdout("* " TEST_SHA256_FOO " *");
    g_test_trap_assert_stdout("* " TEST_SHA256_LIBDISASM_DSC " *");
    g_test_trap_assert_stdout("* " TEST_SHA256_LIBDISASM_ORIG " *");
    g_test_trap_assert_stdout("* " TEST_SHA256_LIBDISASM_DEB " *");

    g_test_trap_subprocess("/cli/subprocess/apt/bad-signature", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*Bad signature*");

    g_test_trap_subprocess("/cli/subprocess/portage/success", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr_unmatched("*ERROR*");
    g_test_trap_assert_stdout("* " TEST_SHA512_FOO " *");
    g_test_trap_assert_stdout("* " TEST_SHA512_BAR " *");
    g_test_trap_assert_stdout("* " TEST_SHA512_QUUX " *");

    g_test_trap_subprocess("/cli/subprocess/portage/success-cache", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr_unmatched("*ERROR*");
    g_test_trap_assert_stdout("* " TEST_SHA512_FOO " *");

    g_test_trap_subprocess("/cli/subprocess/portage/bad-signature", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*Bad signature*");

    g_test_trap_subprocess("/cli/subprocess/portage/bad-signature-cache", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*Bad signature*");

    g_test_trap_subprocess("/cli/subprocess/portage/invalid-archive", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*archive*");

    g_test_trap_subprocess("/cli/subprocess/portage/bad-manifest", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*unexpected*");

    g_test_trap_subprocess("/cli/subprocess/portage/404", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*ERROR*Empty*");

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

static void test_cli_apt_success(gpointer data, gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog", "--config=test-cli", "--repos=test-cli-success",
        "foo",  "libdisasm",         NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-success]\n"
                          "backend = apt\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/InRelease",
                                      "agent", s->apt_release, 0, 0,
                                      MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/main/source/Sources.xz", "agent",
                                      s->apt_main, s->apt_main_size, 0,
                                      MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/contrib/source/Sources.xz", "agent",
                                      s->apt_contrib, s->apt_contrib_size, 0,
                                      MHD_HTTP_OK, NULL));

    g_assert_true(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_apt_bad_signature(gpointer data, gconstpointer user_data)
{
    char *cfg;
    char *release;
    char *tmp;
    char *argv[] = {
        "prog", "--config=test-cli", "--repos=test-cli-bad-signature",
        "foo",  "libdisasm",         NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-bad-signature]\n"
                          "backend = apt\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    release = g_strdup(s->apt_release);
    g_assert_nonnull(tmp = strstr(release, "Debian"));
    *tmp = 'd';
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/InRelease",
                                      "agent", release, 0, 0, MHD_HTTP_OK,
                                      NULL));
    dlp_mem_free(&release);

    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/main/source/Sources.xz", "agent",
                                      s->apt_main, s->apt_main_size, 0,
                                      MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/contrib/source/Sources.xz", "agent",
                                      s->apt_contrib, s->apt_contrib_size, 0,
                                      MHD_HTTP_OK, NULL));

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_portage_success(gpointer data, gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-success",
        "foo",
        "bar",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-success]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(
        dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/portage-latest.tar.xz",
                            "agent", s->portage_good_tar,
                            s->portage_good_tar_size, 0, MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz.gpgsig", "agent",
                                      s->portage_good_sig, 0, 0, MHD_HTTP_OK,
                                      NULL));

    g_assert_true(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_portage_success_cache(gpointer data,
                                           gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-success-cache",
        "no-match",
        NULL,
    };
    char *argv_cache[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-success-cache",
        "foo",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-success-cache]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(
        dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/portage-latest.tar.xz",
                            "agent", s->portage_good_tar,
                            s->portage_good_tar_size, 0, MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz.gpgsig", "agent",
                                      s->portage_good_sig, 0, 0, MHD_HTTP_OK,
                                      NULL));

    g_assert_true(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
    g_assert_true(dlp_cli(G_N_ELEMENTS(argv) - 1, argv_cache));
}

static void test_cli_portage_bad_signature(gpointer data,
                                           gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-bad-signature",
        "foo",
        "bar",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-bad-signature]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz", "agent",
                                      s->portage_good_tar,
                                      s->portage_good_tar_size - 1, 0,
                                      MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz.gpgsig", "agent",
                                      s->portage_good_sig, 0, 0, MHD_HTTP_OK,
                                      NULL));

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_portage_bad_signature_cache(gpointer data,
                                                 gconstpointer user_data)
{
    char *cfg;
    char *path;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-bad-signature-cache",
        "no-match",
        NULL,
    };
    char *argv_cache[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-bad-signature-cache",
        "foo",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-bad-signature-cache]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(
        dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/portage-latest.tar.xz",
                            "agent", s->portage_good_tar,
                            s->portage_good_tar_size, 0, MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz.gpgsig", "agent",
                                      s->portage_good_sig, 0, 0, MHD_HTTP_OK,
                                      NULL));

    g_assert_true(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));

    g_assert_true(dlp_fs_data_path(&path, NULL,
                                   "test-cli-portage-bad-signature-cache",
                                   "portage.tar.xz", NULL));
    g_assert_true(g_file_set_contents(path, "foo", -1, NULL));
    dlp_mem_free(&path);
    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv_cache));
}

static void test_cli_portage_invalid_archive(gpointer data,
                                             gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-invalid-archive",
        "foo",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-invalid-archive]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(
        dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1", "/portage-latest.tar.xz",
                            "agent", s->portage_invalid_tar,
                            s->portage_invalid_tar_size, 0, MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz.gpgsig", "agent",
                                      s->portage_invalid_sig, 0, 0, MHD_HTTP_OK,
                                      NULL));

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_portage_bad_manifest(gpointer data,
                                          gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-bad-manifest",
        "foo",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-bad-manifest]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz", "agent",
                                      s->portage_bad_manifest_tar,
                                      s->portage_bad_manifest_tar_size, 0,
                                      MHD_HTTP_OK, NULL));
    g_assert_true(dlp_mhd_session_add(s->mhd, "GET", "HTTP/1.1",
                                      "/portage-latest.tar.xz.gpgsig", "agent",
                                      s->portage_bad_manifest_sig, 0, 0,
                                      MHD_HTTP_OK, NULL));

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
}

static void test_cli_portage_404(gpointer data, gconstpointer user_data)
{
    char *cfg;
    char *argv[] = {
        "prog",
        "--config=test-cli",
        "--repos=test-cli-portage-404",
        "foo",
        "bar",
        NULL,
    };
    struct subprocess *s = data;

    (void)user_data;

    cfg = g_strdup_printf("[test-cli-portage-404]\n"
                          "backend = portage\n"
                          "url = %s:%u\n"
                          "ca-file = %s\n"
                          "tls-key = "
                          "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                          "o6fCDtm59VBQ8=\n"
                          "verify-keys = %s\n"
                          "user-agent = agent\n",
                          s->host, s->port, s->cert, s->ed25519);
    g_assert_true(g_file_set_contents("test-cli", cfg, -1, NULL));
    dlp_mem_free(&cfg);

    g_assert_false(dlp_cli(G_N_ELEMENTS(argv) - 1, argv));
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
    g_test_add_vtable("/cli/subprocess/apt/success", sizeof(struct subprocess),
                      NULL, setup_subprocess, test_cli_apt_success,
                      teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/apt/bad-signature",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_apt_bad_signature, teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/success",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_portage_success, teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/success-cache",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_portage_success_cache, teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/bad-signature",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_portage_bad_signature, teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/bad-signature-cache",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_portage_bad_signature_cache,
                      teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/invalid-archive",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_portage_invalid_archive, teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/bad-manifest",
                      sizeof(struct subprocess), NULL, setup_subprocess,
                      test_cli_portage_bad_manifest, teardown_subprocess);
    g_test_add_vtable("/cli/subprocess/portage/404", sizeof(struct subprocess),
                      NULL, setup_subprocess, test_cli_portage_404,
                      teardown_subprocess);
    g_test_add_func("/cli/subprocess/bad-option", test_cli_bad_option);
    g_test_add_func("/cli/subprocess/missing-config", test_cli_missing_config);
    g_test_add_func("/cli/subprocess/failed-curl-init",
                    test_cli_failed_curl_init);

    return g_test_run();
}

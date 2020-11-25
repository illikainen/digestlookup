/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include <fcntl.h>

#include "config.h"
#include "dlp_cfg.h"
#include "dlp_error.h"
#include "dlp_fs.h"
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

static gint cmp_repo(gconstpointer a, gconstpointer b)
{
    const struct dlp_cfg_repo *repo = a;

    if (repo == NULL) {
        return -1;
    }
    return g_strcmp0(repo->name, b);
}

static void test_cfg_free(gpointer data, gconstpointer user_data)
{
    struct dlp_cfg *cfg = NULL;

    (void)data;
    (void)user_data;

    dlp_cfg_free(NULL);
    dlp_cfg_free(&cfg);
    g_assert_null(cfg);
}

static void test_cfg_read(gpointer data, gconstpointer user_data)
{
    bool rv;
    GList *l;
    struct dlp_cfg *cfg;
    struct dlp_cfg_repo *r;
    GError *err = NULL;
    char *str;
    char *defpath;
    char *dir;
    const char *path;

    (void)data;
    (void)user_data;

    path = g_test_get_filename(G_TEST_BUILT, "cfg", NULL);
    g_assert_true(
        dlp_fs_config_path(&defpath, NULL, PROJECT_NAME ".conf", NULL));

    /* No path. */
    rv = dlp_cfg_read(NULL, &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(cfg);
    g_assert_nonnull(cfg->repos);
    g_assert_nonnull(
        l = g_list_find_custom(cfg->repos, "debian-stable", cmp_repo));
    r = l->data;
    g_assert_cmpuint(r->verify_keys->len, ==, 3);
    dlp_cfg_free(&cfg);

    /* Valid user-specified config override. */
    g_assert_true(g_file_set_contents(path,
                                      "[debian-stable]\n"
                                      "user-agent = foo\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(cfg);
    g_assert_nonnull(cfg->repos);
    g_assert_nonnull(
        l = g_list_find_custom(cfg->repos, "debian-stable", cmp_repo));
    r = l->data;
    g_assert_cmpstr(r->user_agent, ==, "foo");
    dlp_cfg_free(&cfg);

    /* Valid default config override. */
    g_assert_true(g_file_set_contents(defpath,
                                      "[debian-stable]\n"
                                      "user-agent = foo\n",
                                      -1, NULL));
    rv = dlp_cfg_read(NULL, &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(cfg);
    g_assert_nonnull(cfg->repos);
    g_assert_nonnull(
        l = g_list_find_custom(cfg->repos, "debian-stable", cmp_repo));
    r = l->data;
    g_assert_cmpstr(r->user_agent, ==, "foo");
    dlp_cfg_free(&cfg);

    /* Valid default config override. */
    str = g_strdup_printf("[debian-stable]\nverify-keys = %s\n", path);
    g_assert_true(g_file_set_contents(defpath, str, -1, NULL));
    rv = dlp_cfg_read(NULL, &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(cfg);
    g_assert_nonnull(cfg->repos);
    g_assert_nonnull(
        l = g_list_find_custom(cfg->repos, "debian-stable", cmp_repo));
    r = l->data;
    g_assert_cmpuint(r->verify_keys->len, ==, 1);
    g_assert_cmpstr(r->verify_keys->pdata[0], ==, path);
    dlp_cfg_free(&cfg);
    dlp_mem_free(&str);

    /* Invalid override. */
    g_assert_true(g_file_set_contents(path,
                                      "[debian-stable]\n"
                                      "cache = foo\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Bogus user-specified config. */
    g_assert_true(g_file_set_contents(path, "abcdefghijkl\n", -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Bogus default config. */
    g_assert_true(g_file_set_contents(defpath, "abcdefghijkl\n", -1, NULL));
    rv = dlp_cfg_read(NULL, &cfg, &err);
    g_assert_error(err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);
    g_assert_cmpint(unlink(defpath), ==, 0);

    /* Missing user-specified config. */
    path = g_test_get_filename(G_TEST_BUILT, "cfg1", NULL);
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, DLP_ERROR, ENOENT);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);
    path = g_test_get_filename(G_TEST_BUILT, "cfg", NULL);

    /* Missing file. */
    g_assert_true(g_file_set_contents(path,
                                      "[debian-stable]\n"
                                      "verify-keys = foo/bar/baz\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, DLP_ERROR, ENOENT);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Missing resource. */
    g_assert_true(g_file_set_contents(path,
                                      "[debian-stable]\n"
                                      "verify-keys = resource://foo/bar/baz\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, G_RESOURCE_ERROR, G_RESOURCE_ERROR_NOT_FOUND);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Default uint64. */
    g_assert_true(g_file_set_contents(path,
                                      "[foo]\n"
                                      "url = https://127.0.0.1\n"
                                      "tls-key = sha256://bar\n"
                                      "verify-keys = "
                                      "resource:///dlp/keys/debian/"
                                      "buster-automatic.asc\n"
                                      "backend = apt\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(cfg);
    g_assert_nonnull(cfg->repos);
    g_assert_nonnull(l = g_list_find_custom(cfg->repos, "foo", cmp_repo));
    r = l->data;
    g_assert_cmpuint(r->cache, !=, 0);
    dlp_cfg_free(&cfg);

    /* Missing url. */
    g_assert_true(g_file_set_contents(path,
                                      "[foo]\n"
                                      "tls-key = sha256://bar\n"
                                      "verify-keys = "
                                      "resource:///dlp/keys/debian/"
                                      "buster-automatic.asc\n"
                                      "backend = apt\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Missing verify-keys. */
    g_assert_true(g_file_set_contents(path,
                                      "[foo]\n"
                                      "url = https://127.0.0.1\n"
                                      "tls-key = sha256://bar\n"
                                      "backend = apt\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Missing backend. */
    str = g_strdup_printf("[foo]\n"
                          "verify-keys = %s\n"
                          "url = https://127.0.0.1\n"
                          "tls-key = sha256://bar\n",
                          path);
    g_assert_true(g_file_set_contents(path, str, -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);
    dlp_mem_free(&str);

    /* Invalid backend. */
    g_assert_true(g_file_set_contents(path,
                                      "[debian-stable]\n"
                                      "backend = foobar\n",
                                      -1, NULL));
    rv = dlp_cfg_read(path, &cfg, &err);
    g_assert_error(err, DLP_ERROR, DLP_BACKEND_ERROR_NOT_FOUND);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);

    /* Bad permission. */
    dir = g_path_get_dirname(defpath);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(dir, S_IRWXU | S_IWOTH), 0);
    rv = dlp_cfg_read(NULL, &cfg, &err);
    g_assert_error(err, DLP_ERROR, EBADFD);
    g_assert_false(rv);
    g_assert_null(cfg);
    g_clear_error(&err);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(dir, S_IRWXU), 0);
    dlp_mem_free(&dir);

    if (test_wrap_p()) {
        /* Bad load. */
        test_wrap_push(g_key_file_load_from_data, true, NULL);
        rv = dlp_cfg_read(NULL, &cfg, &err);
        g_assert_no_error(err);
        g_assert_false(rv);
        g_assert_null(cfg);

        /* Missing value. */
        g_assert_true(g_file_set_contents(path,
                                          "[debian-stable]\n"
                                          "user-agent = foo\n",
                                          -1, NULL));
        test_wrap_push(g_key_file_get_value, true, NULL);
        rv = dlp_cfg_read(path, &cfg, &err);
        g_assert_no_error(err);
        g_assert_false(rv);
        g_assert_null(cfg);
    }

    dlp_mem_free(&defpath);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_add_vtable("/cfg/free", sizeof(struct state), NULL, setup,
                      test_cfg_free, teardown);
    g_test_add_vtable("/cfg/read", sizeof(struct state), NULL, setup,
                      test_cfg_read, teardown);

    g_test_init(&argc, &argv, NULL);

    return g_test_run();
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include <sys/stat.h>
#include <unistd.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "test.h"

enum test_fs_error {
    TEST_FS_ERROR_FAILED = 1,
};

struct state {
    char *home;
    char orig_cwd[PATH_MAX];
};

struct walk_data {
    bool rv;
    GList *list;
};

static int group_setup(void **state)
{
    const char *cwd;
    struct state *s;

    s = g_malloc0(sizeof(*s));

    if (!test_setup_home(&s->home)) {
        g_free(s);
        return -1;
    }

    if (getcwd(s->orig_cwd, sizeof(s->orig_cwd)) == NULL) {
        g_free(s);
        return -1;
    }

    if ((cwd = g_getenv("DLP_TEST_HOME")) == NULL) {
        g_free(s);
        return -1;
    }

    if (chdir(cwd) != 0) {
        g_free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int group_teardown(void **state)
{
    int rv;
    struct state *s = *state;

    rv = chdir(s->orig_cwd);

    g_free(s->home);
    g_free(s);

    return rv;
}

static bool test_walk_retval_cb(int fd, const char *name, const char *path,
                                const struct stat *s, void *data,
                                GError **error)
{
    struct walk_data *wd = data;

    (void)fd;
    (void)name;
    (void)path;
    (void)s;

    if (!wd->rv) {
        g_set_error(error, DLP_ERROR, TEST_FS_ERROR_FAILED, "foobar");
    }
    return wd->rv;
}

static bool test_walk_filelist_cb(int fd, const char *name, const char *path,
                                  const struct stat *s, void *data,
                                  GError **error)
{
    struct walk_data *wd = data;

    (void)fd;
    (void)name;
    (void)s;
    (void)error;

    wd->list = g_list_prepend(wd->list, g_strdup(path));
    return wd->rv;
}

static void test_walk_symlink(void **state)
{
    GError *err = NULL;
    struct walk_data wd = { .rv = true };

    (void)state;

    assert_int_equal(symlink(".", "link"), 0);
    assert_false(dlp_fs_walk("link", test_walk_retval_cb, &wd, &err));
    TEST_ASSERT_ERR(err, ELOOP, "*");
    assert_int_equal(unlink("link"), 0);
}

/*
 * FIXME: hardcoded path separator.
 */
static void test_walk_cb_failure(void **state)
{
    GError *err = NULL;
    struct walk_data wd = { .rv = false };

    (void)state;

    assert_true(dlp_fs_mkdir("foo/bar/baz", NULL));

    assert_false(dlp_fs_walk("foo/bar/baz", test_walk_retval_cb, &wd, &err));
    TEST_ASSERT_ERR(err, TEST_FS_ERROR_FAILED, "foobar");

    assert_false(dlp_fs_walk("foo/bar", test_walk_retval_cb, &wd, &err));
    TEST_ASSERT_ERR(err, TEST_FS_ERROR_FAILED, "foobar");

    assert_false(dlp_fs_walk("foo", test_walk_retval_cb, &wd, &err));
    TEST_ASSERT_ERR(err, TEST_FS_ERROR_FAILED, "foobar");

    assert_true(dlp_fs_rmdir("foo", NULL));
}

/*
 * FIXME: hardcoded path separator.
 */
static void test_walk_filelist(void **state)
{
    guint i;
    GList *got;
    GList *want = NULL;
    static struct walk_data wd = { .rv = true, .list = NULL };

    (void)state;

    assert_true(dlp_fs_mkdir("b", NULL));
    assert_true(dlp_fs_mkdir("a", NULL));
    want = g_list_prepend(want, "a");

    /* empty directories */
    assert_true(dlp_fs_mkdir("a/empty1", NULL));
    assert_true(dlp_fs_mkdir("a/empty2", NULL));
    want = g_list_prepend(want, "a/empty1");
    want = g_list_prepend(want, "a/empty2");

    /* regular files */
    assert_true(dlp_fs_mkdir("a/foo/bar/baz", NULL));
    assert_true(g_file_set_contents("a/foo/bar/baz/qux", "abc", -1, NULL));
    assert_true(g_file_set_contents("a/foo/bar/baz/quux", "def", -1, NULL));
    want = g_list_prepend(want, "a/foo");
    want = g_list_prepend(want, "a/foo/bar");
    want = g_list_prepend(want, "a/foo/bar/baz");
    want = g_list_prepend(want, "a/foo/bar/baz/qux");
    want = g_list_prepend(want, "a/foo/bar/baz/quux");

    /* symlinks */
    assert_true(g_file_set_contents("b/abc", "xyz", -1, NULL));
    assert_int_equal(symlink("../b", "a/dirlink"), 0);
    assert_int_equal(symlink("../b/abc", "a/filelink"), 0);
    assert_int_equal(symlink("../b/missing", "a/brokenlink"), 0);
    assert_int_equal(symlink("cycle2", "a/cycle1"), 0);
    assert_int_equal(symlink("cycle1", "a/cycle2"), 0);
    want = g_list_prepend(want, "a/dirlink");
    want = g_list_prepend(want, "a/filelink");
    want = g_list_prepend(want, "a/brokenlink");
    want = g_list_prepend(want, "a/cycle1");
    want = g_list_prepend(want, "a/cycle2");

    assert_true(dlp_fs_walk("a", test_walk_filelist_cb, &wd, NULL));

    want = g_list_sort(want, (GCompareFunc)g_strcmp0);
    got = g_list_sort(wd.list, (GCompareFunc)g_strcmp0);

    assert_int_equal(g_list_length(got), g_list_length(want));
    for (i = 0; i < g_list_length(want); i++) {
        assert_string_equal(g_list_nth_data(got, i), g_list_nth_data(want, i));
    }

    g_list_free(want);
    g_list_free_full(got, g_free);

    assert_true(dlp_fs_rmdir("a", NULL));
    assert_true(dlp_fs_rmdir("b", NULL));
}

static void test_user_dir(void **state)
{
    size_t i;
    bool (*fn[])(char **path, GError **error) = {
        dlp_fs_cache_dir,
        dlp_fs_config_dir,
        dlp_fs_data_dir,
    };
    char *path[TEST_ARRAY_LEN(fn)];
    char *p = NULL;
    GError *err = NULL;
    struct state *s = *state;

    for (i = 0; i < TEST_ARRAY_LEN(fn); i++) {
        assert_true(fn[i](&path[i], &err));
        assert_null(err);
        assert_ptr_equal(path[i], strstr(path[i], s->home));

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(path[i], S_IRWXU | S_IWGRP), 0);
        assert_false(fn[i](&p, &err));
        assert_null(p);
        TEST_ASSERT_ERR(err, DLP_FS_ERROR_FAILED, "*permission*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(path[i], S_IRWXU | S_IWOTH), 0);
        assert_false(fn[i](&p, &err));
        assert_null(p);
        TEST_ASSERT_ERR(err, DLP_FS_ERROR_FAILED, "*permission*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(path[i], S_IRWXU), 0);
        g_free(path[i]);
    }
}

static void test_mkdir(void **state)
{
    char *p;
    char *sp;
    GError *err = NULL;

    (void)state;

    assert_true(dlp_fs_cache_dir(&p, NULL));
    assert_true(dlp_fs_mkdir(p, NULL));

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU | S_IWGRP), 0);
    assert_false(dlp_fs_mkdir(p, &err));
    TEST_ASSERT_ERR(err, DLP_FS_ERROR_FAILED, "*permission*");

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU | S_IWOTH), 0);
    assert_false(dlp_fs_mkdir(p, &err));
    TEST_ASSERT_ERR(err, DLP_FS_ERROR_FAILED, "*permission*");

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU | S_IWGRP | S_IWOTH), 0);
    assert_false(dlp_fs_mkdir(p, &err));
    TEST_ASSERT_ERR(err, DLP_FS_ERROR_FAILED, "*permission*");

    assert_int_equal(chmod(p, 0), 0);
    sp = g_build_filename(p, "subpath", NULL);
    assert_false(dlp_fs_mkdir(sp, &err));
    TEST_ASSERT_ERR(err, EACCES, "*denied*");

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU), 0);

    g_free(p);
    g_free(sp);
}

/*
 * FIXME: hardcoded path separator.
 */
static void test_rmdir(void **state)
{
    struct stat s;
    GError *err = NULL;

    (void)state;

    /* missing directory */
    assert_false(dlp_fs_rmdir("a", &err));
    TEST_ASSERT_ERR(err, ENOENT, "*");

    /* empty directory */
    assert_true(dlp_fs_mkdir("a", NULL));
    assert_true(dlp_fs_rmdir("a", &err));
    assert_null(err);
    assert_int_not_equal(stat("a", &s), 0);

    /* directory with subdirectories, files and symlinks */
    assert_true(dlp_fs_mkdir("a", NULL));
    assert_true(dlp_fs_mkdir("b", NULL));
    assert_true(g_file_set_contents("b/abc", "xyz", -1, NULL));
    assert_int_equal(symlink("../b", "a/dirlink"), 0);
    assert_int_equal(symlink("../b/abc", "a/filelink"), 0);
    assert_int_equal(symlink("../b/missing", "a/brokenlink"), 0);
    assert_int_equal(symlink("cycle2", "a/cycle1"), 0);
    assert_int_equal(symlink("cycle1", "a/cycle2"), 0);
    assert_true(dlp_fs_mkdir("a/foo/bar/baz/qux", NULL));
    assert_true(g_file_set_contents("a/foo/bar/baz/qux/a", "a", -1, NULL));
    assert_true(g_file_set_contents("a/foo/bar/baz/qux/b", "b", -1, NULL));
    assert_true(g_file_set_contents("a/foo/bar/baz/qux/c", "c", -1, NULL));
    assert_true(g_file_set_contents("a/foo/bar/d", "d", -1, NULL));

    /* successful removal of a */
    assert_true(dlp_fs_rmdir("a", &err));
    assert_null(err);
    assert_int_not_equal(stat("a", &s), 0);
    assert_int_equal(stat("b", &s), 0);
    assert_int_equal(stat("b/abc", &s), 0);

    /* failed removal of b */
    assert_true(dlp_fs_mkdir("b/c/d", NULL));
    assert_int_equal(chmod("b/c/d", 0), 0);
    assert_false(dlp_fs_rmdir("b", &err));
    TEST_ASSERT_ERR(err, EACCES, "*denied*");
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod("b/c/d", S_IRWXU), 0);
    assert_int_equal(stat("b", &s), 0);
    assert_int_equal(stat("b/c/d", &s), 0);

    /* successful removal of b */
    assert_true(dlp_fs_rmdir("b", &err));
    assert_null(err);
    assert_int_not_equal(stat("b", &s), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_user_dir),
        cmocka_unit_test(test_mkdir),
        cmocka_unit_test(test_rmdir),
        cmocka_unit_test(test_walk_symlink),
        cmocka_unit_test(test_walk_cb_failure),
        cmocka_unit_test(test_walk_filelist),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

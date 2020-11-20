/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "test.h"

enum test_fs_error {
    TEST_FS_ERROR_FAILED = 1,
};

struct state {
    char *home;
    char *cwd;
    char orig_cwd[PATH_MAX];
};

struct walk_data {
    bool rv;
    GList *list;
};

static int group_setup(void **state)
{
    struct state *s;

    s = dlp_mem_alloc(sizeof(*s));

    if (!test_setup_home(&s->home)) {
        dlp_mem_free(&s);
        return -1;
    }

    if (getcwd(s->orig_cwd, sizeof(s->orig_cwd)) == NULL) {
        dlp_mem_free(&s);
        return -1;
    }

    if ((s->cwd = g_strdup(g_getenv("DLP_TEST_HOME"))) == NULL) {
        dlp_mem_free(&s);
        return -1;
    }

    if (chdir(s->cwd) != 0) {
        dlp_mem_free(&s->cwd);
        dlp_mem_free(&s);
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
    rv += dlp_fs_rmdir(s->cwd, NULL) == false;

    dlp_mem_free(&s->cwd);
    dlp_mem_free(&s->home);
    dlp_mem_free(&s);

    return rv != 0;
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
    errno_t e;
    GList *got;
    GError *err = NULL;
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

    if (test_wrap_p()) {
        /* fdopendir() failure */
        e = EACCES;
        test_wrap_push(fdopendir, true, &e);
        assert_false(dlp_fs_walk("a", test_walk_filelist_cb, &wd, &err));
        TEST_ASSERT_ERR(err, e, "*");
        g_clear_error(&err);

        /* readdir() failure */
        e = EBADF;
        test_wrap_push(readdir64, true, &e);
        assert_false(dlp_fs_walk("a", test_walk_filelist_cb, &wd, &err));
        TEST_ASSERT_ERR(err, e, "*");
        g_clear_error(&err);

        /* closedir() failure */
        e = EBADF;
        test_wrap_push(closedir, true, &e);
        assert_false(dlp_fs_walk("a", test_walk_filelist_cb, &wd, &err));
        TEST_ASSERT_ERR(err, e, "*");
        g_clear_error(&err);

        /* fstat() failure */
        e = ENAMETOOLONG;
        test_wrap_push(__fxstat64, true, &e);
        assert_false(dlp_fs_walk("a", test_walk_filelist_cb, &wd, &err));
        TEST_ASSERT_ERR(err, e, "*");
        g_clear_error(&err);

        e = ENONET;
        test_wrap_push(__fxstat64, true, &e);
        test_wrap_push(__fxstat64, false, NULL);
        assert_false(dlp_fs_walk("a", test_walk_filelist_cb, &wd, &err));
        TEST_ASSERT_ERR(err, e, "*");
        g_clear_error(&err);

        /* fstatat() failure */
        e = EACCES;
        test_wrap_push(__fxstatat64, true, &e);
        assert_false(dlp_fs_walk("a", test_walk_filelist_cb, &wd, &err));
        TEST_ASSERT_ERR(err, e, "*");
        g_clear_error(&err);
    }

    assert_true(dlp_fs_rmdir("a", NULL));
    assert_true(dlp_fs_rmdir("b", NULL));
}

static void test_user_dir(void **state)
{
    size_t i;
    struct stat st;
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
        assert_int_equal(stat(path[i], &st), 0);
        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(st.st_mode & (mode_t)~S_IFMT, S_IRWXU);

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(path[i], S_IRWXU | S_IWGRP), 0);
        assert_false(fn[i](&p, &err));
        assert_null(p);
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(path[i], S_IRWXU | S_IWOTH), 0);
        assert_false(fn[i](&p, &err));
        assert_null(p);
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(path[i], S_IRWXU), 0);
        dlp_mem_free(&path[i]);
    }
}

static void test_user_path(void **state)
{
    size_t i;
    struct stat st;
    bool (*fn[])(char **path, GError **error, ...) = {
        dlp_fs_cache_path,
        dlp_fs_config_path,
        dlp_fs_data_path,
    };
    char *path[TEST_ARRAY_LEN(fn)];
    char *dir;
    char *typedir;
    char *p = NULL;
    GError *err = NULL;
    struct state *s = *state;

    for (i = 0; i < TEST_ARRAY_LEN(fn); i++) {
        assert_true(fn[i](&path[i], &err, "foo", "bar", NULL));
        assert_null(err);
        assert_ptr_equal(path[i], strstr(path[i], s->home));
        assert_non_null(dir = g_path_get_dirname(path[i]));
        assert_non_null(typedir = g_path_get_dirname(dir));
        assert_int_equal(stat(dir, &st), 0);
        assert_true(st.st_mode & DLP_FS_DIR);
        assert_int_not_equal(stat(path[i], &st), 0);

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(typedir, S_IRWXU | S_IWGRP), 0);
        assert_false(fn[i](&p, &err, "foo", "baz", NULL));
        assert_null(p);
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(typedir, S_IRWXU | S_IWOTH), 0);
        assert_false(fn[i](&p, &err, "foo", "qux", NULL));
        assert_null(p);
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(typedir, S_IRWXU), 0);

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(dir, S_IRWXU | S_IWGRP), 0);
        assert_false(fn[i](&p, &err, "foo", "baz", NULL));
        assert_null(p);
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(dir, S_IRWXU | S_IWOTH), 0);
        assert_false(fn[i](&p, &err, "foo", "qux", NULL));
        assert_null(p);
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
        assert_int_equal(chmod(dir, S_IRWXU), 0);
        dlp_mem_free(&dir);
        dlp_mem_free(&typedir);
        dlp_mem_free(&path[i]);
    }
}

static void test_check_stat(void **state)
{
    int fd;
    struct stat s;
    GError *err = NULL;

    (void)state;

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    fd = open("check-stat", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IWUSR);
    assert_int_not_equal(fd, -1);

    assert_int_equal(fstat(fd, &s), 0);
    assert_false(dlp_fs_check_stat(&s, DLP_FS_DIR, &err));
    TEST_ASSERT_ERR(err, DLP_FS_ERROR_TYPE, "*");
    assert_true(dlp_fs_check_stat(&s, DLP_FS_REG, &err));
    assert_null(err);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fchmod(fd, S_IWUSR | S_IWGRP), 0);
    assert_int_equal(fstat(fd, &s), 0);
    assert_false(dlp_fs_check_stat(&s, DLP_FS_REG, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");
    g_clear_error(&err);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fchmod(fd, S_IWUSR | S_IWOTH), 0);
    assert_int_equal(fstat(fd, &s), 0);
    assert_false(dlp_fs_check_stat(&s, DLP_FS_REG, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");
    g_clear_error(&err);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fchmod(fd, S_IWUSR | S_IWGRP | S_IWOTH), 0);
    assert_int_equal(fstat(fd, &s), 0);
    assert_false(dlp_fs_check_stat(&s, DLP_FS_REG, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");
    g_clear_error(&err);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fchmod(fd, S_IWUSR), 0);
    assert_int_equal(fstat(fd, &s), 0);
    assert_true(dlp_fs_check_stat(&s, DLP_FS_REG, &err));
    assert_null(err);

    assert_int_equal(close(fd), 0);
}

static void test_check_path(void **state)
{
    int fd;
    char *path = "check-path";
    GError *err = NULL;

    (void)state;

    assert_false(dlp_fs_check_path(path, DLP_FS_REG, true, &err));
    TEST_ASSERT_ERR(err, ENOENT, "*");

    assert_true(dlp_fs_check_path(path, DLP_FS_REG, false, &err));
    assert_null(err);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IWUSR);
    assert_int_not_equal(fd, -1);

    assert_true(dlp_fs_check_path(path, DLP_FS_REG, true, &err));
    assert_null(err);

    assert_false(dlp_fs_check_path(path, DLP_FS_DIR, true, &err));
    TEST_ASSERT_ERR(err, DLP_FS_ERROR_TYPE, "*");

    assert_false(dlp_fs_check_path(path, DLP_FS_DIR, false, &err));
    TEST_ASSERT_ERR(err, DLP_FS_ERROR_TYPE, "*");

    assert_int_equal(close(fd), 0);
}

static void test_openat(void **state)
{
    int fd;
    int fdflags;
    int tmp;
    GError *err = NULL;
    int flags = O_RDWR | O_CREAT; /* NOLINT(hicpp-signed-bitwise) */
    mode_t mode = S_IRUSR | S_IWUSR; /* NOLINT(hicpp-signed-bitwise) */

    (void)state;

    assert_true(dlp_fs_openat(AT_FDCWD, "openat", flags, mode, &fd, &err));
    assert_null(err);

    /*
     * Check mode.
     */
    assert_int_not_equal((fdflags = fcntl(fd, F_GETFD)), -1);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_not_equal(fdflags & FD_CLOEXEC, 0);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fdflags & O_NONBLOCK, 0);

    /*
     * Open failure.
     */
    assert_int_equal(fchmod(fd, 0), 0);
    assert_false(dlp_fs_openat(AT_FDCWD, "openat", flags, mode, &tmp, &err));
    assert_non_null(err);
    g_clear_error(&err);
    assert_int_equal(fchmod(fd, mode), 0);

    /*
     * Bad permissions.
     */
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fchmod(fd, mode | S_IWGRP), 0);
    assert_false(dlp_fs_openat(AT_FDCWD, "openat", flags, mode, &tmp, &err));
    assert_non_null(err);
    g_clear_error(&err);
    assert_int_equal(fchmod(fd, mode), 0);

    if (test_wrap_p()) {
        tmp = EBADF;
        test_wrap_push(__fxstat64, true, &tmp);
        assert_false(dlp_fs_openat(AT_FDCWD, "fstat", flags, mode, &fd, &err));
        TEST_ASSERT_ERR(err, EBADF, "*");
    }
}

static void test_open(void **state)
{
    int fd;
    int fdflags;
    int tmp;
    GError *err = NULL;
    int flags = O_RDWR | O_CREAT; /* NOLINT(hicpp-signed-bitwise) */
    mode_t mode = S_IRUSR | S_IWUSR; /* NOLINT(hicpp-signed-bitwise) */

    (void)state;

    assert_true(dlp_fs_open("open", flags, mode, &fd, &err));
    assert_null(err);

    /*
     * Check mode.
     */
    assert_int_not_equal((fdflags = fcntl(fd, F_GETFD)), -1);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_not_equal(fdflags & FD_CLOEXEC, 0);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fdflags & O_NONBLOCK, 0);

    /*
     * Open failure.
     */
    assert_int_equal(fchmod(fd, 0), 0);
    assert_false(dlp_fs_open("open", flags, mode, &tmp, &err));
    assert_non_null(err);
    g_clear_error(&err);
    assert_int_equal(fchmod(fd, mode), 0);

    /*
     * Bad permissions.
     */
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(fchmod(fd, mode | S_IWGRP), 0);
    assert_false(dlp_fs_open("open", flags, mode, &tmp, &err));
    assert_non_null(err);
    g_clear_error(&err);
    assert_int_equal(fchmod(fd, mode), 0);
}

static void test_close(void **state)
{
    int fd;
    errno_t e;
    GError *err = NULL;
    int flags = O_RDWR | O_CREAT; /* NOLINT(hicpp-signed-bitwise) */
    mode_t mode = S_IRUSR | S_IWUSR; /* NOLINT(hicpp-signed-bitwise) */

    (void)state;

    assert_true(dlp_fs_close(NULL, NULL));
    assert_true(dlp_fs_close(NULL, &err));
    assert_null(err);

    assert_true(dlp_fs_open("close", flags, mode, &fd, &err));

    assert_true(dlp_fs_close(&fd, &err));
    assert_int_equal(fd, -1);
    assert_null(err);

    assert_true(dlp_fs_close(&fd, &err));
    assert_int_equal(fd, -1);
    assert_null(err);

    if (test_wrap_p()) {
        e = EBADF;
        test_wrap_push(close, true, &e);
        assert_true(dlp_fs_open("close", flags, mode, &fd, &err));
        assert_false(dlp_fs_close(&fd, &err));
        assert_int_equal(fd, -1);
        TEST_ASSERT_ERR(err, EBADF, "*");
        assert_true(dlp_fs_close(&fd, NULL));
    }
}

static void test_seek(void **state)
{
    int fd;
    GError *err = NULL;
    char buf[MIN(MIN(SSIZE_MAX, G_MAXSSIZE), 4096)];
    int flags = O_RDWR | O_CREAT; /* NOLINT(hicpp-signed-bitwise) */
    mode_t mode = S_IRUSR | S_IWUSR; /* NOLINT(hicpp-signed-bitwise) */

    (void)state;

    assert_true(dlp_fs_open("seek", flags, mode, &fd, &err));
    assert_int_equal(write(fd, "foobar", 6), 6);

    assert_true(dlp_fs_seek(fd, 0, SEEK_SET, &err));
    assert_null(err);
    assert_int_equal(read(fd, buf, sizeof(buf)), 6);
    assert_int_equal(strncmp(buf, "foobar", 6), 0);

    assert_true(dlp_fs_seek(fd, 3, SEEK_SET, &err));
    assert_null(err);
    assert_int_equal(read(fd, buf, sizeof(buf)), 3);
    assert_int_equal(strncmp(buf, "bar", 3), 0);

    assert_true(dlp_fs_seek(fd, -2, SEEK_END, &err));
    assert_null(err);
    assert_int_equal(read(fd, buf, sizeof(buf)), 2);
    assert_int_equal(strncmp(buf, "ar", 2), 0);

    assert_true(dlp_fs_seek(fd, 3, SEEK_SET, &err));
    assert_true(dlp_fs_seek(fd, 1, SEEK_CUR, &err));
    assert_null(err);
    assert_int_equal(read(fd, buf, sizeof(buf)), 2);
    assert_int_equal(strncmp(buf, "ar", 2), 0);

    assert_false(dlp_fs_seek(fd, 0, 12345, &err));
    TEST_ASSERT_ERR(err, EINVAL, "*");

    assert_true(dlp_fs_close(&fd, NULL));
}

static void test_truncate(void **state)
{
    int fd;
    GError *err = NULL;
    char buf[MIN(MIN(SSIZE_MAX, G_MAXSSIZE), 4096)];
    int flags = O_RDWR | O_CREAT; /* NOLINT(hicpp-signed-bitwise) */
    mode_t mode = S_IRUSR | S_IWUSR; /* NOLINT(hicpp-signed-bitwise) */

    (void)state;

    assert_true(dlp_fs_open("seek", flags, mode, &fd, &err));

    assert_int_equal(write(fd, "foobar", 6), 6);
    assert_true(dlp_fs_truncate(fd, 3, &err));
    assert_null(err);
    assert_true(dlp_fs_seek(fd, 0, SEEK_SET, &err));
    assert_int_equal(read(fd, buf, sizeof(buf)), 3);
    assert_int_equal(strncmp(buf, "foo", 3), 0);

    assert_false(dlp_fs_truncate(fd, -1, &err));
    TEST_ASSERT_ERR(err, EINVAL, "*");

    assert_true(dlp_fs_close(&fd, NULL));
}

static void test_mkdir(void **state)
{
    char *p;
    char *sp;
    struct stat st;
    errno_t e;
    uid_t uid;
    gid_t gid;
    GError *err = NULL;

    (void)state;

    assert_true(dlp_fs_cache_dir(&p, NULL));
    assert_true(dlp_fs_mkdir(p, NULL));
    assert_int_equal(stat(p, &st), 0);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(st.st_mode & (mode_t)~S_IFMT, S_IRWXU);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU | S_IWGRP), 0);
    assert_false(dlp_fs_mkdir(p, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU | S_IWOTH), 0);
    assert_false(dlp_fs_mkdir(p, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU | S_IWGRP | S_IWOTH), 0);
    assert_false(dlp_fs_mkdir(p, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");

    assert_int_equal(chmod(p, 0), 0);
    sp = g_build_filename(p, "subpath", NULL);
    assert_false(dlp_fs_mkdir(sp, &err));
    TEST_ASSERT_ERR(err, EACCES, "*denied*");

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(p, S_IRWXU), 0);

    dlp_mem_free(&p);
    dlp_mem_free(&sp);

    if (test_wrap_p()) {
        /* stat() failure */
        e = EACCES;
        test_wrap_push(__xstat64, true, &e);
        assert_false(dlp_fs_mkdir("stat", &err));
        TEST_ASSERT_ERR(err, e, "*");

        /* getuid() failure */
        uid = 12345;
        test_wrap_push(getuid, true, &uid);
        assert_false(dlp_fs_mkdir("getuid", &err));
        TEST_ASSERT_ERR(err, EBADFD, "*");

        /* getgid() failure */
        gid = 12345;
        test_wrap_push(getgid, true, &gid);
        assert_false(dlp_fs_mkdir("getuid", &err));
        TEST_ASSERT_ERR(err, EBADFD, "*");
    }
}

/*
 * FIXME: hardcoded path separator.
 */
static void test_rmdir(void **state)
{
    struct stat s;
    errno_t e;
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

    if (test_wrap_p()) {
        /* unlinkat() failure */
        e = EACCES;
        test_wrap_push(unlinkat, true, &e);
        assert_false(dlp_fs_rmdir("b", &err));
        TEST_ASSERT_ERR(err, e, "*");
        assert_int_equal(stat("b", &s), 0);
    }

    /* successful removal of b */
    assert_true(dlp_fs_rmdir("b", &err));
    assert_null(err);
    assert_int_not_equal(stat("b", &s), 0);
}

static void test_mkdtemp(void **state)
{
    char *cache;
    char *path;
    struct stat st;
    errno_t e;
    GError *err = NULL;
    struct state *s = *state;

    /* permission failure */
    assert_true(dlp_fs_cache_dir(&cache, NULL));
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(cache, S_IRWXU | S_IWGRP), 0);
    assert_false(dlp_fs_mkdtemp(&path, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(cache, S_IRWXU), 0);
    dlp_mem_free(&cache);

    /* success */
    assert_true(dlp_fs_mkdtemp(&path, &err));
    assert_null(err);
    assert_ptr_equal(strstr(path, s->home), path);
    assert_true(strlen(path) > 6);
    assert_string_not_equal(path + strlen(path) - 6, "XXXXXX");
    assert_int_equal(stat(path, &st), 0);
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(st.st_mode & (mode_t)~S_IFMT, S_IRWXU);
    dlp_mem_free(&path);

    /* mkdtemp failure */
    if (test_wrap_p()) {
        e = 5;
        test_wrap_push(mkdtemp, true, &e);
        assert_false(dlp_fs_mkdtemp(&path, &err));
        TEST_ASSERT_ERR(err, 5, "*");
    }
}

static void test_mkstemp(void **state)
{
    char *cache;
    int fd;
    errno_t e;
    GError *err = NULL;

    (void)state;

    /* permission failure */
    assert_true(dlp_fs_cache_dir(&cache, NULL));
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(cache, S_IRWXU | S_IWGRP), 0);
    assert_false(dlp_fs_mkstemp(&fd, &err));
    TEST_ASSERT_ERR(err, EBADFD, "*");
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    assert_int_equal(chmod(cache, S_IRWXU), 0);
    dlp_mem_free(&cache);

    /* success */
    assert_true(dlp_fs_mkstemp(&fd, &err));
    assert_null(err);
    assert_int_equal(close(fd), 0);

    if (test_wrap_p()) {
        e = EEXIST;
        test_wrap_push(mkstemp64, true, &e);
        assert_false(dlp_fs_mkstemp(&fd, &err));
        assert_int_equal(fd, -1);
        TEST_ASSERT_ERR(err, e, "*");

        e = EACCES;
        test_wrap_push(unlink, true, &e);
        assert_false(dlp_fs_mkstemp(&fd, &err));
        assert_int_equal(fd, -1);
        TEST_ASSERT_ERR(err, e, "*");
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_user_dir),
        cmocka_unit_test(test_user_path),
        cmocka_unit_test(test_check_stat),
        cmocka_unit_test(test_check_path),
        cmocka_unit_test(test_openat),
        cmocka_unit_test(test_open),
        cmocka_unit_test(test_close),
        cmocka_unit_test(test_seek),
        cmocka_unit_test(test_truncate),
        cmocka_unit_test(test_mkdir),
        cmocka_unit_test(test_rmdir),
        cmocka_unit_test(test_mkdtemp),
        cmocka_unit_test(test_mkstemp),
        cmocka_unit_test(test_walk_symlink),
        cmocka_unit_test(test_walk_cb_failure),
        cmocka_unit_test(test_walk_filelist),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include "dlp_archive.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"
#include "test.h"

struct state {
    char *home;
    char *cwd;
    char *portage;
    char orig_cwd[PATH_MAX];
};

static void setup(gpointer data, gconstpointer user_data)
{
    gsize len;
    gssize slen;
    char *content;
    const char *path;
    struct state *s = data;

    (void)user_data;

    g_assert_true(test_setup_home(&s->home));
    g_assert_true(getcwd(s->orig_cwd, sizeof(s->orig_cwd)) != NULL);
    g_assert_nonnull((s->cwd = g_strdup(g_getenv("DLP_TEST_HOME"))));
    g_assert_true(chdir(s->cwd) == 0);

    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "archive",
                               "portage.tar.xz.base64", NULL);
    g_assert_true(g_file_get_contents(path, &content, NULL, NULL));
    g_assert_true(g_base64_decode_inplace(content, &len));
    g_assert_false(dlp_overflow_add(len, 0, &slen));

    s->portage = g_build_filename("portage.tar.xz", NULL);
    g_assert_true(g_file_set_contents(s->portage, content, slen, NULL));
    dlp_mem_free(&content);
}

static void teardown(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(chdir(s->orig_cwd) == 0);
    g_assert_true(dlp_fs_rmdir(s->cwd, NULL));

    dlp_mem_free(&s->cwd);
    dlp_mem_free(&s->home);
    dlp_mem_free(&s->portage);
}

static void test_archive_double_free(gpointer data, gconstpointer user_data)
{
    bool rv;
    struct archive *a;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    rv = dlp_archive_read_new(&a, &err);
    g_assert_nonnull(a);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_archive_read_free(&a, &err);
    g_assert_null(a);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_archive_read_free(&a, &err);
    g_assert_null(a);
    g_assert_no_error(err);
    g_assert_true(rv);
}

static void test_archive_read_success(gpointer data, gconstpointer user_data)
{
    bool eof;
    bool rv;
    guint len;
    size_t strlen;
    char **tok;
    char *str;
    const char *path;
    struct archive *a;
    struct archive_entry *e;
    struct state *s = data;

    (void)user_data;

    g_assert_true(dlp_archive_read_new(&a, NULL));
    g_assert_true(dlp_archive_read_format_tar(a, NULL));
    g_assert_true(dlp_archive_read_filter_xz(a, NULL));
    g_assert_true(dlp_archive_read_open_filename(a, s->portage, 10, NULL));

    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));
    g_assert_false(eof);
    g_assert_true(dlp_archive_entry_path(e, &path, NULL));
    g_assert_cmpstr(path, ==, "portage/");
    g_assert_true(dlp_archive_entry_tokenized_path(e, &tok, &len, NULL));
    g_assert_cmpuint(len, ==, 2);
    g_strfreev(tok);

    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));
    g_assert_false(eof);
    g_assert_true(dlp_archive_entry_path(e, &path, NULL));
    g_assert_cmpstr(path, ==, "portage/Manifest");
    g_assert_true(dlp_archive_entry_tokenized_path(e, &tok, &len, NULL));
    g_assert_cmpuint(len, ==, 2);
    g_strfreev(tok);

    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));
    g_assert_false(eof);
    g_assert_true(dlp_archive_entry_path(e, &path, NULL));
    g_assert_cmpstr(path, ==, "portage/app-bar/");
    g_assert_true(dlp_archive_entry_tokenized_path(e, &tok, &len, NULL));
    g_assert_cmpuint(len, ==, 3);
    g_strfreev(tok);

    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));
    g_assert_false(eof);
    g_assert_true(dlp_archive_entry_path(e, &path, NULL));
    g_assert_cmpstr(path, ==, "portage/app-bar/def/");
    g_assert_true(dlp_archive_entry_tokenized_path(e, &tok, &len, NULL));
    g_assert_cmpuint(len, ==, 4);
    g_strfreev(tok);

    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));
    g_assert_false(eof);
    g_assert_true(dlp_archive_entry_path(e, &path, NULL));
    g_assert_cmpstr(path, ==, "portage/app-bar/def/Manifest");
    g_assert_true(dlp_archive_entry_tokenized_path(e, &tok, &len, NULL));
    g_assert_cmpuint(len, ==, 4);
    g_strfreev(tok);
    g_assert_true(dlp_archive_read_text(a, &str, &strlen, NULL));
    g_assert_nonnull(strstr(str, "bar.tar.gz"));
    g_assert_true(len != 0);
    dlp_mem_free(&str);

    while ((rv = dlp_archive_read_next_header(a, &e, &eof, NULL)) && !eof) {
    }
    g_assert_true(rv);
    g_assert_true(eof);

    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_new(gpointer data, gconstpointer user_data)
{
    struct archive *a;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    if (!test_wrap_p()) {
        return;
    }

    test_wrap_push(archive_read_new, true, NULL);
    g_assert_false(dlp_archive_read_new(&a, &err));
    g_assert_error(err, DLP_ERROR, ENOMEM);
    g_assert_null(a);
    g_clear_error(&err);
}

static void test_archive_read_fail_format_tar(gpointer data,
                                              gconstpointer user_data)
{
    struct archive *a;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    if (!test_wrap_p()) {
        return;
    }

    g_assert_true(dlp_archive_read_new(&a, NULL));
    test_wrap_push(archive_read_support_format_tar, true,
                   GINT_TO_POINTER(ARCHIVE_FATAL));
    g_assert_false(dlp_archive_read_format_tar(a, &err));
    g_assert_nonnull(err);
    g_clear_error(&err);
    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_filter_xz(gpointer data,
                                             gconstpointer user_data)
{
    struct archive *a;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    if (!test_wrap_p()) {
        return;
    }

    g_assert_true(dlp_archive_read_new(&a, NULL));
    test_wrap_push(archive_read_support_filter_xz, true,
                   GINT_TO_POINTER(ARCHIVE_FATAL));
    g_assert_false(dlp_archive_read_filter_xz(a, &err));
    g_assert_nonnull(err);
    g_clear_error(&err);
    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_open_filename(gpointer data,
                                                 gconstpointer user_data)
{
    struct archive *a;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_archive_read_new(&a, NULL));
    g_assert_false(dlp_archive_read_open_filename(a, "enoent", 1, &err));
    g_assert_nonnull(err);
    g_clear_error(&err);
    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_next_header(gpointer data,
                                               gconstpointer user_data)
{
    struct archive *a;
    struct archive_entry *e;
    GError *err = NULL;
    struct state *s = data;
    bool eof = false;

    (void)user_data;

    g_assert_true(dlp_archive_read_new(&a, NULL));
    g_assert_true(dlp_archive_read_format_tar(a, NULL));
    g_assert_true(dlp_archive_read_filter_xz(a, NULL));
    g_assert_true(dlp_archive_read_open_filename(a, s->portage, 1, NULL));

    while (dlp_archive_read_next_header(a, &e, &eof, NULL)) {
    }
    g_assert_true(eof);

    g_assert_false(dlp_archive_read_next_header(a, &e, &eof, &err));
    g_assert_nonnull(err);
    g_clear_error(&err);

    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_read_state(gpointer data,
                                              gconstpointer user_data)
{
    la_ssize_t size;
    struct archive *a;
    GError *err = NULL;
    char buf[DLP_BUFSIZ];
    char *str;
    struct state *s = data;

    (void)user_data;

    g_assert_true(dlp_archive_read_new(&a, NULL));
    g_assert_true(dlp_archive_read_format_tar(a, NULL));
    g_assert_true(dlp_archive_read_filter_xz(a, NULL));
    g_assert_true(dlp_archive_read_open_filename(a, s->portage, 1, NULL));

    g_assert_false(dlp_archive_read_data(a, buf, sizeof(buf), &size, &err));
    g_assert_nonnull(err);
    g_clear_error(&err);

    g_assert_false(dlp_archive_read_text(a, &str, NULL, &err));
    g_assert_nonnull(err);
    g_assert_null(str);
    g_clear_error(&err);

    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_read_size(gpointer data,
                                             gconstpointer user_data)
{
    bool eof;
    la_ssize_t size;
    struct archive *a;
    struct archive_entry *e;
    GError *err = NULL;
    char buf[DLP_BUFSIZ];
    struct state *s = data;

    (void)user_data;

    g_assert_true(dlp_archive_read_new(&a, NULL));
    g_assert_true(dlp_archive_read_format_tar(a, NULL));
    g_assert_true(dlp_archive_read_filter_xz(a, NULL));
    g_assert_true(dlp_archive_read_open_filename(a, s->portage, 1, NULL));
    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));

    g_assert_false(dlp_archive_read_data(a, buf, 0, &size, &err));
    g_assert_error(err, DLP_ERROR, ERANGE);
    g_clear_error(&err);

    if (SIZE_MAX > SSIZE_MAX) {
        size_t rdsize = (size_t)SSIZE_MAX + 1;
        g_assert_false(dlp_archive_read_data(a, buf, rdsize, &size, &err));
        g_assert_error(err, DLP_ERROR, ERANGE);
        g_clear_error(&err);
    }

    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_path(gpointer data, gconstpointer user_data)
{
    bool eof;
    guint ntok;
    char **tok;
    const char *path;
    struct archive *a;
    struct archive_entry *e;
    GError *err = NULL;
    struct state *s = data;

    (void)user_data;

    if (!test_wrap_p()) {
        return;
    }

    g_assert_true(dlp_archive_read_new(&a, NULL));
    g_assert_true(dlp_archive_read_format_tar(a, NULL));
    g_assert_true(dlp_archive_read_filter_xz(a, NULL));
    g_assert_true(dlp_archive_read_open_filename(a, s->portage, 1, NULL));
    g_assert_true(dlp_archive_read_next_header(a, &e, &eof, NULL));

    test_wrap_push(archive_entry_pathname, true, NULL);
    g_assert_false(dlp_archive_entry_path(e, &path, &err));
    g_assert_error(err, DLP_ERROR, DLP_ARCHIVE_ERROR_FAILED);
    g_clear_error(&err);

    test_wrap_push(archive_entry_pathname, true, NULL);
    g_assert_false(dlp_archive_entry_tokenized_path(e, &tok, &ntok, &err));
    g_assert_error(err, DLP_ERROR, DLP_ARCHIVE_ERROR_FAILED);
    g_clear_error(&err);

    g_assert_true(dlp_archive_read_free(&a, NULL));
}

static void test_archive_read_fail_free(gpointer data, gconstpointer user_data)
{
    struct archive *a;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    if (!test_wrap_p()) {
        return;
    }

    g_assert_true(dlp_archive_read_new(&a, NULL));
    test_wrap_push(archive_read_free, true, GINT_TO_POINTER(ARCHIVE_FATAL));
    g_assert_false(dlp_archive_read_free(&a, &err));
    g_assert_error(err, DLP_ERROR, DLP_ARCHIVE_ERROR_FAILED);
    g_clear_error(&err);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/archive/double-free", sizeof(struct state), NULL, setup,
                      test_archive_double_free, teardown);
    g_test_add_vtable("/archive/read/success", sizeof(struct state), NULL,
                      setup, test_archive_read_success, teardown);
    g_test_add_vtable("/archive/read/fail/new", sizeof(struct state), NULL,
                      setup, test_archive_read_fail_new, teardown);
    g_test_add_vtable("/archive/read/fail/format-tar", sizeof(struct state),
                      NULL, setup, test_archive_read_fail_format_tar, teardown);
    g_test_add_vtable("/archive/read/fail/filter-xz", sizeof(struct state),
                      NULL, setup, test_archive_read_fail_filter_xz, teardown);
    g_test_add_vtable("/archive/read/fail/open-filename", sizeof(struct state),
                      NULL, setup, test_archive_read_fail_open_filename,
                      teardown);
    g_test_add_vtable("/archive/read/fail/next_header", sizeof(struct state),
                      NULL, setup, test_archive_read_fail_next_header,
                      teardown);
    g_test_add_vtable("/archive/read/fail/read-state", sizeof(struct state),
                      NULL, setup, test_archive_read_fail_read_state, teardown);
    g_test_add_vtable("/archive/read/fail/read-size", sizeof(struct state),
                      NULL, setup, test_archive_read_fail_read_size, teardown);
    g_test_add_vtable("/archive/read/fail/path", sizeof(struct state), NULL,
                      setup, test_archive_read_fail_path, teardown);
    g_test_add_vtable("/archive/read/fail/free", sizeof(struct state), NULL,
                      setup, test_archive_read_fail_free, teardown);

    return g_test_run();
}

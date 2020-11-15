/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include <fcntl.h>

#include "dlp_apt.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"
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

static void prepare_fd(int fd, const char *buf)
{
    ssize_t rv;
    size_t nbytes;

    if (fd < 0 || buf == NULL) {
        g_error("fd/buf");
    }

    if (!dlp_fs_seek(fd, 0, SEEK_SET, NULL) || !dlp_fs_truncate(fd, 0, NULL)) {
        g_error("seek/truncate");
    }

    /*
     * POSIX.1-2017 specifies the result is undefined if nbytes is 0 and the fd
     * doesn't refer to a regular file.  The result is implementation-defined
     * if nbytes is larger than SSIZE_MAX.
     */
    nbytes = strlen(buf);
    if (nbytes == 0 || nbytes > SSIZE_MAX) {
        g_error("strlen");
    }

    while ((errno = 0) == 0 && nbytes > 0 &&
           (rv = write(fd, buf, nbytes)) < (ssize_t)nbytes) {
        if (rv > 0) {
            if (dlp_overflow_sub(nbytes, rv, &nbytes)) {
                g_error("overflow");
            }
            buf += rv;
        } else if (rv == -1 && errno != EINTR) {
            g_error("write");
        }
    }

    if (!dlp_fs_seek(fd, 0, SEEK_SET, NULL)) {
        g_error("seek");
    }
}

static void test_apt_ht_free(gpointer data, gconstpointer user_data)
{
    GHashTable *ht = NULL;

    (void)data;
    (void)user_data;

    dlp_apt_ht_free(NULL);
    dlp_apt_ht_free(&ht);
    g_assert_null(ht);

    ht = g_hash_table_new(g_str_hash, g_str_equal);
    g_assert_nonnull(ht);

    dlp_apt_ht_free(&ht);
    g_assert_null(ht);
}

static void test_apt_list_free(gpointer data, gconstpointer user_data)
{
    GHashTable *ht = NULL;
    GList *list = NULL;

    (void)data;
    (void)user_data;

    dlp_apt_list_free(NULL);
    dlp_apt_list_free(&list);
    g_assert_null(list);

    ht = g_hash_table_new(g_str_hash, g_str_equal);
    g_assert_nonnull(ht);
    g_hash_table_insert(ht, "foo", "bar");

    list = g_list_prepend(list, ht);
    g_assert_nonnull(list);

    dlp_apt_list_free(&list);
    g_assert_null(list);
}

static void test_apt_read_release_misc(gpointer data, gconstpointer user_data)
{
    int fd;
    GHashTable *ht;
    GError *err = NULL;
    bool rv;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty file.
     */
    rv = dlp_apt_read_release(fd, &ht, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_assert_null(ht);
    g_clear_error(&err);

    /*
     * Success.
     */
    prepare_fd(fd, "Suite: foo\nCodename: bar\n");
    rv = dlp_apt_read_release(fd, &ht, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpstr(g_hash_table_lookup(ht, "Suite"), ==, "foo");
    g_assert_cmpstr(g_hash_table_lookup(ht, "Codename"), ==, "bar");
    dlp_apt_ht_free(&ht);

    /*
     * Invalid space separated word.
     */
    prepare_fd(fd, "Suite: foo bar\nCodename: baz\n");
    rv = dlp_apt_read_release(fd, &ht, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Invalid EOF.
     */
    prepare_fd(fd, "Suite: foo\nCodename:");
    rv = dlp_apt_read_release(fd, &ht, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_read_release_full(gpointer data, gconstpointer user_data)
{
    int fd;
    const char *path;
    GHashTable *ht;
    GError *err = NULL;
    bool rv;

    (void)data;
    (void)user_data;

    /*
     * Multiple release elements.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_multi", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_read_release(fd, &ht, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_DUPLICATE);
    g_assert_false(rv);
    g_clear_error(&err);
    g_assert_true(dlp_fs_close(&fd, NULL));
    g_assert_null(ht);

    /*
     * Single release element.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_single", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_read_release(fd, &ht, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_close(&fd, NULL));
    g_assert_nonnull(ht);
    g_assert_cmpstr(g_hash_table_lookup(ht, "Suite"), ==, "stable");
    g_assert_cmpstr(g_hash_table_lookup(ht, "Codename"), ==, "buster");
    dlp_apt_ht_free(&ht);
}

static void test_apt_read_sources_package(gpointer data,
                                          gconstpointer user_data)
{
    int fd;
    GList *list;
    GError *err = NULL;
    bool rv;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Missing name.
     */
    prepare_fd(fd, "Package:\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Success.
     */
    prepare_fd(fd, "Package: foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);

    /*
     * Success with missing space.
     */
    prepare_fd(fd, "Package:foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);

    /*
     * Success with numeric name.
     */
    prepare_fd(fd, "Package: 123\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "123");
    dlp_apt_list_free(&list);

    prepare_fd(fd, "Package: 1.23\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "1.23");
    dlp_apt_list_free(&list);

    prepare_fd(fd, "Package: 0x123\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "0x123");
    dlp_apt_list_free(&list);

    /*
     * Too short name.
     */
    prepare_fd(fd, "Package: x\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Missing newline.
     */
    prepare_fd(fd, "Package: foo");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Missing separator.
     */
    prepare_fd(fd, "Package foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * EOF before separator.
     */
    prepare_fd(fd, "Package: foo\nBinary");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Duplicate.
     */
    prepare_fd(fd, "Package: foo\nBinary: bar\nPackage: baz\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_DUPLICATE);
    g_assert_false(rv);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_read_sources_ignore(gpointer data, gconstpointer user_data)
{
    int fd;
    GError *err = NULL;
    GList *list = NULL;
    bool rv;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty value.
     */
    prepare_fd(fd, "Autobuild:\nPackage: foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Multiple ignores with empty value(s).
     */
    prepare_fd(fd, "Autobuild:\nTestsuite-Triggers:\nPackage: foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild:\nTestsuite-Triggers: abc\nPackage: foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild: abc\nTestsuite-Triggers:\nPackage: foo\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with empty value.
     */
    prepare_fd(fd, "Package: foo\nAutobuild:\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with a value.
     */
    prepare_fd(fd, "Package: foo\nAutobuild:bar\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with empty value and no newline.
     */
    prepare_fd(fd, "Package: foo\nAutobuild:");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with a value and no newline.
     */
    prepare_fd(fd, "Package: foo\nAutobuild: bar");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "foo");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Multiline starting on the same line.
     */
    prepare_fd(fd, "Autobuild:foo\nbar\n baz\n   qux\nPackage: abcd\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "abcd");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild:foo\nbar\n baz\n   qux\n"
                   "Testsuite-Triggers: x\n    y\n"
                   "Package: abcd\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "abcd");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    /*
     * Multiline starting on a new line.
     */
    prepare_fd(fd, "Autobuild:\nfoo\nbar\n baz\n   qux\nPackage: abcd\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "abcd");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild:\nfoo\nbar\n baz\n   qux\n"
                   "Testsuite-Triggers: x\n    y\n"
                   "Package: abcd\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_cmpstr(g_hash_table_lookup(list->data, "Package"), ==, "abcd");
    dlp_apt_list_free(&list);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_read_sources_misc(gpointer data, gconstpointer user_data)
{
    int fd;
    GError *err = NULL;
    GList *list = NULL;
    bool rv;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty file.
     */
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_clear_error(&err);

    /*
     * Unknown symbol.
     */
    prepare_fd(fd, "Package: foo\nBar: baz\n");
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_read_sources_full(gpointer data, gconstpointer user_data)
{
    int fd;
    const char *path;
    GList *list;
    GHashTable *ht;
    GError *err = NULL;
    bool rv;

    (void)data;
    (void)user_data;

    /*
     * Single source element.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_single", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_close(&fd, NULL));

    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(ht = g_list_nth_data(list, 0));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "libdisasm");
    dlp_apt_list_free(&list);

    /*
     * Multiple source elements.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_multi", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_read_sources(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_close(&fd, NULL));

    g_assert_cmpuint(g_list_length(list), ==, 6);
    g_assert_nonnull(ht = g_list_nth_data(list, 0));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "util-linux");
    g_assert_nonnull(ht = g_list_nth_data(list, 1));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "libdisasm");
    g_assert_nonnull(ht = g_list_nth_data(list, 2));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "elfutils");
    g_assert_nonnull(ht = g_list_nth_data(list, 3));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "binutils");
    g_assert_nonnull(ht = g_list_nth_data(list, 4));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "base-files");
    g_assert_nonnull(ht = g_list_nth_data(list, 5));
    g_assert_cmpstr(g_hash_table_lookup(ht, "Package"), ==, "aptitude");
    dlp_apt_list_free(&list);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/apt/ht/free", sizeof(struct state), NULL, setup,
                      test_apt_ht_free, teardown);
    g_test_add_vtable("/apt/list/free", sizeof(struct state), NULL, setup,
                      test_apt_list_free, teardown);
    g_test_add_vtable("/apt/read/release/misc", sizeof(struct state), NULL,
                      setup, test_apt_read_release_misc, teardown);
    g_test_add_vtable("/apt/read/release/full", sizeof(struct state), NULL,
                      setup, test_apt_read_release_full, teardown);
    g_test_add_vtable("/apt/read/sources/package", sizeof(struct state), NULL,
                      setup, test_apt_read_sources_package, teardown);
    g_test_add_vtable("/apt/read/sources/ignore", sizeof(struct state), NULL,
                      setup, test_apt_read_sources_ignore, teardown);
    g_test_add_vtable("/apt/read/sources/misc", sizeof(struct state), NULL,
                      setup, test_apt_read_sources_misc, teardown);
    g_test_add_vtable("/apt/read/sources/full", sizeof(struct state), NULL,
                      setup, test_apt_read_sources_full, teardown);

    return g_test_run();
}

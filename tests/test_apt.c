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

static void test_apt_release_free(gpointer data, gconstpointer user_data)
{
    struct dlp_apt_release *r;

    (void)data;
    (void)user_data;

    dlp_apt_release_free(NULL);

    r = dlp_mem_alloc(sizeof(*r));
    dlp_apt_release_free(&r);
    g_assert_null(r);

    dlp_apt_release_free(&r);
    g_assert_null(r);
}

static void test_apt_release_read_files(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    struct dlp_apt_file *f;
    struct dlp_apt_release *r;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Success.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpstr(r->suite, ==, "foo");
    g_assert_cmpstr(r->codename, ==, "bar");
    g_assert_cmpuint(g_list_length(r->md5sum), ==, 1);
    g_assert_nonnull(f = g_list_nth_data(r->md5sum, 0));
    g_assert_cmpstr(f->digest, ==, "68b329da9893e34099c7d8ad5cb9c940");
    g_assert_cmpint(f->size, ==, 0);
    g_assert_cmpstr(f->name, ==, "file1");
    g_assert_cmpuint(g_list_length(r->sha256), ==, 1);
    g_assert_nonnull(f = g_list_nth_data(r->sha256, 0));
    g_assert_cmpstr(f->digest, ==,
                    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                    "ca546b");
    g_assert_cmpint(f->size, ==, 987);
    g_assert_cmpstr(f->name, ==, "file2");
    dlp_apt_release_free(&r);

    /*
     * No newline before value.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 321 file\n"
                   "SHA256: "
                   "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805dac"
                   "a546b 123 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum: 68b329da9893e34099c7d8ad5cb9c940 321 file\n"
                   " 68b329da9893e34099c7d8ad5cb9c941 123 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Too short digest.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c 123 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * String size.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b SIZE file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Invalid filename.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 \033[31mfoo\033[0m\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Missing final newline.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Empty value.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_release_read_misc(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    struct dlp_apt_file *f;
    struct dlp_apt_release *r;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty file.
     */
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Success.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 321 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 123 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpstr(r->suite, ==, "foo");
    g_assert_cmpstr(r->codename, ==, "bar");
    g_assert_cmpuint(g_list_length(r->md5sum), ==, 1);
    g_assert_nonnull(f = g_list_nth_data(r->md5sum, 0));
    g_assert_cmpstr(f->digest, ==, "68b329da9893e34099c7d8ad5cb9c940");
    g_assert_cmpint(f->size, ==, 321);
    g_assert_cmpstr(f->name, ==, "file1");
    g_assert_cmpuint(g_list_length(r->sha256), ==, 1);
    g_assert_nonnull(f = g_list_nth_data(r->sha256, 0));
    g_assert_cmpstr(f->digest, ==,
                    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                    "ca546b");
    g_assert_cmpint(f->size, ==, 123);
    g_assert_cmpstr(f->name, ==, "file2");
    dlp_apt_release_free(&r);

    /*
     * Invalid space separated word.
     */
    prepare_fd(fd, "Suite: foo bar\n"
                   "Codename: baz\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 321 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 123 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Invalid EOF.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 321 file\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 123 file2\n"
                   "Codename:");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_release_read_full(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    const char *path;
    struct dlp_apt_file *f;
    struct dlp_apt_release *r;
    GList *elt;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    /*
     * Multiple release elements.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_multi", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_clear_error(&err);
    g_assert_true(dlp_fs_close(&fd, NULL));
    g_assert_null(r);

    /*
     * Single release element.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "release_single", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_close(&fd, NULL));
    g_assert_nonnull(r);
    g_assert_cmpstr(r->suite, ==, "stable");
    g_assert_cmpstr(r->codename, ==, "buster");
    g_assert_cmpuint(g_list_length(r->md5sum), ==, 628);
    g_assert_nonnull(f = g_list_nth_data(r->md5sum, 0));
    g_assert_cmpstr(f->digest, ==, "934b3f80ead8a7045d52b5c812fc6b4b");
    g_assert_cmpuint(g_list_length(r->sha256), ==, 628);
    g_assert_nonnull(f = g_list_nth_data(r->sha256, 0));
    g_assert_cmpstr(f->digest, ==,
                    "3c5eb439b193bc2281b88cdf178ceb943cd4b6097afee6ce2b51ff1550"
                    "656ee0");

    for (elt = r->md5sum; elt != NULL; elt = elt->next) {
        f = elt->data;
        g_assert_cmpuint(strlen(f->digest), ==, 32);
    }

    for (elt = r->sha256; elt != NULL; elt = elt->next) {
        f = elt->data;
        g_assert_cmpuint(strlen(f->digest), ==, 64);
    }

    dlp_apt_release_free(&r);
}

static void test_apt_sources_free(gpointer data, gconstpointer user_data)
{
    GList *l;

    (void)data;
    (void)user_data;

    dlp_apt_sources_free(NULL);

    l = g_list_prepend(NULL, dlp_mem_alloc(sizeof(struct dlp_apt_source)));
    l = g_list_prepend(l, dlp_mem_alloc(sizeof(struct dlp_apt_source)));

    dlp_apt_sources_free(&l);
    g_assert_null(l);

    dlp_apt_sources_free(&l);
    g_assert_null(l);
}

static void test_apt_sources_read_package(gpointer data,
                                          gconstpointer user_data)
{
    int fd;
    bool rv;
    GList *list;
    struct dlp_apt_source *s;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Missing name.
     */
    prepare_fd(fd, "Package:\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Missing.
     */
    prepare_fd(fd, "Binary: bar\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n"
                   "Package: baz\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    prepare_fd(fd, "Package: foo\n"
                   "Binary: bar\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n"
                   "Binary: baz\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Success.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    dlp_apt_sources_free(&list);

    /*
     * Success with missing space.
     */
    prepare_fd(fd, "Package:foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    dlp_apt_sources_free(&list);

    /*
     * Success with numeric name.
     */
    prepare_fd(fd, "Package: 123\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "123");
    dlp_apt_sources_free(&list);

    prepare_fd(fd, "Package: 1.23\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "1.23");
    dlp_apt_sources_free(&list);

    prepare_fd(fd, "Package: 0x123\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "0x123");
    dlp_apt_sources_free(&list);

    /*
     * Too short name.
     */
    prepare_fd(fd, "Package: x\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Missing newline.
     */
    prepare_fd(fd, "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Package: foo");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Missing separator.
     */
    prepare_fd(fd, "Package foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * EOF before separator.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n"
                   "Binary");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Duplicate.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Binary: bar\n"
                   "Package: baz\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_DUPLICATE);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_sources_read_ignore(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    GList *list;
    GTokenType tok;
    struct dlp_apt_source *s;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty value.
     */
    prepare_fd(fd, "Autobuild:\n"
                   "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Multiple ignores with empty value(s).
     */
    prepare_fd(fd, "Autobuild:\n"
                   "Testsuite-Triggers:\n"
                   "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild:\n"
                   "Testsuite-Triggers: abc\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Package: foo\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild: abc\n"
                   "Testsuite-Triggers:\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Package: foo\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with empty value.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Autobuild:\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with a value.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Autobuild:bar\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with empty value and no newline.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Autobuild:");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Last symbol with a value and no newline.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Autobuild: bar");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Multiline starting on the same line.
     */
    prepare_fd(fd, "Autobuild:foo\n"
                   "bar\n"
                   " baz\n"
                   "    qux\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Package: abcd\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "abcd");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild:foo\n"
                   "bar\n"
                   " baz\n"
                   "   qux\n"
                   "Testsuite-Triggers: x\n"
                   "    y\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Package: abcd\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "abcd");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    /*
     * Multiline starting on a new line.
     */
    prepare_fd(fd, "Autobuild:\n"
                   "foo\n"
                   "bar\n"
                   " baz\n"
                   "   qux\n"
                   "Package: abcd\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "abcd");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    prepare_fd(fd, "Autobuild:\nfoo\nbar\n baz\n   qux\n"
                   "Testsuite-Triggers: x\n    y\n"
                   "Package: abcd\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "abcd");
    g_assert_cmpuint(g_list_length(s->files), ==, 1);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 1);
    dlp_apt_sources_free(&list);
    g_clear_error(&err);

    if (test_wrap_p()) {
        /*
         * Error token.
         */
        tok = G_TOKEN_ERROR;
        test_wrap_push(g_scanner_peek_next_token, true, &tok);
        test_wrap_push(g_scanner_peek_next_token, false, NULL);
        prepare_fd(fd, "Package: foo\n"
                       "Autobuild: no\n"
                       "Files:\n"
                       " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                       "Checksums-Sha256:\n"
                       " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f98"
                       "05daca546b 456 f2\n");
        rv = dlp_apt_sources_read(fd, &list, &err);
        g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
        g_assert_false(rv);
        g_assert_null(list);
        g_clear_error(&err);
    }

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_sources_read_misc(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    GList *list;
    struct dlp_apt_source *s;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Empty file.
     */
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_REQUIRED);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Unknown symbol.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n"
                   "Bar: baz\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(list);
    g_clear_error(&err);

    /*
     * Last element separator.
     */
    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "foo");
    g_clear_error(&err);
    dlp_apt_sources_free(&list);

    prepare_fd(fd, "Package: foo\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n"
                   "Package: bar\n"
                   "Files:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 123 f1\n"
                   "Checksums-Sha256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 456 f2\n\n");
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_cmpuint(g_list_length(list), ==, 2);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "bar");
    g_assert_nonnull(s = g_list_nth_data(list, 1));
    g_assert_cmpstr(s->package, ==, "foo");
    g_clear_error(&err);
    dlp_apt_sources_free(&list);

    g_assert_true(dlp_fs_close(&fd, NULL));
}

static void test_apt_sources_read_full(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    const char *path;
    GList *list;
    struct dlp_apt_file *f;
    struct dlp_apt_source *s;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    /*
     * Single source element.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_single", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_close(&fd, NULL));

    g_assert_cmpuint(g_list_length(list), ==, 1);
    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpuint(g_list_length(s->files), ==, 3);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 3);
    g_assert_cmpstr(s->package, ==, "libdisasm");
    dlp_apt_sources_free(&list);

    /*
     * Multiple source elements.
     */
    path = g_test_get_filename(G_TEST_DIST, "tests", "data", "apt",
                               "sources_multi", NULL);
    g_assert_true(dlp_fs_open(path, O_RDONLY, 0, &fd, NULL));
    rv = dlp_apt_sources_read(fd, &list, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_close(&fd, NULL));

    g_assert_cmpuint(g_list_length(list), ==, 6);

    g_assert_nonnull(s = g_list_nth_data(list, 0));
    g_assert_cmpstr(s->package, ==, "util-linux");
    g_assert_cmpuint(g_list_length(s->files), ==, 3);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 3);

    g_assert_nonnull(s = g_list_nth_data(list, 1));
    g_assert_cmpstr(s->package, ==, "libdisasm");
    g_assert_cmpuint(g_list_length(s->files), ==, 3);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 3);

    g_assert_nonnull(s = g_list_nth_data(list, 2));
    g_assert_cmpstr(s->package, ==, "elfutils");
    g_assert_cmpuint(g_list_length(s->files), ==, 4);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 4);

    g_assert_nonnull(s = g_list_nth_data(list, 3));
    g_assert_cmpstr(s->package, ==, "binutils");
    g_assert_cmpuint(g_list_length(s->files), ==, 3);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 3);

    g_assert_nonnull(s = g_list_nth_data(list, 4));
    g_assert_cmpstr(s->package, ==, "base-files");
    g_assert_cmpuint(g_list_length(s->files), ==, 2);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 2);

    g_assert_nonnull(s = g_list_nth_data(list, 5));
    g_assert_cmpstr(s->package, ==, "aptitude");
    g_assert_cmpuint(g_list_length(s->files), ==, 3);
    g_assert_nonnull(f = g_list_nth_data(s->files, 0));
    g_assert_cmpstr(f->name, ==, "aptitude_0.8.11-7.debian.tar.xz");
    g_assert_cmpstr(f->digest, ==, "11fa60f97e5e88e76e875ef4b4fcbe95");
    g_assert_cmpuint(f->size, ==, 57412);
    g_assert_nonnull(f = g_list_nth_data(s->files, 1));
    g_assert_cmpstr(f->name, ==, "aptitude_0.8.11.orig.tar.xz");
    g_assert_cmpstr(f->digest, ==, "369e2bded48219bdf73462810c315009");
    g_assert_cmpuint(f->size, ==, 4724388);
    g_assert_nonnull(f = g_list_nth_data(s->files, 2));
    g_assert_cmpstr(f->name, ==, "aptitude_0.8.11-7.dsc");
    g_assert_cmpstr(f->digest, ==, "2fb598437c270a3ca32ad372e4b4424d");
    g_assert_cmpuint(f->size, ==, 3007);
    g_assert_cmpuint(g_list_length(s->checksums_sha256), ==, 3);
    g_assert_nonnull(f = g_list_nth_data(s->checksums_sha256, 0));
    g_assert_cmpstr(f->name, ==, "aptitude_0.8.11-7.debian.tar.xz");
    g_assert_cmpstr(f->digest, ==,
                    "efa17287e955836b3047bf64aee3ab0e726c42062eacfc6257d0968032"
                    "eef64c");
    g_assert_cmpuint(f->size, ==, 57412);
    g_assert_nonnull(f = g_list_nth_data(s->checksums_sha256, 1));
    g_assert_cmpstr(f->name, ==, "aptitude_0.8.11.orig.tar.xz");
    g_assert_cmpstr(f->digest, ==,
                    "a3aed83a14765336c8b4ca8f8b6fbcc5dadda0d98c5a1d3e643183f6ef"
                    "8fc73e");
    g_assert_cmpuint(f->size, ==, 4724388);
    g_assert_nonnull(f = g_list_nth_data(s->checksums_sha256, 2));
    g_assert_cmpstr(f->name, ==, "aptitude_0.8.11-7.dsc");
    g_assert_cmpstr(f->digest, ==,
                    "b0a39c712ff7284cb2119bee8179836a0c93bee5bf0f87f2fefe2f12ee"
                    "95b987");
    g_assert_cmpuint(f->size, ==, 3007);

    dlp_apt_sources_free(&list);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/apt/release/free", sizeof(struct state), NULL, setup,
                      test_apt_release_free, teardown);
    g_test_add_vtable("/apt/release/read/files", sizeof(struct state), NULL,
                      setup, test_apt_release_read_files, teardown);
    g_test_add_vtable("/apt/release/read/misc", sizeof(struct state), NULL,
                      setup, test_apt_release_read_misc, teardown);
    g_test_add_vtable("/apt/release/read/full", sizeof(struct state), NULL,
                      setup, test_apt_release_read_full, teardown);
    g_test_add_vtable("/apt/sources/free", sizeof(struct state), NULL, setup,
                      test_apt_sources_free, teardown);
    g_test_add_vtable("/apt/sources/read/package", sizeof(struct state), NULL,
                      setup, test_apt_sources_read_package, teardown);
    g_test_add_vtable("/apt/sources/read/ignore", sizeof(struct state), NULL,
                      setup, test_apt_sources_read_ignore, teardown);
    g_test_add_vtable("/apt/sources/read/misc", sizeof(struct state), NULL,
                      setup, test_apt_sources_read_misc, teardown);
    g_test_add_vtable("/apt/sources/read/full", sizeof(struct state), NULL,
                      setup, test_apt_sources_read_full, teardown);

    return g_test_run();
}

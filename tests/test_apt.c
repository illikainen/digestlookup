/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>

#include <fcntl.h>

#include <microhttpd.h>

#include "dlp_apt.h"
#include "dlp_backend.h"
#include "dlp_curl.h"
#include "dlp_digest.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_gpg.h"
#include "dlp_mem.h"
#include "dlp_mhd.h"
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

static void test_apt_ctor(gpointer data, gconstpointer user_data)
{
    struct dlp_backend *be;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_backend_find("apt", &be, NULL));
    g_assert_nonnull(be);
    g_assert_cmpstr(be->name, ==, "apt");
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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

static void test_apt_release_read_date(gpointer data, gconstpointer user_data)
{
    int fd;
    bool rv;
    struct dlp_apt_release *r;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    g_assert_true(dlp_fs_mkstemp(&fd, NULL));

    /*
     * Success with +0000 %z timezone and 0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 0);
    dlp_apt_release_free(&r);

    /*
     * Success with +0000 %z timezone and non-0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 2020 00:00:00 +0000\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 1577836800);
    dlp_apt_release_free(&r);

    /*
     * Success with Z %z timezone and 0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 1970 00:00:00 Z\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 0);
    dlp_apt_release_free(&r);

    /*
     * Success with Z %z timezone and non-0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 2020 00:00:00 Z\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 1577836800);
    dlp_apt_release_free(&r);

    /*
     * Success with UTC %Z timezone and 0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 1970 00:00:00 UTC\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 0);
    dlp_apt_release_free(&r);

    /*
     * Success with UTC %Z timezone and non-0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 2020 00:00:00 UTC\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 1577836800);
    dlp_apt_release_free(&r);

    /*
     * Success with GMT %Z timezone and 0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 1970 00:00:00 GMT\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 0);
    dlp_apt_release_free(&r);

    /*
     * Success with GMT %Z timezone and non-0 time.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Thu, 01 Jan 2020 00:00:00 GMT\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(r);
    g_assert_cmpint(r->date, ==, 1577836800);
    dlp_apt_release_free(&r);

    /*
     * Invalid string.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: _Thu, 01 Jan 1970 00:00:00 +0000\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Invalid date.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "Date: Foo, 01 Jan 1970 00:00:00 +0000\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    /*
     * Missing newline.
     */
    prepare_fd(fd, "Suite: foo\n"
                   "Codename: bar\n"
                   "MD5Sum:\n"
                   " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                   "SHA256:\n"
                   " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805da"
                   "ca546b 987 file2\n"
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000");
    rv = dlp_apt_release_read(fd, &r, &err);
    g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
    g_assert_false(rv);
    g_assert_null(r);
    g_clear_error(&err);

    if (test_wrap_p()) {
        /*
         * newlocale() failure with %z
         */
        prepare_fd(fd, "Suite: foo\n"
                       "Codename: bar\n"
                       "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
                       "MD5Sum:\n"
                       " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                       "SHA256:\n"
                       " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f98"
                       "05da"
                       "ca546b 987 file2\n");
        test_wrap_push(newlocale, true, NULL);
        rv = dlp_apt_release_read(fd, &r, &err);
        g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
        g_assert_false(rv);
        g_assert_null(r);
        g_clear_error(&err);

        /*
         * newlocale() failure with %Z
         */
        prepare_fd(fd, "Suite: foo\n"
                       "Codename: bar\n"
                       "Date: Thu, 01 Jan 1970 00:00:00 UTC\n"
                       "MD5Sum:\n"
                       " 68b329da9893e34099c7d8ad5cb9c940 0 file1\n"
                       "SHA256:\n"
                       " 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f98"
                       "05da"
                       "ca546b 987 file2\n");
        test_wrap_push(newlocale, true, NULL);
        rv = dlp_apt_release_read(fd, &r, &err);
        g_assert_error(err, DLP_ERROR, DLP_APT_ERROR_LEX);
        g_assert_false(rv);
        g_assert_null(r);
        g_clear_error(&err);
    }
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
                   "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
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
    g_assert_no_error(err);
    g_assert_true(rv);
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

static bool test_apt_lookup_walk(int dfd, const char *name, const char *path,
                                 const struct stat *s, void *data,
                                 GError **error)
{
    (void)dfd;
    (void)path;
    (void)error;

    if ((s->st_mode & DLP_FS_TYPE) == DLP_FS_REG) {
        g_ptr_array_add(data, g_strdup(name));
    }
    return true;
}

static void test_apt_lookup_success(gpointer data, gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *str = NULL;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_no_error(err);
            g_assert_true(rv);
        }
    }

    rv = dlp_table_format(tbl, &str);
    g_assert_true(rv);
    g_assert_nonnull(strstr(str, "576c7288395653bf3082e4a08db5215509eeaeae71b2d"
                                 "e9099590a1224535981"));
    g_assert_nonnull(strstr(str, "de3e578aa582af6e1d7729f39626892fb72dc6573658a"
                                 "221e0905f42a65433da"));
    g_assert_nonnull(strstr(str, "787deebb9026378ed6906a42f18bb83b85e9e3e469178"
                                 "e68d4d83522d11c4d87"));
    g_assert_nonnull(strstr(str, "2c26b46b68ffc68ff99b453c1d30413413422d706483b"
                                 "fa0f98a5e886266e7ae"));

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_assert_cmpuint(paths->len, ==, 3);

    dlp_mem_free(&str);
    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_success_cache(gpointer data,
                                          gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_cfg_repo *repo;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *str = NULL;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "cache = 1234567890\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_no_error(err);
            g_assert_true(rv);
        }
    }

    dlp_table_free(&tbl);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_no_error(err);
            g_assert_true(rv);
        }
    }

    rv = dlp_table_format(tbl, &str);
    g_assert_true(rv);
    g_assert_nonnull(strstr(str, "576c7288395653bf3082e4a08db5215509eeaeae71b2d"
                                 "e9099590a1224535981"));
    g_assert_nonnull(strstr(str, "de3e578aa582af6e1d7729f39626892fb72dc6573658a"
                                 "221e0905f42a65433da"));
    g_assert_nonnull(strstr(str, "787deebb9026378ed6906a42f18bb83b85e9e3e469178"
                                 "e68d4d83522d11c4d87"));
    g_assert_nonnull(strstr(str, "2c26b46b68ffc68ff99b453c1d30413413422d706483b"
                                 "fa0f98a5e886266e7ae"));

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_assert_cmpuint(paths->len, ==, 3);

    dlp_mem_free(&str);
    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_success_stale(gpointer data,
                                          gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *str = NULL;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "cache = 1\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", "Release", NULL);
    g_assert_true(rv);
    rv = g_file_set_contents(path, "foo", -1, NULL);
    g_assert_true(rv);
    dlp_mem_free(&path);

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", "sources",
                          "main_source_Sources_xz", NULL);
    g_assert_true(rv);
    rv = g_file_set_contents(path, "foo", -1, NULL);
    g_assert_true(rv);
    dlp_mem_free(&path);

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", "sources",
                          "contrib_source_Sources_xz", NULL);
    g_assert_true(rv);
    rv = g_file_set_contents(path, "foo", -1, NULL);
    g_assert_true(rv);
    dlp_mem_free(&path);

    sleep(2);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_no_error(err);
            g_assert_true(rv);
        }
    }

    rv = dlp_table_format(tbl, &str);
    g_assert_true(rv);
    g_assert_nonnull(strstr(str, "576c7288395653bf3082e4a08db5215509eeaeae71b2d"
                                 "e9099590a1224535981"));
    g_assert_nonnull(strstr(str, "de3e578aa582af6e1d7729f39626892fb72dc6573658a"
                                 "221e0905f42a65433da"));
    g_assert_nonnull(strstr(str, "787deebb9026378ed6906a42f18bb83b85e9e3e469178"
                                 "e68d4d83522d11c4d87"));
    g_assert_nonnull(strstr(str, "2c26b46b68ffc68ff99b453c1d30413413422d706483b"
                                 "fa0f98a5e886266e7ae"));

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_assert_cmpuint(paths->len, ==, 3);

    dlp_mem_free(&str);
    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_release_url(gpointer data,
                                            gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/bad-url", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, CURLE_GOT_NOTHING);
            g_assert_false(rv);
        }
    }

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_assert_cmpuint(paths->len, ==, 0);

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_sources_url(gpointer data,
                                            gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/bad-url",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, CURLE_GOT_NOTHING);
            g_assert_false(rv);
        }
    }

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_assert_cmpuint(paths->len, ==, 1);
    g_assert_cmpstr(paths->pdata[0], ==, "Release");

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_sig(gpointer data, gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "rsa4096-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, GPG_ERR_NO_PUBKEY);
            g_assert_false(rv);
        }
    }

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_assert_cmpuint(paths->len, ==, 0);

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_digest(gpointer data, gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size - 1, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
            g_assert_false(rv);
        }
    }

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_ptr_array_sort(paths, g_str_equal);
    g_assert_cmpuint(paths->len, ==, 2);
    g_assert_cmpstr(paths->pdata[0], ==, "main_source_Sources_xz");
    g_assert_cmpstr(paths->pdata[1], ==, "Release");

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_cache_digest(gpointer data,
                                             gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_cfg_repo *repo;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;
    GPtrArray *paths;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_no_error(err);
            g_assert_true(rv);
        }
    }
    dlp_table_free(&tbl);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", "sources",
                          "main_source_Sources_xz", NULL);
    g_assert_true(rv);
    rv = g_file_set_contents(path, "foo", -1, NULL);
    g_assert_true(rv);
    dlp_mem_free(&path);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, DLP_DIGEST_ERROR_MISMATCH);
            g_assert_false(rv);
        }
    }

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-cfg", NULL);
    g_assert_true(rv);

    paths = g_ptr_array_new_full(0, g_free);
    rv = dlp_fs_walk(path, test_apt_lookup_walk, paths, NULL);
    g_assert_true(rv);
    g_ptr_array_sort(paths, g_str_equal);
    g_assert_cmpuint(paths->len, ==, 2);
    g_assert_cmpstr(paths->pdata[0], ==, "contrib_source_Sources_xz");
    g_assert_cmpstr(paths->pdata[1], ==, "Release");

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(paths);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_row(gpointer data, gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-cfg]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "foo", "bar", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-cfg") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, EINVAL);
            g_assert_false(rv);
        }
    }

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

static void test_apt_lookup_bad_data_dir(gpointer data, gconstpointer user_data)
{
    bool rv;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    char *path = NULL;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;

    (void)data;
    (void)user_data;

    cfgdata = g_strdup_printf("[test-apt-lookup-bad-data-dir]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "foo", "bar", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-bad-data-dir", NULL);
    g_assert_true(rv);
    rv = dlp_fs_mkdir(path, NULL);
    g_assert_true(rv);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_cmpint(chmod(path, S_IRWXU | S_IWGRP), ==, 0);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-bad-data-dir") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, EBADFD);
            g_assert_false(rv);
        }
    }

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_cmpint(chmod(path, S_IRWXU), ==, 0);

    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
}

static void test_apt_lookup_bad_source_dir(gpointer data,
                                           gconstpointer user_data)
{
    bool rv;
    size_t size;
    struct dlp_cfg *cfg;
    struct dlp_backend *b;
    struct dlp_table *tbl;
    struct dlp_mhd *mhd;
    GRegex *rx;
    GPtrArray *rxs;
    GList *repos;
    const char *key;
    const char *cert;
    char *str = NULL;
    char *cfgdata = NULL;
    char *rls = NULL;
    char *maind = NULL;
    char *contrib = NULL;
    const char *host = "127.0.0.1";
    uint16_t port = 4321;
    GError *err = NULL;
    char *path = NULL;

    (void)data;
    (void)user_data;

    key = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "key.pem",
                              NULL);
    cert = g_test_get_filename(G_TEST_DIST, "tests", "data", "tls", "cert.pem",
                               NULL);

    cfgdata = g_strdup_printf("[test-apt-lookup-bad-source-dir]\n"
                              "backend = apt\n"
                              "url = https:/%s:%u\n"
                              "ca-file = %s\n"
                              "cache = 1\n"
                              "tls-key = "
                              "sha256//hiC2YHsimS6rJ/RZ1OM3rbt1DFATF/"
                              "o6fCDtm59VBQ8=\n"
                              "verify-keys = %s\n"
                              "user-agent = agent\n",
                              host, port, cert,
                              g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                  "gpg", "ed25519-pub.asc",
                                                  NULL));
    rv = g_file_set_contents("test-apt-lookup-cfg", cfgdata, -1, NULL);
    g_assert_true(rv);

    rv = dlp_cfg_read("test-apt-lookup-cfg", &cfg, &err);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_mhd_init(&mhd);
    g_assert_true(rv);

    rv = dlp_mhd_start(mhd, host, port, key, cert, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "release_signed.asc",
                                                 NULL),
                             &rls, NULL, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/InRelease", "agent", rls,
                             0, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_main.xz",
                                                 NULL),
                             &maind, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1", "/main/source/Sources.xz",
                             "agent", maind, size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = g_file_get_contents(g_test_get_filename(G_TEST_DIST, "tests", "data",
                                                 "apt", "sources_contrib.xz",
                                                 NULL),
                             &contrib, &size, NULL);
    g_assert_true(rv);

    rv = dlp_mhd_session_add(mhd, "GET", "HTTP/1.1",
                             "/contrib/source/Sources.xz", "agent", contrib,
                             size, 0, MHD_HTTP_OK, NULL);
    g_assert_true(rv);

    rv = dlp_backend_find("apt", &b, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_nonnull(b->lookup);

    rxs = g_ptr_array_new_full(0, dlp_mem_regex_destroy);
    rx = g_regex_new("foo", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);
    rx = g_regex_new("libdisasm_.*orig", (GRegexCompileFlags)0,
                     (GRegexMatchFlags)0, NULL);
    g_ptr_array_add(rxs, rx);

    dlp_table_init(&tbl);
    rv = dlp_table_add_columns(tbl, &err, "repository", "package", "file",
                               "algorithm", "digest", NULL);
    g_assert_no_error(err);
    g_assert_true(rv);

    rv = dlp_fs_data_path(&path, NULL, "test-apt-lookup-bad-source-dir",
                          "sources", NULL);
    g_assert_true(rv);
    rv = dlp_fs_mkdir(path, NULL);
    g_assert_true(rv);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_cmpint(chmod(path, S_IRWXU | S_IWGRP), ==, 0);

    for (repos = cfg->repos; repos != NULL; repos = repos->next) {
        struct dlp_cfg_repo *repo = repos->data;
        if (g_strcmp0(repo->name, "test-apt-lookup-bad-source-dir") == 0) {
            rv = b->lookup(repo, rxs, tbl, &err);
            g_assert_error(err, DLP_ERROR, EBADFD);
            g_assert_false(rv);
        }
    }

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    g_assert_cmpint(chmod(path, S_IRWXU), ==, 0);

    dlp_mem_free(&str);
    dlp_mem_free(&cfgdata);
    dlp_mem_free(&rls);
    dlp_mem_free(&maind);
    dlp_mem_free(&contrib);
    dlp_mem_free(&path);
    g_ptr_array_unref(rxs);
    dlp_table_free(&tbl);
    dlp_cfg_free(&cfg);
    g_assert_true(dlp_mhd_stop(mhd));
    g_assert_true(dlp_mhd_free(mhd));
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_assert_true(dlp_gpg_global_init(NULL));
    g_assert_true(dlp_curl_global_init(NULL));

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/apt/ctor", sizeof(struct state), NULL, setup,
                      test_apt_ctor, teardown);
    g_test_add_vtable("/apt/release/free", sizeof(struct state), NULL, setup,
                      test_apt_release_free, teardown);
    g_test_add_vtable("/apt/release/read/files", sizeof(struct state), NULL,
                      setup, test_apt_release_read_files, teardown);
    g_test_add_vtable("/apt/release/read/date", sizeof(struct state), NULL,
                      setup, test_apt_release_read_date, teardown);
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
    g_test_add_vtable("/apt/lookup/success", sizeof(struct state), NULL, setup,
                      test_apt_lookup_success, teardown);
    g_test_add_vtable("/apt/lookup/success-cache", sizeof(struct state), NULL,
                      setup, test_apt_lookup_success_cache, teardown);
    g_test_add_vtable("/apt/lookup/success-stale", sizeof(struct state), NULL,
                      setup, test_apt_lookup_success_stale, teardown);
    g_test_add_vtable("/apt/lookup/bad-release-url", sizeof(struct state), NULL,
                      setup, test_apt_lookup_bad_release_url, teardown);
    g_test_add_vtable("/apt/lookup/bad-sources-url", sizeof(struct state), NULL,
                      setup, test_apt_lookup_bad_sources_url, teardown);
    g_test_add_vtable("/apt/lookup/bad-sig", sizeof(struct state), NULL, setup,
                      test_apt_lookup_bad_sig, teardown);
    g_test_add_vtable("/apt/lookup/bad-digest", sizeof(struct state), NULL,
                      setup, test_apt_lookup_bad_digest, teardown);
    g_test_add_vtable("/apt/lookup/bad-cache-digest", sizeof(struct state),
                      NULL, setup, test_apt_lookup_bad_cache_digest, teardown);
    g_test_add_vtable("/apt/lookup/bad-row", sizeof(struct state), NULL, setup,
                      test_apt_lookup_bad_row, teardown);
    g_test_add_vtable("/apt/lookup/bad-data-dir", sizeof(struct state), NULL,
                      setup, test_apt_lookup_bad_data_dir, teardown);
    g_test_add_vtable("/apt/lookup/bad-source-dir", sizeof(struct state), NULL,
                      setup, test_apt_lookup_bad_source_dir, teardown);

    return g_test_run();
}

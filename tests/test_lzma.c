/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <errno.h>
#include <stdio.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_lzma.h"
#include "test.h"

struct state {
    char *home;
    char *cwd;
    char orig_cwd[PATH_MAX];
    char *xz;
};

static void setup(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(test_setup_home(&s->home));
    g_assert_true(getcwd(s->orig_cwd, sizeof(s->orig_cwd)) != NULL);
    g_assert_nonnull((s->cwd = g_strdup(g_getenv("DLP_TEST_HOME"))));
    g_assert_true(chdir(s->cwd) == 0);
    g_assert_nonnull(s->xz = g_find_program_in_path("xz"));
}

static void teardown(gpointer data, gconstpointer user_data)
{
    struct state *s = data;

    (void)user_data;

    g_assert_true(chdir(s->orig_cwd) == 0);
    g_assert_true(dlp_fs_rmdir(s->cwd, NULL));

    dlp_mem_free(&s->xz);
    dlp_mem_free(&s->cwd);
    dlp_mem_free(&s->home);
}

static void compress(const char *xz, const char *path, const char *content)
{
    int rc;
    GError *err = NULL;
    char *argv[] = { g_strdup(xz), g_strdup(path), "--keep", NULL };

    if (!g_file_set_contents(path, content, -1, &err)) {
        g_error("%s", err ? err->message : "unknown");
    }

    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL, NULL,
                      &rc, &err)) {
        g_error("%s", err ? err->message : "unknown");
    }

    if (!g_spawn_check_exit_status(rc, &err)) {
        g_error("%s", err ? err->message : "unknown");
    }

    g_free(argv[0]);
    g_free(argv[1]);
}

static void test_lzma_decompress_success(gpointer data, gconstpointer user_data)
{
    int infd;
    int outfd;
    size_t i;
    size_t len;
    struct stat st;
    bool rv;
    char *tmp = NULL;
    char *got = NULL;
    char *want = NULL;
    char *plain = NULL;
    char *comp = NULL;
    GError *err = NULL;
    struct state *s = data;

    (void)data;
    (void)user_data;

    /*
     * Empty file.
     */
    want = g_strdup("");

    g_assert_true(dlp_fs_cache_path(&plain, NULL, "empty", NULL));
    g_assert_true(dlp_fs_cache_path(&comp, NULL, "empty.xz", NULL));
    compress(s->xz, plain, want);
    g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
    g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

    rv = dlp_lzma_decompress(infd, outfd, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
    g_assert_cmpint(st.st_size, ==, 0);

    g_assert_true(dlp_fs_close(&infd, NULL));
    g_assert_true(dlp_fs_close(&outfd, NULL));
    g_assert_cmpint(unlink(plain), ==, 0);
    g_assert_cmpint(unlink(comp), ==, 0);

    dlp_mem_free(&want);
    dlp_mem_free(&plain);
    dlp_mem_free(&comp);

    /*
     * Small file.
     */
    want = g_strdup("foobar");
    len = strlen(want);
    got = g_malloc(len);

    g_assert_true(dlp_fs_cache_path(&plain, NULL, "small", NULL));
    g_assert_true(dlp_fs_cache_path(&comp, NULL, "small.xz", NULL));
    compress(s->xz, plain, want);
    g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
    g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

    rv = dlp_lzma_decompress(infd, outfd, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
    g_assert_cmpint(st.st_size, ==, len);
    g_assert_true(dlp_fs_read_bytes(outfd, got, len, NULL));
    g_assert_cmpmem(got, len, want, len);

    g_assert_true(dlp_fs_close(&infd, NULL));
    g_assert_true(dlp_fs_close(&outfd, NULL));
    g_assert_cmpint(unlink(plain), ==, 0);
    g_assert_cmpint(unlink(comp), ==, 0);

    dlp_mem_free(&want);
    dlp_mem_free(&got);
    dlp_mem_free(&plain);
    dlp_mem_free(&comp);

    /*
     * Non-small file.
     */
    g_assert_true(g_file_get_contents(__FILE__, &want, NULL, NULL));
    len = strlen(want);
    got = g_malloc(len);

    g_assert_true(dlp_fs_cache_path(&plain, NULL, "non-small", NULL));
    g_assert_true(dlp_fs_cache_path(&comp, NULL, "non-small.xz", NULL));
    compress(s->xz, plain, want);
    g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
    g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

    rv = dlp_lzma_decompress(infd, outfd, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
    g_assert_cmpint(st.st_size, ==, len);
    g_assert_true(dlp_fs_read_bytes(outfd, got, len, NULL));
    g_assert_cmpmem(got, len, want, len);

    g_assert_true(dlp_fs_close(&infd, NULL));
    g_assert_true(dlp_fs_close(&outfd, NULL));
    g_assert_cmpint(unlink(plain), ==, 0);
    g_assert_cmpint(unlink(comp), ==, 0);

    dlp_mem_free(&want);
    dlp_mem_free(&got);
    dlp_mem_free(&plain);
    dlp_mem_free(&comp);

    /*
     * Large-ish file.
     */
    want = g_malloc0_n(1234, 4321);
    tmp = g_uuid_string_random();
    len = strlen(tmp);
    for (i = 0; i < 1234 * 4321 - 1; i++) {
        want[i] = tmp[i % len];
        if ((i % 1234) == 0) {
            dlp_mem_free(&tmp);
            tmp = g_uuid_string_random();
            len = strlen(tmp);
        }
    }
    dlp_mem_free(&tmp);

    len = strlen(want);
    got = g_malloc(len);

    g_assert_true(dlp_fs_cache_path(&plain, NULL, "largeish", NULL));
    g_assert_true(dlp_fs_cache_path(&comp, NULL, "largeish.xz", NULL));
    compress(s->xz, plain, want);
    g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
    g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

    rv = dlp_lzma_decompress(infd, outfd, &err);
    g_assert_no_error(err);
    g_assert_true(rv);
    g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
    g_assert_cmpint(st.st_size, ==, len);
    g_assert_true(dlp_fs_read_bytes(outfd, got, len, NULL));
    g_assert_cmpmem(got, len, want, len);

    g_assert_true(dlp_fs_close(&infd, NULL));
    g_assert_true(dlp_fs_close(&outfd, NULL));
    g_assert_cmpint(unlink(plain), ==, 0);
    g_assert_cmpint(unlink(comp), ==, 0);

    dlp_mem_free(&want);
    dlp_mem_free(&got);
    dlp_mem_free(&plain);
    dlp_mem_free(&comp);
}

static void test_lzma_decompress_fail(gpointer data, gconstpointer user_data)
{
    int infd;
    int outfd;
    struct stat st;
    bool rv;
    char *tmp = NULL;
    char *plain = NULL;
    char *comp = NULL;
    GError *err = NULL;
    struct state *s = data;

    (void)data;
    (void)user_data;

    /*
     * Truncation failure.
     */
    g_assert_true(dlp_fs_cache_path(&plain, NULL, "trunc", NULL));
    g_assert_true(dlp_fs_cache_path(&comp, NULL, "trunc.xz", NULL));
    g_assert_true(dlp_fs_cache_dir(&tmp, NULL));
    compress(s->xz, plain, "foobar");
    g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
    g_assert_true(dlp_fs_open(tmp, O_RDONLY, 0, &outfd, NULL));

    rv = dlp_lzma_decompress(infd, outfd, &err);
    g_assert_nonnull(err);
    g_assert_false(rv);

    g_assert_true(dlp_fs_close(&infd, NULL));
    g_assert_true(dlp_fs_close(&outfd, NULL));
    g_assert_cmpint(unlink(plain), ==, 0);
    g_assert_cmpint(unlink(comp), ==, 0);

    g_clear_error(&err);
    dlp_mem_free(&plain);
    dlp_mem_free(&comp);
    dlp_mem_free(&tmp);

    if (test_wrap_p()) {
        GVariantDict *v;

        /*
         * Decoder init failure.
         */
        test_wrap_push(lzma_auto_decoder, true,
                       GUINT_TO_POINTER(LZMA_MEM_ERROR));

        g_assert_true(dlp_fs_cache_path(&plain, NULL, "dec-init", NULL));
        g_assert_true(dlp_fs_cache_path(&comp, NULL, "dec-init.xz", NULL));
        compress(s->xz, plain, "foobar");
        g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

        rv = dlp_lzma_decompress(infd, outfd, &err);
        g_assert_error(err, DLP_ERROR, DLP_LZMA_ERROR_FAILED);
        g_assert_false(rv);
        g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
        g_assert_cmpint(st.st_size, ==, 0);

        g_assert_true(dlp_fs_close(&infd, NULL));
        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_cmpint(unlink(plain), ==, 0);
        g_assert_cmpint(unlink(comp), ==, 0);

        g_clear_error(&err);
        dlp_mem_free(&plain);
        dlp_mem_free(&comp);

        /*
         * Decode memory failure.
         */
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "rv", "i", LZMA_MEM_ERROR);

        g_assert_true(dlp_fs_cache_path(&plain, NULL, "dec-mem", NULL));
        g_assert_true(dlp_fs_cache_path(&comp, NULL, "dec-mem.xz", NULL));
        compress(s->xz, plain, "foobar");
        g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

        test_wrap_push(lzma_code, true, v);
        rv = dlp_lzma_decompress(infd, outfd, &err);
        g_assert_error(err, DLP_ERROR, DLP_LZMA_ERROR_FAILED);
        g_assert_false(rv);
        g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
        g_assert_cmpint(st.st_size, ==, 0);

        g_assert_true(dlp_fs_close(&infd, NULL));
        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_cmpint(unlink(plain), ==, 0);
        g_assert_cmpint(unlink(comp), ==, 0);

        g_variant_dict_unref(v);
        g_clear_error(&err);
        dlp_mem_free(&plain);
        dlp_mem_free(&comp);

        /*
         * Decode integer overflow.
         */
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "avail_out", "u", BUFSIZ + 1);
        g_variant_dict_insert(v, "rv", "i", LZMA_STREAM_END);

        g_assert_true(dlp_fs_cache_path(&plain, NULL, "dec-mem", NULL));
        g_assert_true(dlp_fs_cache_path(&comp, NULL, "dec-mem.xz", NULL));
        compress(s->xz, plain, "foobar");
        g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

        test_wrap_push(lzma_code, true, v);
        rv = dlp_lzma_decompress(infd, outfd, &err);
        g_assert_error(err, DLP_ERROR, ERANGE);
        g_assert_false(rv);
        g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
        g_assert_cmpint(st.st_size, ==, 0);

        g_assert_true(dlp_fs_close(&infd, NULL));
        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_cmpint(unlink(plain), ==, 0);
        g_assert_cmpint(unlink(comp), ==, 0);

        g_variant_dict_unref(v);
        g_clear_error(&err);
        dlp_mem_free(&plain);
        dlp_mem_free(&comp);

        /*
         * read() failure.
         */
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "rv", "i", -1);
        g_variant_dict_insert(v, "errno", "i", EBADF);

        g_assert_true(dlp_fs_cache_path(&plain, NULL, "read", NULL));
        g_assert_true(dlp_fs_cache_path(&comp, NULL, "read.xz", NULL));
        compress(s->xz, plain, "foobar");
        g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

        test_wrap_push(read, true, v);
        rv = dlp_lzma_decompress(infd, outfd, &err);
        g_assert_error(err, DLP_ERROR, EBADF);
        g_assert_false(rv);
        g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
        g_assert_cmpint(st.st_size, ==, 0);

        g_assert_true(dlp_fs_close(&infd, NULL));
        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_cmpint(unlink(plain), ==, 0);
        g_assert_cmpint(unlink(comp), ==, 0);

        g_variant_dict_unref(v);
        g_clear_error(&err);
        dlp_mem_free(&plain);
        dlp_mem_free(&comp);

        /*
         * write() failure.
         */
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "rv", "i", -1);
        g_variant_dict_insert(v, "errno", "i", EBADF);

        g_assert_true(dlp_fs_cache_path(&plain, NULL, "write", NULL));
        g_assert_true(dlp_fs_cache_path(&comp, NULL, "write.xz", NULL));
        compress(s->xz, plain, "foobar");
        g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

        test_wrap_push(write, true, v);
        rv = dlp_lzma_decompress(infd, outfd, &err);
        g_assert_error(err, DLP_ERROR, EBADF);
        g_assert_false(rv);
        g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
        g_assert_cmpint(st.st_size, ==, 0);

        g_assert_true(dlp_fs_close(&infd, NULL));
        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_cmpint(unlink(plain), ==, 0);
        g_assert_cmpint(unlink(comp), ==, 0);

        g_variant_dict_unref(v);
        g_clear_error(&err);
        dlp_mem_free(&plain);
        dlp_mem_free(&comp);

        /*
         * Final read() failure.
         */
        v = g_variant_dict_new(NULL);
        g_variant_dict_insert(v, "rv", "i", -1);
        g_variant_dict_insert(v, "errno", "i", EBADF);

        g_assert_true(dlp_fs_cache_path(&plain, NULL, "fin-read", NULL));
        g_assert_true(dlp_fs_cache_path(&comp, NULL, "fin-read.xz", NULL));
        compress(s->xz, plain, "");
        g_assert_true(dlp_fs_open(comp, O_RDONLY, 0, &infd, NULL));
        g_assert_true(dlp_fs_mkstemp(&outfd, NULL));

        test_wrap_push(read, true, v);
        test_wrap_push(read, false, NULL);
        rv = dlp_lzma_decompress(infd, outfd, &err);
        g_assert_error(err, DLP_ERROR, EBADF);
        g_assert_false(rv);
        g_assert_true(dlp_fs_fstat(outfd, &st, NULL));
        g_assert_cmpint(st.st_size, ==, 0);

        g_assert_true(dlp_fs_close(&infd, NULL));
        g_assert_true(dlp_fs_close(&outfd, NULL));
        g_assert_cmpint(unlink(plain), ==, 0);
        g_assert_cmpint(unlink(comp), ==, 0);

        g_variant_dict_unref(v);
        g_clear_error(&err);
        dlp_mem_free(&plain);
        dlp_mem_free(&comp);
    }
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_init(&argc, &argv, NULL);

    g_test_add_vtable("/lzma/decompress/success", sizeof(struct state), NULL,
                      setup, test_lzma_decompress_success, teardown);
    g_test_add_vtable("/lzma/decompress/fail", sizeof(struct state), NULL,
                      setup, test_lzma_decompress_fail, teardown);

    return g_test_run();
}

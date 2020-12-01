/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include <glib.h>

#include "dlp.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "test.h"

enum dlp_fixture_error {
    DLP_FIXTURE_ERROR_FAILED = 1,
};

static bool fixture_lzma_setup(GError **error) DLP_NODISCARD;
static bool fixture_lzma_cleanup(GError **error) DLP_NODISCARD;
static bool fixture_lzma_compress(int dfd, const char *name, const char *path,
                                  const struct stat *s, void *data,
                                  GError **error) DLP_NODISCARD;

int main(void)
{
    GError *err = NULL;
    bool rv = false;

    if (!test_setup_home(NULL)) {
        g_error("cannot setup HOME");
    }

    if (g_getenv("FIXTURE_SETUP")) {
        rv = fixture_lzma_setup(&err);
    } else if (g_getenv("FIXTURE_CLEANUP")) {
        rv = fixture_lzma_cleanup(&err);
    } else {
        g_error("invalid stage");
    }

    if (!rv) {
        g_error("%s", err ? err->message : "unknown error");
    }
    return 0;
}

static bool fixture_lzma_setup(GError **error)
{
    const char *env;
    char *src_dir = NULL;
    char *build_dir = NULL;
    bool rv = false;

    if (!fixture_lzma_cleanup(error)) {
        goto out;
    }

    if ((env = g_getenv("FIXTURE_SOURCE_DIR")) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_FIXTURE_ERROR_FAILED,
                    "FIXTURE_SOURCE_DIR is not set");
        goto out;
    }

    src_dir = g_build_filename(env, "data", "lzma", NULL);
    if (!g_file_test(src_dir, G_FILE_TEST_IS_DIR)) {
        g_set_error(error, DLP_ERROR, DLP_FIXTURE_ERROR_FAILED,
                    "%s is not a directory", src_dir);
        goto out;
    }

    if ((env = g_getenv("FIXTURE_BUILD_DIR")) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_FIXTURE_ERROR_FAILED,
                    "FIXTURE_BUILD_DIR is not set");
        goto out;
    }

    build_dir = g_build_filename(env, "data", "lzma", NULL);
    if (!dlp_fs_mkdir(build_dir, error)) {
        goto out;
    }

    if (!dlp_fs_walk(src_dir, fixture_lzma_compress, build_dir, error)) {
        goto out;
    }

    rv = true;

out:
    g_free(build_dir);
    g_free(src_dir);
    return rv;
}

static bool fixture_lzma_cleanup(GError **error)
{
    const char *env;
    char *build_dir = NULL;
    bool rv = false;

    if ((env = g_getenv("FIXTURE_BUILD_DIR")) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_FIXTURE_ERROR_FAILED,
                    "FIXTURE_BUILD_DIR is not set");
        goto out;
    }

    build_dir = g_build_filename(env, "data", "lzma", NULL);
    if (g_file_test(build_dir, G_FILE_TEST_EXISTS) &&
        !dlp_fs_rmdir(build_dir, error)) {
        goto out;
    }

    rv = true;

out:
    g_free(build_dir);
    return rv;
}

static bool fixture_lzma_compress(int dfd, const char *name, const char *path,
                                  const struct stat *s, void *data,
                                  GError **error)
{
    int rc;
    char *argv[3] = { NULL };
    char *xz = NULL;
    char *content = NULL;
    char *build_bname = NULL;
    char *build_path = NULL;
    char *build_dir = data;
    bool rv = false;

    (void)dfd;
    (void)name;

    if ((s->st_mode & DLP_FS_TYPE) != DLP_FS_REG) {
        return true;
    }

    build_bname = g_path_get_basename(path);
    build_path = g_build_filename(build_dir, build_bname, NULL);

    if (!g_file_get_contents(path, &content, NULL, error)) {
        goto out;
    }

    if (!g_file_set_contents(build_path, content, -1, error)) {
        goto out;
    }

    if ((xz = g_find_program_in_path("xz")) == NULL) {
        g_set_error(error, DLP_ERROR, DLP_FIXTURE_ERROR_FAILED, "missing xz");
        goto out;
    }

    argv[0] = xz;
    argv[1] = build_path;
    argv[2] = NULL;

    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL, NULL,
                      &rc, error)) {
        goto out;
    }

    if (!g_spawn_check_exit_status(rc, error)) {
        goto out;
    }

    rv = true;

out:
    g_free(build_bname);
    g_free(build_path);
    g_free(content);
    g_free(xz);
    return rv;
}

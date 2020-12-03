/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_cfg.h"

#include <errno.h>

#include "config.h"
#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"
#include "dlp_resource.h"

struct dlp_cfg_setting {
    const char *key;
    bool (*get)(GKeyFile *kf, const char *group, const char *key,
                const void *fallback, void *dst, GError **error);
    GDestroyNotify free;
    void *fallback;
    glong offset;
    bool required;
};

static bool dlp_cfg_read_default(GKeyFile **kf, GError **error) DLP_NODISCARD;
static bool dlp_cfg_read_user(const char *path, GKeyFile **kf,
                              GError **error) DLP_NODISCARD;
static bool dlp_cfg_overwrite(GKeyFile *dst, GKeyFile *src,
                              GError **error) DLP_NODISCARD;
static bool dlp_cfg_convert(GKeyFile *kf, struct dlp_cfg **cfg,
                            GError **error) DLP_NODISCARD;
static bool dlp_cfg_convert_repo(GKeyFile *kf, const char *group,
                                 struct dlp_cfg_repo **repo,
                                 GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_string(GKeyFile *kf, const char *group, const char *key,
                               const void *fallback, void *dst,
                               GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_strings(GKeyFile *kf, const char *group,
                                const char *key, const void *fallback,
                                void *dst, GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_uint64(GKeyFile *kf, const char *group, const char *key,
                               const void *fallback, void *dst,
                               GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_time(GKeyFile *kf, const char *group, const char *key,
                             const void *fallback, void *dst,
                             GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_files(GKeyFile *kf, const char *group, const char *key,
                              const void *fallback, void *dst,
                              GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_backend(GKeyFile *kf, const char *group,
                                const char *key, const void *fallback,
                                void *dst, GError **error) DLP_NODISCARD;
static bool dlp_cfg_get_group(GKeyFile *kf, const char *group, const char *key,
                              const void *fallback, void *dst,
                              GError **error) DLP_NODISCARD;
static void dlp_cfg_repo_free(gpointer ptr);

static const struct dlp_cfg_setting dlp_cfg_repo_settings[] = {
    { .key = "name",
      .get = dlp_cfg_get_group,
      .free = g_free,
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, name),
      .required = true },
    { .key = "backend",
      .get = dlp_cfg_get_backend,
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, backend),
      .required = true },
    { .key = "url",
      .get = dlp_cfg_get_string,
      .free = g_free,
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, url),
      .required = true },
    { .key = "tls-key",
      .get = dlp_cfg_get_string,
      .free = g_free,
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, tls_key),
      .required = true },
    { .key = "user-agent",
      .get = dlp_cfg_get_string,
      .free = g_free,
      .fallback = PROJECT_NAME,
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, user_agent),
      .required = false },
    { .key = "verify-keys",
      .get = dlp_cfg_get_files,
      .free = dlp_mem_ptr_array_destroy,
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, verify_keys),
      .required = true },
    { .key = "cache",
      .get = dlp_cfg_get_time,
      .fallback = GUINT_TO_POINTER(86400),
      .offset = G_STRUCT_OFFSET(struct dlp_cfg_repo, cache),
      .required = false },
};

/**
 * Read one or more config files.
 *
 * The default config is always read.  It is overwritten by settings in the
 * user config if `path` is non-NULL or if the default user config path exist.
 *
 * @param path  Optional path that overrides the default configuration.
 * @param cfg   Config structure that must be freed with dlp_cfg_free().
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_cfg_read(const char *path, struct dlp_cfg **cfg, GError **error)
{
    GKeyFile *def = NULL;
    GKeyFile *usr = NULL;
    bool rv = false;

    g_return_val_if_fail(cfg != NULL, false);
    *cfg = NULL;

    if (!dlp_cfg_read_default(&def, error)) {
        goto out;
    }

    if (!dlp_cfg_read_user(path, &usr, error)) {
        goto out;
    }

    if (usr != NULL && !dlp_cfg_overwrite(def, usr, error)) {
        goto out;
    }

    if (!dlp_cfg_convert(def, cfg, error)) {
        goto out;
    }

    rv = true;

out:
    if (usr != NULL) {
        g_key_file_free(usr);
    }

    if (def != NULL) {
        g_key_file_free(def);
    }

    return rv;
}

/**
 * Free a config structure.
 *
 * @param cfg Structure to free.
 */
void dlp_cfg_free(struct dlp_cfg **cfg)
{
    if (cfg != NULL && *cfg != NULL) {
        g_list_free_full((*cfg)->repos, dlp_cfg_repo_free);
        dlp_mem_free(cfg);
    }
}

/**
 * Read the default configuration from GResource.
 *
 * @param kf    Keyfile structure that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_read_default(GKeyFile **kf, GError **error)
{
    void *data;
    gsize n;

    g_return_val_if_fail(kf != NULL, false);
    *kf = NULL;

    if (!dlp_resource_data("/dlp/config/digestlookup.conf", &data, &n, error)) {
        return false;
    }

    *kf = g_key_file_new();
    if (!g_key_file_load_from_data(*kf, data, n, G_KEY_FILE_NONE, error)) {
        g_key_file_free(*kf);
        *kf = NULL;
        dlp_mem_free(&data);
        return false;
    }

    dlp_mem_free(&data);
    return true;
}

/**
 * Read a user configuration file.
 *
 * @param path  Optional path to read.  If it is non-NULL, the path must exist.
 *              Otherwise, the default user configuration path is used, which
 *              may successfully be non-existent.
 * @param kf    Keyfile structure that must be freed after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_read_user(const char *path, GKeyFile **kf, GError **error)
{
    char *usr = NULL;
    bool rv = false;

    g_return_val_if_fail(kf != NULL, false);
    *kf = g_key_file_new();

    if (path == NULL) {
        if (!dlp_fs_config_path(&usr, error, PROJECT_NAME ".conf", NULL)) {
            goto out;
        }

        if (g_file_test(usr, G_FILE_TEST_IS_REGULAR) &&
            !g_key_file_load_from_file(*kf, usr, G_KEY_FILE_NONE, error)) {
            goto out;
        }
    } else {
        if (!dlp_fs_check_path(path, DLP_FS_REG, true, error) ||
            !g_key_file_load_from_file(*kf, path, G_KEY_FILE_NONE, error)) {
            goto out;
        }
    }

    rv = true;

out:
    dlp_mem_free(&usr);

    if (!rv) {
        g_key_file_free(*kf);
        *kf = NULL;
    }

    return rv;
}

/**
 * Overwrite one keyfile structure with another.
 *
 * @param dst   Destination keyfile.
 * @param src   Source keyfile.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_overwrite(GKeyFile *dst, GKeyFile *src, GError **error)
{
    char **g;
    char **k;
    char *value;
    char **groups = NULL;
    char **keys = NULL;

    g_return_val_if_fail(dst != NULL && src != NULL, false);

    groups = g_key_file_get_groups(src, NULL);
    for (g = groups; g != NULL && *g != NULL; g++) {
        keys = g_key_file_get_keys(src, *g, NULL, error);
        for (k = keys; k != NULL && *k != NULL; k++) {
            value = g_key_file_get_value(src, *g, *k, error);
            if (value == NULL) {
                g_prefix_error(error, "%s: %s: ", *g, *k);
                g_strfreev(keys);
                g_strfreev(groups);
                return false;
            }

            g_key_file_set_value(dst, *g, *k, value);
            g_free(value);
        }
        g_strfreev(keys);
    }
    g_strfreev(groups);

    return true;
}

/**
 * Fill a dlp_cfg structure with configuration settings.
 *
 * @param kf    Config settings.
 * @param cfg   Config structure that must be freed with dlp_cfg_free().
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_convert(GKeyFile *kf, struct dlp_cfg **cfg, GError **error)
{
    struct dlp_cfg_repo *repo;
    char **g;
    char **groups;

    g_return_val_if_fail(kf != NULL && cfg != NULL, false);

    *cfg = dlp_mem_alloc(sizeof(**cfg));

    groups = g_key_file_get_groups(kf, NULL);
    for (g = groups; g != NULL && *g != NULL; g++) {
        if (!dlp_cfg_convert_repo(kf, *g, &repo, error)) {
            g_strfreev(groups);
            dlp_cfg_free(cfg);
            return false;
        }

        (*cfg)->repos = g_list_prepend((*cfg)->repos, repo);
    }
    g_strfreev(groups);

    return true;
}

/**
 * Fill a dlp_cfg_repo structure with repository settings.
 *
 * @param kf    Config settings.
 * @param group Config group for the repository.
 * @param repo  Repo structure that must be freed with dlp_cfg_repo_free().
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_convert_repo(GKeyFile *kf, const char *group,
                                 struct dlp_cfg_repo **repo, GError **error)
{
    size_t i;
    GError *err = NULL;

    g_return_val_if_fail(kf != NULL && group != NULL && repo != NULL, false);

    *repo = dlp_mem_alloc(sizeof(**repo));

    for (i = 0; i < G_N_ELEMENTS(dlp_cfg_repo_settings); i++) {
        const struct dlp_cfg_setting *s = &dlp_cfg_repo_settings[i];
        void *dst = G_STRUCT_MEMBER_P(*repo, s->offset);

        if (!s->get(kf, group, s->key, s->fallback, dst, &err)) {
            if (err == NULL) {
                return false;
            }

            if (err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND || s->required) {
                g_propagate_prefixed_error(error, err, "%s: %s: ", group,
                                           s->key);
                dlp_cfg_repo_free(*repo);
                return false;
            }

            g_clear_error(&err);
        }
    }

    return true;
}

/**
 * Read a string from the configuration.
 *
 * @param kf        Config settings.
 * @param group     Group to read from.
 * @param key       Key to read.
 * @param fallback  Optional value to use if the key doesn't exist.
 * @param dst       Destination for the config value.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_string(GKeyFile *kf, const char *group, const char *key,
                               const void *fallback, void *dst, GError **error)
{
    GError *err = NULL;
    char **str = dst;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    *str = g_key_file_get_string(kf, group, key, &err);
    if (err != NULL) {
        if (err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND || fallback == NULL) {
            g_propagate_error(error, err);
            return false;
        }
        g_clear_error(&err);
        *str = g_strdup(fallback);
    }

    return true;
}

/**
 * Read an array of strings from the configuration.
 *
 * @param kf        Config settings.
 * @param group     Group to read from.
 * @param key       Key to read.
 * @param fallback  Unused.
 * @param dst       Destination for the config value.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_strings(GKeyFile *kf, const char *group,
                                const char *key, const void *fallback,
                                void *dst, GError **error)
{
    char **strs;
    char **s;
    GPtrArray **array = dst;

    (void)fallback;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    strs = g_key_file_get_string_list(kf, group, key, NULL, error);
    if (strs == NULL) {
        return false;
    }

    *array = g_ptr_array_new_full(0, g_free);
    for (s = strs; *s != NULL; s++) {
        g_ptr_array_add(*array, g_strstrip(*s));
    }
    g_free(strs);

    return true;
}

/**
 * Read a guint64 from the configuration.
 *
 * @param kf        Config settings.
 * @param group     Group to read from.
 * @param key       Key to read.
 * @param fallback  Optional value to use if the key doesn't exist.
 * @param dst       Destination for the config value.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_uint64(GKeyFile *kf, const char *group, const char *key,
                               const void *fallback, void *dst, GError **error)
{
    GError *err = NULL;
    guint64 *n = dst;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    *n = g_key_file_get_uint64(kf, group, key, &err);
    if (err != NULL) {
        if (err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND || fallback == NULL) {
            g_propagate_error(error, err);
            return false;
        }
        g_clear_error(&err);
        *n = GPOINTER_TO_UINT(fallback);
    }

    return true;
}

/**
 * Read a time_t from the configuration.
 *
 * @param kf        Config settings.
 * @param group     Group to read from.
 * @param key       Key to read.
 * @param fallback  Optional value to use if the key doesn't exist.
 * @param dst       Destination for the config value.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_time(GKeyFile *kf, const char *group, const char *key,
                             const void *fallback, void *dst, GError **error)
{
    guint64 n;
    time_t *t = dst;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    if (!dlp_cfg_get_uint64(kf, group, key, fallback, &n, error)) {
        return false;
    }

    if (dlp_overflow_add(n, 0, t)) {
        g_set_error(error, DLP_ERROR, EOVERFLOW, "%s", g_strerror(EOVERFLOW));
        return false;
    }

    return true;
}

/**
 * Read an array of files from the configuration.
 *
 * All files must exist and entries prefixed with resource:// are interpreted
 * as being a GResource file.
 *
 * @param kf        Config settings.
 * @param group     Group to read from.
 * @param key       Key to read.
 * @param fallback  Unused.
 * @param dst       Destination for the config value.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_files(GKeyFile *kf, const char *group, const char *key,
                              const void *fallback, void *dst, GError **error)
{
    guint i;
    GPtrArray **files = dst;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    if (!dlp_cfg_get_strings(kf, group, key, fallback, files, error)) {
        return false;
    }

    for (i = 0; i < (*files)->len; i++) {
        char *path = (*files)->pdata[i];
        if (dlp_resource_p(path)) {
            if (!dlp_resource_exists_p(path, error)) {
                break;
            }
        } else if (!dlp_fs_check_path(path, DLP_FS_REG, true, error)) {
            break;
        }
    }

    if (i != (*files)->len) {
        dlp_mem_ptr_array_unref(files);
        return false;
    }

    return true;
}

/**
 * Retrieve an appropriate backend.
 *
 * @param kf        Config settings.
 * @param group     Group to read from.
 * @param key       Key to read.
 * @param fallback  Unused.
 * @param dst       Destination for the backend.
 * @param error     Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_backend(GKeyFile *kf, const char *group,
                                const char *key, const void *fallback,
                                void *dst, GError **error)
{
    char *name;
    struct dlp_backend **be = dst;

    (void)fallback;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    if (!dlp_cfg_get_string(kf, group, key, NULL, &name, error)) {
        return false;
    }

    if (!dlp_backend_find(name, be, error)) {
        dlp_mem_free(&name);
        return false;
    }

    dlp_mem_free(&name);
    return true;
}

/**
 * Set the section group.
 *
 * @param kf        Unused.
 * @param group     Group to set.
 * @param key       Unused.
 * @param fallback  Unused.
 * @param dst       Destination for the group.
 * @param error     Unused.
 * @return True on success and false on failure.
 */
static bool dlp_cfg_get_group(GKeyFile *kf, const char *group, const char *key,
                              const void *fallback, void *dst, GError **error)
{
    char **str = dst;

    (void)fallback;
    (void)error;

    g_return_val_if_fail(kf != NULL && group != NULL, false);
    g_return_val_if_fail(key != NULL && dst != NULL, false);

    *str = g_strdup(group);
    return *str != NULL;
}

/**
 * Free a dlp_cfg_repo structure.
 *
 * @param ptr Structure to free.
 */
static void dlp_cfg_repo_free(gpointer ptr)
{
    struct dlp_cfg_repo *repo = ptr;

    if (repo != NULL) {
        size_t i;
        for (i = 0; i < G_N_ELEMENTS(dlp_cfg_repo_settings); i++) {
            const struct dlp_cfg_setting *s = &dlp_cfg_repo_settings[i];
            void *value = G_STRUCT_MEMBER(void *, repo, s->offset);
            if (s->free != NULL && value != NULL) {
                s->free(value);
            }
        }
        g_free(repo);
    }
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_gpg.h"

#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <gio/gio.h>
#include <glib/gi18n.h>

#include "dlp_error.h"
#include "dlp_fs.h"
#include "dlp_mem.h"
#include "dlp_overflow.h"
#include "dlp_resource.h"

struct dlp_gpg {
    gpgme_ctx_t ctx;
    char *home;
};

static bool dlp_gpg_verify(struct dlp_gpg *gpg, gpgme_data_t sig,
                           gpgme_data_t signed_text, gpgme_data_t plain,
                           GError **error) DLP_NODISCARD;
static bool dlp_gpg_check_key(struct dlp_gpg *gpg, gpgme_key_t key,
                              GError **error) DLP_NODISCARD;
static bool dlp_gpg_check_subkeys(struct dlp_gpg *gpg, gpgme_subkey_t subkeys,
                                  GError **error) DLP_NODISCARD;
static bool dlp_gpg_check_uids(struct dlp_gpg *gpg, gpgme_user_id_t uids,
                               GError **error) DLP_NODISCARD;
static bool dlp_gpg_check_signatures(struct dlp_gpg *gpg,
                                     gpgme_signature_t sigs,
                                     GError **error) DLP_NODISCARD;
static bool dlp_gpg_change_owner_trust(struct dlp_gpg *gpg, const char *fpr,
                                       gpgme_validity_t trust,
                                       GError **error) DLP_NODISCARD;
static bool dlp_gpg_get_exec(struct dlp_gpg *gpg, const char **path,
                             GError **error) DLP_NODISCARD;
static bool dlp_gpg_data_from_fd(int fd, gpgme_data_t *data,
                                 GError **error) DLP_NODISCARD;
static bool dlp_gpg_data_from_mem(const char *buf, size_t size,
                                  gpgme_data_t *data,
                                  GError **error) DLP_NODISCARD;
static void dlp_gpg_data_release(gpgme_data_t *data);
static bool dlp_gpg_ensure(gpgme_error_t err, GError **error) DLP_NODISCARD;
static void dlp_gpg_set_error(gpgme_error_t err, GError **error);

/**
 * Prepare GPGME for threaded use.
 *
 * See:
 * - https://gnupg.org/documentation/manuals/gpgme/Multi_002dThreading.html
 *
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_global_init(GError **error)
{
    gpgme_error_t err;

    if (gpgme_check_version(NULL) == NULL) {
        dlp_gpg_set_error(GPG_ERR_NOT_INITIALIZED, error);
        return false;
    }

    err = gpgme_engine_check_version(GPGME_PROTOCOL_OPENPGP);
    if (!dlp_gpg_ensure(err, error)) {
        return false;
    }

    return true;
}

/**
 * Initialize a GPG context.
 *
 * The context is initialized in a temporary directory to avoid polluting the
 * users keyring.
 *
 * @param gpg   Context that must be freed with dlp_gpg_free() after use.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_init(struct dlp_gpg **gpg, GError **error)
{
    gpgme_error_t err;

    g_return_val_if_fail(gpg != NULL && *gpg == NULL, false);
    *gpg = dlp_mem_alloc(sizeof(**gpg));

    if (!dlp_fs_mkdtemp(&(*gpg)->home, error)) {
        DLP_DISCARD(dlp_gpg_free(gpg, NULL));
        return false;
    }

    if ((err = gpgme_new(&(*gpg)->ctx)) ||
        (err = gpgme_ctx_set_engine_info((*gpg)->ctx, GPGME_PROTOCOL_OPENPGP,
                                         NULL, (*gpg)->home)) ||
        (err = gpgme_set_protocol((*gpg)->ctx, GPGME_PROTOCOL_OPENPGP)) ||
        (err = gpgme_set_keylist_mode((*gpg)->ctx, GPGME_KEYLIST_MODE_LOCAL)) ||
        (err = gpgme_set_ctx_flag((*gpg)->ctx, "auto-key-retrieve", "0")) ||
        (err = gpgme_set_ctx_flag((*gpg)->ctx, "auto-key-locate", "clear"))) {
        dlp_gpg_set_error(err, error);
        DLP_DISCARD(dlp_gpg_free(gpg, NULL));
        return false;
    }

    return true;
}

/**
 * Free a GPG context.
 *
 * @param gpg   Context to free.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_free(struct dlp_gpg **gpg, GError **error)
{
    bool success = true;

    if (gpg != NULL && *gpg != NULL) {
        if ((*gpg)->ctx != NULL) {
            gpgme_release((*gpg)->ctx);
            (*gpg)->ctx = NULL;
        }

        if ((*gpg)->home != NULL) {
            success = dlp_fs_rmdir((*gpg)->home, error);
            dlp_mem_free(&(*gpg)->home);
        }

        dlp_mem_free(gpg);
    }

    return success;
}

/**
 * Import a key to the keyring.
 *
 * Note that GPGME handles trust levels somewhat interestingly.  The
 * documentation for signature verification suggest that the resulting
 * gpgme_signature_t structure will have its summary member populated.  The
 * summary member is an enum with the gpgme_sigsum_t typedef name [1].
 *
 * The GPGME documentation further explains that a signature is valid without
 * restriction if the GPGME_SIGSUM_VALID flag is set in the summary member [1].
 * If GPGME_SIGSUM_VALID is unset, one has to make a decision based on what
 * flags are set -- e.g. some applications may find expired signatures OK and
 * therefore accept a summary with the GPGME_SIGSUM_KEY_EXPIRED flag.
 *
 * However, the documentation does *not* explain that summary may be set to 0,
 * nor does it explain what conditions causes the summary to be 0.  A value of
 * 0 is also not a named member in the gpgme_sigsum_t enum.
 *
 * Werner Koch said the following on the gnupg-devel ML about the magic summary
 * value 0 over a decade ago [2]:
 *
 * > I already mentioned that this indicates: Not enough information to tell
 * > anything about the validity of the signature.
 *
 * Uhm...  Great, I guess.  In my testing, the summary member is set to 0
 * during signature verification if the key is considered untrusted (e.g. if it
 * has unknown or marginal trust).  But that doesn't necessarily mean that
 * untrusted signatures are the only reason for the summary to be 0.
 *
 * Some applications blindly accept a 0 summary if no other errors occurred.
 * But that seems like a dangerous approach when the behavior is undocumented.
 * Instead, this function requires that a trust level be specified when
 * importing a key in order to avoid relying on undefined behavior during
 * signature verification.
 *
 * See:
 * [1] https://gnupg.org/documentation/manuals/gpgme/Verify.html
 * [2] https://lists.gnupg.org/pipermail/gnupg-devel/2009-October/025408.html
 *
 * @param gpg   GPG context.
 * @param path  Key to import.
 * @param trust Trust level to set for the key.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_import_key(struct dlp_gpg *gpg, const char *path,
                        gpgme_validity_t trust, GError **error)
{
    gpgme_import_result_t res;
    gpgme_import_status_t s;
    gpgme_error_t err;
    gpgme_data_t data = NULL;
    GList *fpr = NULL;
    GList *fprs = NULL;
    void *buf = NULL;
    gsize size = 0;
    int fd = -1;
    bool success = false;

    g_return_val_if_fail(gpg != NULL && path != NULL, false);

    if (dlp_resource_p(path)) {
        if (!dlp_resource_data(path, &buf, &size, error)) {
            goto out;
        }

        if (!dlp_gpg_data_from_mem(buf, size, &data, error)) {
            goto out;
        }
    } else {
        if (!dlp_fs_open(path, O_RDONLY, S_IRUSR, &fd, error)) {
            goto out;
        }

        if (!dlp_gpg_data_from_fd(fd, &data, error)) {
            goto out;
        }
    }

    err = gpgme_op_import(gpg->ctx, data);
    if (!dlp_gpg_ensure(err, error)) {
        goto out;
    }

    res = gpgme_op_import_result(gpg->ctx);
    if (res == NULL) {
        dlp_gpg_set_error(GPG_ERR_INV_OBJ, error);
        goto out;
    }

    if (res->imported <= 0 || res->skipped_v3_keys != 0) {
        dlp_gpg_set_error(GPG_ERR_BAD_KEY, error);
        goto out;
    }

    for (s = res->imports; s != NULL; s = s->next) {
        if (!dlp_gpg_ensure(s->result, error)) {
            goto out;
        }

        /*
         * The gpgme_import_result_t list is only valid until another operation
         * is performed on the context.  While the trust level is currently set
         * without GPGME (since GPGME doesn't seem to support changing trust
         * levels), the fingerprints are still captured in order to avoid
         * future bugs if GPGME ever implements the equivalent of `gpg
         * --import-ownertrust`.
         */
        if (s->fpr == NULL) {
            dlp_gpg_set_error(GPG_ERR_BAD_KEY, error);
            goto out;
        }
        fprs = g_list_prepend(fprs, g_strdup(s->fpr));
    }

    for (fpr = fprs; fpr != NULL; fpr = fpr->next) {
        if (!dlp_gpg_change_owner_trust(gpg, fpr->data, trust, error)) {
            goto out;
        }
    }

    success = true;

out:
    g_list_free_full(fprs, g_free);
    dlp_gpg_data_release(&data);
    dlp_mem_free(&buf);

    return MIN(success, dlp_fs_close(&fd, success ? error : NULL));
}

/**
 * Check that the keyring is in a good state.
 *
 * @param gpg   GPG context.
 * @param count Optional number of keys checked.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_check_keyring(struct dlp_gpg *gpg, rsize_t *count, GError **error)
{
    gpgme_key_t key;
    gpgme_error_t err;
    rsize_t num = 0;

    g_return_val_if_fail(gpg != NULL, false);

    if (count != NULL) {
        *count = 0;
    }

    err = gpgme_op_keylist_start(gpg->ctx, NULL, 0);
    if (!dlp_gpg_ensure(err, error)) {
        return false;
    }

    while ((err = gpgme_op_keylist_next(gpg->ctx, &key)) == GPG_ERR_NO_ERROR) {
        if (!dlp_gpg_check_key(gpg, key, error)) {
            gpgme_key_unref(key);
            gpgme_op_keylist_end(gpg->ctx);
            return false;
        }

        gpgme_key_unref(key);

        if (num >= RSIZE_MAX) {
            gpgme_op_keylist_end(gpg->ctx);
            dlp_gpg_set_error(GPG_ERR_ERANGE, error);
            return false;
        }
        num++;
    }

    /*
     * FIXME: should the keylist operation be ended with on failure?  The
     * documentation mentions that the context is busy until GPG_ERR_EOF is
     * returned from gpgme_op_keylist_next() or gpgme_op_keylist_end() is
     * called.  But it does not mention whether the operation is ended on
     * failure.
     */
    if (gpg_err_code(err) != GPG_ERR_EOF && !dlp_gpg_ensure(err, error)) {
        return false;
    }

    if (count) {
        *count = num;
    }

    return true;
}

/**
 * Verify a message with an attached (clearsign/inline) signature.
 *
 * It is important to note that neither GPG nor GPGME signals an error if
 * unsigned content is encountered in a signature.  The implication for
 * messages that are clearsigned or signed with an inline signature is that it
 * may contain unsigned data outside of the PGP header and/or footer.
 *
 * The `outfd` parameter is a file descriptor used by GPG(ME) to write the
 * signed and verified part of a message with an attached signature -- that is,
 * `outfd` does not include unsigned content before the header or after the
 * footer.  Further processing must use that descriptor instead of `msgfd`.
 *
 * @param gpg   GPG context.
 * @param msgfd A file descriptor with the message to verify.
 * @param outfd A file descriptor to write the verified message.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_verify_attached(struct dlp_gpg *gpg, int msgfd, int outfd,
                             GError **error)
{
    gpgme_data_t msg = NULL;
    gpgme_data_t out = NULL;
    bool success = false;

    g_return_val_if_fail(gpg != NULL && msgfd >= 0 && outfd >= 0, false);

    if (dlp_fs_seek(msgfd, 0, SEEK_SET, error) &&
        dlp_fs_seek(outfd, 0, SEEK_SET, error) &&
        dlp_fs_truncate(outfd, 0, error) &&
        dlp_gpg_data_from_fd(msgfd, &msg, error) &&
        dlp_gpg_data_from_fd(outfd, &out, error) &&
        dlp_gpg_verify(gpg, msg, NULL, out, error) &&
        dlp_fs_seek(msgfd, 0, SEEK_SET, error) &&
        dlp_fs_seek(outfd, 0, SEEK_SET, error)) {
        success = true;
    }

    dlp_gpg_data_release(&out);
    dlp_gpg_data_release(&msg);

    return success;
}

/**
 * Verify a message with a detached signature.
 *
 * It is important to note that neither GPG nor GPGME signals an error if
 * unsigned content is encountered in a signature.  This is primarily an issue
 * for messages signed with an attached signature.  But it could also be
 * problematic for messages signed with a detached signature because it could
 * contain e.g. ANSI escape codes or other malicious content meant to exploit a
 * user being shown the signature in a log message and/or a user that processes
 * a signature file stored on disk.
 *
 * @param gpg   GPG context.
 * @param msgfd A file descriptor with the message to verify.
 * @param sigfd A file descriptor with a detached signature.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
bool dlp_gpg_verify_detached(struct dlp_gpg *gpg, int msgfd, int sigfd,
                             GError **error)
{
    gpgme_data_t msg = NULL;
    gpgme_data_t sig = NULL;
    bool success = false;

    g_return_val_if_fail(gpg != NULL && msgfd >= 0 && sigfd >= 0, false);

    if (dlp_fs_seek(msgfd, 0, SEEK_SET, error) &&
        dlp_fs_seek(sigfd, 0, SEEK_SET, error) &&
        dlp_gpg_data_from_fd(msgfd, &msg, error) &&
        dlp_gpg_data_from_fd(sigfd, &sig, error) &&
        dlp_gpg_verify(gpg, sig, msg, NULL, error) &&
        dlp_fs_seek(msgfd, 0, SEEK_SET, error) &&
        dlp_fs_seek(sigfd, 0, SEEK_SET, error)) {
        success = true;
    }

    dlp_gpg_data_release(&sig);
    dlp_gpg_data_release(&msg);

    return success;
}

/**
 * Perform a signature verification.
 *
 * The `sig`, `signed_text` and `plain` parameters have the same name and
 * purpose as they do in gpgme_op_verify().
 *
 * See:
 * - https://gnupg.org/documentation/manuals/gpgme/Verify.html
 *
 * @param gpg           GPG context.
 * @param sig           Signature to verify.  For messages with an attached
 *                      signature, this is the content and signature.
 * @param signed_text   Message to verify if `sig` is detached.
 * @param plain         Output for messages with an attached signature.
 * @param error         Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_verify(struct dlp_gpg *gpg, gpgme_data_t sig,
                           gpgme_data_t signed_text, gpgme_data_t plain,
                           GError **error)
{
    gpgme_verify_result_t res;
    gpgme_error_t err;

    g_return_val_if_fail(gpg != NULL && sig != NULL, false);

    err = gpgme_op_verify(gpg->ctx, sig, signed_text, plain);
    if (!dlp_gpg_ensure(err, error)) {
        return false;
    }

    res = gpgme_op_verify_result(gpg->ctx);
    if (res == NULL) {
        dlp_gpg_set_error(GPG_ERR_BAD_SIGNATURE, error);
        return false;
    }

    return dlp_gpg_check_signatures(gpg, res->signatures, error);
}

/**
 * Check that a key, including subkeys and uids, looks okay.
 *
 * @param gpg   GPG context.
 * @param key   Key to check.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_check_key(struct dlp_gpg *gpg, gpgme_key_t key,
                              GError **error)
{
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (gpg == NULL || key == NULL) {
        err = GPG_ERR_NO_KEY;
    } else if (key->revoked || key->expired || key->disabled || key->invalid) {
        err = GPG_ERR_BAD_KEY;
    } else if (key->fpr == NULL) {
        err = GPG_ERR_BAD_DATA;
    } else if (key->protocol != GPGME_PROTOCOL_OPENPGP) {
        err = GPG_ERR_UNSUPPORTED_PROTOCOL;
    } else if (key->owner_trust != GPGME_VALIDITY_FULL &&
               key->owner_trust != GPGME_VALIDITY_ULTIMATE) {
        err = GPG_ERR_NOT_TRUSTED;
    } else if (key->keylist_mode != GPGME_KEYLIST_MODE_LOCAL) {
        err = GPG_ERR_INV_KEYRING;
    } else {
        if (!dlp_gpg_check_subkeys(gpg, key->subkeys, error) ||
            !dlp_gpg_check_uids(gpg, key->uids, error)) {
            return false;
        }
    }

    return dlp_gpg_ensure(err, error);
}

/**
 * Check that a linked list of subkeys looks okay.
 *
 * @param gpg     GPG context.
 * @param subkeys Subkeys to check.
 * @param error   Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_check_subkeys(struct dlp_gpg *gpg, gpgme_subkey_t subkeys,
                                  GError **error)
{
    gpgme_subkey_t sk;
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (gpg == NULL || subkeys == NULL) {
        dlp_gpg_set_error(GPG_ERR_NO_KEY, error);
        return false;
    }

    for (sk = subkeys; sk != NULL; sk = sk->next) {
        if (sk->revoked || sk->expired || sk->disabled || sk->invalid) {
            err = GPG_ERR_BAD_KEY;
        } else if (sk->fpr == NULL) {
            err = GPG_ERR_BAD_DATA;
        } else if (sk->timestamp == -1) {
            err = GPG_ERR_INV_TIME;
        } else if (sk->pubkey_algo != GPGME_PK_RSA &&
                   sk->pubkey_algo != GPGME_PK_EDDSA) {
            err = GPG_ERR_PUBKEY_ALGO;
        } else if ((sk->pubkey_algo == GPGME_PK_RSA && sk->length < 4096) ||
                   (sk->pubkey_algo == GPGME_PK_EDDSA && sk->length < 256)) {
            err = GPG_ERR_INV_KEYLEN;
        }

        if (!dlp_gpg_ensure(err, error)) {
            return false;
        }
    }

    return true;
}

/**
 * Check that a linked list of UIDs looks okay.
 *
 * @param gpg   GPG context.
 * @param uids  UIDs to check.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_check_uids(struct dlp_gpg *gpg, gpgme_user_id_t uids,
                               GError **error)
{
    gpgme_user_id_t uid;
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (gpg == NULL || uids == NULL) {
        dlp_gpg_set_error(GPG_ERR_NO_USER_ID, error);
        return false;
    }

    for (uid = uids; uid != NULL; uid = uid->next) {
        if (uid->revoked || uid->invalid) {
            err = GPG_ERR_INV_USER_ID;
        } else if (uid->validity != GPGME_VALIDITY_FULL &&
                   uid->validity != GPGME_VALIDITY_ULTIMATE) {
            err = GPG_ERR_NOT_TRUSTED;
        }

        if (!dlp_gpg_ensure(err, error)) {
            return false;
        }
    }

    return true;
}

/**
 * Check that a linked list of signatures looks okay.
 *
 * See:
 * - https://gnupg.org/documentation/manuals/gpgme/Verify.html
 *
 * @param gpg   GPG context.
 * @param sigs  Signatures to check.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_check_signatures(struct dlp_gpg *gpg,
                                     gpgme_signature_t sigs, GError **error)
{
    gpgme_key_t key;
    gpgme_signature_t s;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    gpgme_sigsum_t valid_sigsum = (gpgme_sigsum_t)(GPGME_SIGSUM_VALID |
                                                   GPGME_SIGSUM_GREEN);
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (gpg == NULL || sigs == NULL) {
        dlp_gpg_set_error(GPG_ERR_BAD_SIGNATURE, error);
        return false;
    }

    for (s = sigs; s != NULL; s = s->next) {
        if (s->status != GPG_ERR_NO_ERROR) {
            err = s->status;
        } else if (s->summary != valid_sigsum) {
            err = GPG_ERR_BAD_SIGNATURE;
        } else if (s->validity != GPGME_VALIDITY_FULL &&
                   s->validity != GPGME_VALIDITY_ULTIMATE) {
            err = GPG_ERR_NOT_TRUSTED;
        } else if (s->validity_reason != GPG_ERR_NO_ERROR) {
            err = s->validity_reason;
        } else if (s->fpr == NULL) {
            err = GPG_ERR_BAD_DATA;
        } else if (s->wrong_key_usage) {
            err = GPG_ERR_BAD_DATA;
        } else if (s->pubkey_algo != GPGME_PK_RSA &&
                   s->pubkey_algo != GPGME_PK_EDDSA) {
            err = GPG_ERR_PUBKEY_ALGO;
        } else if (s->hash_algo != GPGME_MD_SHA512 &&
                   s->hash_algo != GPGME_MD_SHA384 &&
                   s->hash_algo != GPGME_MD_SHA256) {
            err = GPG_ERR_DIGEST_ALGO;
        } else {
            /*
             * There is a key member in gpgme_signature_t that contain
             * information available in the signature.  The documentation
             * states that it may be incomplete or NULL.
             *
             * It seems to always(?) be NULL for OpenPGP signatures made with
             * RSA and EDDSA keys.  But even if not, the incomplete aspect of
             * its content might cause dlp_gpg_check_key() to fail even if the
             * key it refers to is valid.  So the key is retrieved with its
             * fingerprint instead.
             *
             * Checking the key here instead of during context initialization
             * and/or at the end of a key import avoids a race condition if the
             * keyring is modified outside this program.  Now, it's not *that*
             * relevant for DLP since the keyrings are created in temporary
             * directories and are removed when the context is closed, but
             * still...
             *
             * The reason for checking the signing key is to be able to verify
             * its length.
             */
            err = gpgme_get_key(gpg->ctx, s->fpr, &key, 0);
            if (err == GPG_ERR_NO_ERROR) {
                if (!dlp_gpg_check_key(gpg, key, error)) {
                    gpgme_key_unref(key);
                    return false;
                }
                gpgme_key_unref(key);
            }
        }

        if (!dlp_gpg_ensure(err, error)) {
            return false;
        }
    }

    return true;
}

/**
 * Change the owner trust for a key.
 *
 * GPGME does not seem to provide an API for changing the owner trust, so
 * GPG is executed directly.  See dlp_gpg_import_key() for the reason behind
 * changing the owner trust.
 *
 * @param gpg   GPG context.
 * @param fpr   Fingerprint for which to change owner trust.
 * @param trust Trust level.  Currently only 'ultimate' is supported.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_change_owner_trust(struct dlp_gpg *gpg, const char *fpr,
                                       gpgme_validity_t trust, GError **error)
{
    GSubprocess *proc;
    const char *exec;
    uint8_t num;
    char *err = NULL;
    char *in = NULL;
    GSubprocessFlags flags;
    bool success = false;

    g_return_val_if_fail(gpg != NULL && fpr != NULL, false);

    if (!dlp_gpg_get_exec(gpg, &exec, error)) {
        goto out;
    }

    if (trust == GPGME_VALIDITY_ULTIMATE) {
        num = 6;
    } else {
        dlp_gpg_set_error(GPG_ERR_EINVAL, error);
        goto out;
    }
    in = g_strdup_printf("%s:%u:\n", fpr, num);

    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    flags = (GSubprocessFlags)(G_SUBPROCESS_FLAGS_STDIN_PIPE |
                               G_SUBPROCESS_FLAGS_STDOUT_SILENCE |
                               G_SUBPROCESS_FLAGS_STDERR_PIPE);
    if ((proc = g_subprocess_new(flags, error, exec, "--homedir", gpg->home,
                                 "--import-ownertrust", NULL)) == NULL) {
        goto out;
    }

    if (!g_subprocess_communicate_utf8(proc, in, NULL, NULL, &err, error)) {
        goto out;
    }

    if (!g_subprocess_wait_check(proc, NULL, error)) {
        g_prefix_error(error, "%s", err ? err : exec);
        goto out;
    }

    success = true;

out:
    dlp_mem_free(&in);
    dlp_mem_free(&err);
    return success;
}

/**
 * Retrieve the path to the GPG executable used by GPGME.
 *
 * @param gpg   GPG context.
 * @param path  Path to the GPG executable.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_get_exec(struct dlp_gpg *gpg, const char **path,
                             GError **error)
{
    gpgme_engine_info_t info;

    g_return_val_if_fail(gpg != NULL && path != NULL, false);
    *path = NULL;

    if (gpgme_get_protocol(gpg->ctx) != GPGME_PROTOCOL_OPENPGP) {
        dlp_gpg_set_error(GPG_ERR_UNSUPPORTED_PROTOCOL, error);
        return false;
    }

    info = gpgme_ctx_get_engine_info(gpg->ctx);

    for (; info != NULL; info = info->next) {
        if (info->protocol == GPGME_PROTOCOL_OPENPGP) {
            if (info->file_name == NULL) {
                dlp_gpg_set_error(GPG_ERR_ENOEXEC, error);
                return false;
            }

            if (!dlp_fs_check_path(info->file_name, DLP_FS_REG, true, error)) {
                return false;
            }

            *path = info->file_name;
            return true;
        }
    }

    dlp_gpg_set_error(GPG_ERR_ENOEXEC, error);
    return false;
}

/**
 * Helper around gpgme_data_new_from_fd().
 *
 * @param fd    File descriptor to base the data object on.
 * @param data  Newly created data object, or NULL on failure.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_data_from_fd(int fd, gpgme_data_t *data, GError **error)
{
    gpgme_error_t err;

    g_return_val_if_fail(fd >= 0 && data != NULL, false);

    err = gpgme_data_new_from_fd(data, fd);
    if (!dlp_gpg_ensure(err, error)) {
        *data = NULL;
        return false;
    }

    return true;
}

/**
 * Helper around gpgme_data_new_from_mem().
 *
 * @param buf   Buffer for the data object.  It is copied by GPGME so it may be
 *              freed before the data object is released.
 * @param size  Size of the buffer.
 * @param data  Newly created data object, or NULL on failure.
 * @param error Optional error information.
 * @return True on success and false on failure.
 */
static bool dlp_gpg_data_from_mem(const char *buf, size_t size,
                                  gpgme_data_t *data, GError **error)
{
    gpgme_error_t err;

    g_return_val_if_fail(buf != NULL && size > 0 && data != NULL, false);

    err = gpgme_data_new_from_mem(data, buf, size, 1);
    if (!dlp_gpg_ensure(err, error)) {
        *data = NULL;
        return false;
    }

    return true;
}

/**
 * Helper around gpgme_data_release().
 *
 * @param data Object to release, or NULL for a noop.
 */
static void dlp_gpg_data_release(gpgme_data_t *data)
{
    if (data != NULL && *data != NULL) {
        gpgme_data_release(*data);
        *data = NULL;
    }
}

/**
 * Ensure that a GPG operation succeeded.
 *
 * @param err   Return value to check.
 * @param error Optional error information.
 * @return True if no erroneous condition happened, false otherwise.
 */
static bool dlp_gpg_ensure(gpgme_error_t err, GError **error)
{
    if (err != GPG_ERR_NO_ERROR) {
        dlp_gpg_set_error(err, error);
        return false;
    }
    return true;
}

/**
 * Construct an error message.
 *
 * @param err   GPG error.
 * @param error Optional error information.
 */
static void dlp_gpg_set_error(gpgme_error_t err, GError **error)
{
    char buf[4096] = { '\0' };
    int code;

    if (dlp_overflow_add(gpg_err_code(err), 0, &code)) {
        code = DLP_GPG_ERROR_FAILED;
    }

    if (gpgme_strerror_r(err, buf, sizeof(buf) - 1) != 0) {
        g_set_error(error, DLP_ERROR, code, "%s", g_strerror(ERANGE));
    } else {
        g_set_error(error, DLP_ERROR, code, "%s", buf);
    }
}

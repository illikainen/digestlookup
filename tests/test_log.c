/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "config.h"
#include "dlp_log.h"
#include "test.h"

static void test_log_verbosity(void)
{
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_test_trap_subprocess("/log/verbosity/subprocess/funcall-enable", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG:*enabled*");

    g_test_trap_subprocess("/log/verbosity/subprocess/funcall-disable", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout_unmatched("DEBUG:*enabled*");

    g_test_trap_subprocess("/log/verbosity/subprocess/env-enable-all", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG:*enabled*");

    g_test_trap_subprocess("/log/verbosity/subprocess/env-disable-all", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG:*enabled*");

    g_test_trap_subprocess("/log/verbosity/subprocess/env-enable-domain", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG:*enabled*");

    g_test_trap_subprocess("/log/verbosity/subprocess/env-bogus-domain", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout_unmatched("DEBUG:*enabled*");
}

static void test_log_verbosity_funcall_enable(void)
{
    g_unsetenv("G_MESSAGES_DEBUG");
    dlp_log_set_verbosity(true);

    g_debug("enabled");
}

static void test_log_verbosity_funcall_disable(void)
{
    g_unsetenv("G_MESSAGES_DEBUG");
    dlp_log_set_verbosity(false);

    g_debug("enabled");
}

static void test_log_verbosity_env_enable_all(void)
{
    dlp_log_set_verbosity(false);
    g_assert_true(g_setenv("G_MESSAGES_DEBUG", "all", 1));
    g_debug("enabled");
}

static void test_log_verbosity_env_disable_all(void)
{
    dlp_log_set_verbosity(true);
    g_unsetenv("G_MESSAGES_DEBUG");
    g_debug("enabled");
}

static void test_log_verbosity_env_enable_domain(void)
{
    dlp_log_set_verbosity(false);
    g_assert_true(g_setenv("G_MESSAGES_DEBUG", PROJECT_NAME, 1));
    g_debug("enabled");
}

static void test_log_verbosity_env_bogus_domain(void)
{
    dlp_log_set_verbosity(false);
    g_assert_true(g_setenv("G_MESSAGES_DEBUG", "foobar123", 1));
    g_debug("enabled");
}

static void test_log_sanitize(void)
{
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-debug", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG: *: _[31mfoo_[0m\n");

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-message", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("_[31mfoo_[0m\n");

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-info", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("INFO: _[31mfoo_[0m\n");

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-warning", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("WARNING: _[31mfoo_[0m\n");

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-critical", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("ERROR: _[31mfoo_[0m\n");

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-print", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("_[31mfoo_[0m\n");

    g_test_trap_subprocess("/log/sanitize/subprocess/escape-printerr", 0,
                           flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("_[31mfoo_[0m\n");

    if (test_wrap_p()) {
        g_test_trap_subprocess("/log/sanitize/subprocess/escape-print-wrap", 0,
                               flags);
        g_test_trap_assert_passed();

        g_test_trap_subprocess("/log/sanitize/subprocess/escape-printerr-wrap",
                               0, flags);
        g_test_trap_assert_passed();
    }
}

static void test_log_sanitize_escape_debug(void)
{
    dlp_log_set_verbosity(true);

    g_debug("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_info(void)
{
    g_info("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_message(void)
{
    g_message("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_warning(void)
{
    g_warning("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_critical(void)
{
    g_critical("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_print(void)
{
    g_print("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_print_wrap(void)
{
    if (test_wrap_p()) {
        test_wrap_push(g_strdup, true, NULL);
        g_print("\033[31mfoo\033[0m");
    }
}

static void test_log_sanitize_escape_printerr(void)
{
    g_printerr("\033[31mfoo\033[0m");
}

static void test_log_sanitize_escape_printerr_wrap(void)
{
    if (test_wrap_p()) {
        test_wrap_push(g_strdup, true, NULL);
        g_printerr("\033[31mfoo\033[0m");
    }
}

static void test_log_file(void)
{
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_test_trap_subprocess("/log/file/subprocess/separator", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG: bar.c:123:baz(): qux\n");

    g_test_trap_subprocess("/log/file/subprocess/no-separator", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout("DEBUG: foo.c:123:bar(): baz\n");
}

static void test_log_file_separator(void)
{
    dlp_log_set_verbosity(true);

    g_log_structured(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "CODE_FILE", "foo/bar.c",
                     "CODE_LINE", "123", "CODE_FUNC", "baz", "MESSAGE", "qux");
}

static void test_log_file_no_separator(void)
{
    dlp_log_set_verbosity(true);

    g_log_structured(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "CODE_FILE", "foo.c",
                     "CODE_LINE", "123", "CODE_FUNC", "bar", "MESSAGE", "baz");
}

static void test_log_msg(void)
{
    GTestSubprocessFlags flags = (GTestSubprocessFlags)0;

    g_test_trap_subprocess("/log/msg/subprocess/empty", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout_unmatched("*(nil)*");
    g_test_trap_assert_stdout_unmatched("*(null)*");
    g_test_trap_assert_stdout("*<empty>*");

    g_test_trap_subprocess("/log/msg/subprocess/partly-empty", 0, flags);
    g_test_trap_assert_passed();
    g_test_trap_assert_stdout_unmatched("*(nil)*");
    g_test_trap_assert_stdout_unmatched("*(null)*");
    g_test_trap_assert_stdout("*<empty>*");
}

static void test_log_msg_empty(void)
{
    dlp_log_set_verbosity(true);

    g_log_structured(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "MESSAGE", NULL);
}

static void test_log_msg_partly_empty(void)
{
    dlp_log_set_verbosity(true);

    g_log_structured(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "CODE_FILE", "foo.c",
                     "CODE_LINE", "123", "CODE_FUNC", "bar", "MESSAGE", NULL);
}

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

    g_test_add_func("/log/verbosity", test_log_verbosity);
    g_test_add_func("/log/verbosity/subprocess/funcall-enable",
                    test_log_verbosity_funcall_enable);
    g_test_add_func("/log/verbosity/subprocess/funcall-disable",
                    test_log_verbosity_funcall_disable);
    g_test_add_func("/log/verbosity/subprocess/env-enable-all",
                    test_log_verbosity_env_enable_all);
    g_test_add_func("/log/verbosity/subprocess/env-disable-all",
                    test_log_verbosity_env_disable_all);
    g_test_add_func("/log/verbosity/subprocess/env-enable-domain",
                    test_log_verbosity_env_enable_domain);
    g_test_add_func("/log/verbosity/subprocess/env-bogus-domain",
                    test_log_verbosity_env_bogus_domain);
    g_test_add_func("/log/sanitize", test_log_sanitize);
    g_test_add_func("/log/sanitize/subprocess/escape-debug",
                    test_log_sanitize_escape_debug);
    g_test_add_func("/log/sanitize/subprocess/escape-info",
                    test_log_sanitize_escape_info);
    g_test_add_func("/log/sanitize/subprocess/escape-message",
                    test_log_sanitize_escape_message);
    g_test_add_func("/log/sanitize/subprocess/escape-warning",
                    test_log_sanitize_escape_warning);
    g_test_add_func("/log/sanitize/subprocess/escape-critical",
                    test_log_sanitize_escape_critical);
    g_test_add_func("/log/sanitize/subprocess/escape-print",
                    test_log_sanitize_escape_print);
    g_test_add_func("/log/sanitize/subprocess/escape-print-wrap",
                    test_log_sanitize_escape_print_wrap);
    g_test_add_func("/log/sanitize/subprocess/escape-printerr",
                    test_log_sanitize_escape_printerr);
    g_test_add_func("/log/sanitize/subprocess/escape-printerr-wrap",
                    test_log_sanitize_escape_printerr_wrap);
    g_test_add_func("/log/file", test_log_file);
    g_test_add_func("/log/file/subprocess/separator", test_log_file_separator);
    g_test_add_func("/log/file/subprocess/no-separator",
                    test_log_file_no_separator);
    g_test_add_func("/log/msg", test_log_msg);
    g_test_add_func("/log/msg/subprocess/empty", test_log_msg_empty);
    g_test_add_func("/log/msg/subprocess/partly-empty",
                    test_log_msg_partly_empty);

    g_test_init(&argc, &argv, NULL);

    return g_test_run();
}

/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_log.h"
#include "test.h"

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

int main(int argc, char **argv)
{
    g_assert_true(setenv("G_TEST_SRCDIR", PROJECT_DIR, 1) == 0);
    g_assert_true(setenv("G_TEST_BUILDDIR", BUILD_DIR, 1) == 0);

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
    g_test_add_func("/log/file", test_log_file);
    g_test_add_func("/log/file/subprocess/separator", test_log_file_separator);
    g_test_add_func("/log/file/subprocess/no-separator",
                    test_log_file_no_separator);

    g_test_init(&argc, &argv, NULL);

    return g_test_run();
}

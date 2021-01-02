include(AddWraps)
include(CopyProperties)

set(qa "${PROJECT_SOURCE_DIR}/cmake/QA.cmake")

file(GLOB_RECURSE fixtures
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "fixture_*.c")

file(GLOB_RECURSE tests
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test_*.c")

file(GLOB_RECURSE fuzz
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "fuzz_*.c")

file(GLOB_RECURSE lib
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test.c" "dlp_*.c")

set(environ
    G_DEBUG=fatal-warnings
    G_MESSAGES_DEBUG=all
    LSAN_OPTIONS=report_objects=1)

#
# Test library.
#
add_library(test_obj OBJECT ${lib})
target_compile_definitions(test_obj
    PUBLIC PROJECT_DIR="${PROJECT_SOURCE_DIR}"
    PUBLIC BUILD_DIR="${PROJECT_BINARY_DIR}")
target_link_libraries(test_obj
    PUBLIC ${PROJECT_NAME}_obj)

# Clang CFI requires LTO.  However, symbol wrapping in BFD 2.31.1 seems broken
# in LTO builds; but gold (ELF-only) works with Clang.  GCC doesn't seem to
# play well with either gold or BFD.
#
# See:
# - https://bugzilla.redhat.com/show_bug.cgi?id=1693831
# - https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88643
# - https://sourceware.org/bugzilla/show_bug.cgi?id=24406
if(UNIX AND CMAKE_C_COMPILER_ID STREQUAL Clang)
    target_compile_definitions(test_obj PUBLIC TEST_WRAP)
    target_link_options(test_obj PUBLIC -fuse-ld=gold)
    add_wraps(test_obj PUBLIC test.c)
endif()

#
# Dependencies.
#
add_pkg_config(TARGET test_obj SCOPE INTERFACE PKG cmocka REQUIRED)
add_pkg_config(TARGET test_obj SCOPE INTERFACE PKG libmicrohttpd REQUIRED)

#
# Fixtures.
#
add_test("fixture_gcov_cleanup" "${CMAKE_COMMAND}"
    -D "QA_ACTION=gcov-cleanup"
    -D "QA_GCOV_COMPILER=${CMAKE_C_COMPILER_ID}"
    -P "${qa}")
set_tests_properties("fixture_gcov_cleanup" PROPERTIES
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}"
    FIXTURES_CLEANUP "fixture_gcov_cleanup")

foreach(file ${fixtures})
    string(REGEX REPLACE "/" "-" bin "${file}")
    string(REGEX REPLACE "\.c$" "" bin "${bin}")

    add_executable("${bin}" "${file}")
    target_link_libraries("${bin}" PRIVATE test_obj)
    copy_properties("${bin}" PRIVATE test_obj)

    foreach(stage SETUP CLEANUP)
        string(TOLOWER "${bin}_${stage}" name)
        add_test("${name}" "${bin}")
        set(env ${environ}
            "FIXTURE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "FIXTURE_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "FIXTURE_${stage}=1")
        set_tests_properties("${name}" PROPERTIES
            ENVIRONMENT "${env}"
            FIXTURES_${stage} "${name}")
    endforeach()
endforeach()

#
# Tests.
#
foreach(file ${tests})
    string(REGEX REPLACE "/" "-" bin ${file})
    string(REGEX REPLACE "\.c$" "" bin ${bin})
    string(REGEX REPLACE "^(fuzz|test)_" "" name "${bin}")
    set(fixture "fixture_${name}")

    add_executable("${bin}" "${file}")
    add_test("${bin}" "${CMAKE_COMMAND}"
        -D "QA_ACTION=test"
        -D "QA_TEST_CWD=${CMAKE_CURRENT_BINARY_DIR}"
        -D "QA_TEST_CMD=${bin}"
        -P "${qa}")

    set(env ${environ} "LLVM_PROFILE_FILE=${bin}-%m%c.profraw")
    set(fixtures
        "${fixture}_setup"
        "${fixture}_cleanup"
        "fixture_gcov_cleanup")
    set_tests_properties("${bin}" PROPERTIES
        ENVIRONMENT "${env}"
        FIXTURES_REQUIRED "${fixtures}")
    copy_properties("${bin}" PRIVATE test_obj)
    target_link_libraries("${bin}" PRIVATE test_obj)
endforeach()

#
# Fuzz targets.
#
if(CMAKE_C_COMPILER_ID STREQUAL Clang AND ${CMAKE_BUILD_TYPE} STREQUAL Debug)
    foreach(file ${fuzz})
        string(REGEX REPLACE "/" "-" bin "${file}")
        string(REGEX REPLACE "\.c$" "" bin "${bin}")
        string(REGEX REPLACE "^(fuzz|test)_" "" name "${bin}")
        set(corpus "${PROJECT_BINARY_DIR}/tests/data/${name}")
        set(fixture "fixture_${name}")

        add_executable("${bin}" "${file}")
        add_test("${bin}" "${CMAKE_COMMAND}"
            -D "QA_ACTION=fuzz"
            -D "QA_FUZZ_CWD=${CMAKE_CURRENT_BINARY_DIR}"
            -D "QA_FUZZ_CMD=${bin}"
            -D "QA_FUZZ_CORPUS=${corpus}"
            -P "${qa}")

        set(env ${environ} "LLVM_PROFILE_FILE=${bin}-%m%c.profraw")
        set(fixtures
            "${fixture}_setup"
            "${fixture}_cleanup"
            "fixture_gcov_cleanup")
        set_tests_properties("${bin}" PROPERTIES
            ENVIRONMENT "${env}"
            FIXTURES_REQUIRED "${fixtures}")
        copy_properties("${bin}" PRIVATE "test_obj")
        target_compile_options("${bin}" PRIVATE -fsanitize=fuzzer)
        target_link_options("${bin}" PRIVATE -fsanitize=fuzzer)
        target_link_libraries("${bin}" PRIVATE test_obj)
    endforeach()
endif()

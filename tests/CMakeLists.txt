include(AddWraps)

file(GLOB_RECURSE tests
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test_*.c")

file(GLOB_RECURSE utils
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test.c" "dlp_*.c")

#
# Static test library.
#
add_library(${PROJECT_NAME}_test_static STATIC ${utils})
target_compile_definitions(${PROJECT_NAME}_test_static
    PUBLIC PROJECT_DIR="${PROJECT_SOURCE_DIR}"
    PUBLIC BUILD_DIR="${PROJECT_BINARY_DIR}")
target_link_libraries(${PROJECT_NAME}_test_static PUBLIC ${PROJECT_NAME}_static)

# Clang CFI requires LTO.  However, symbol wrapping in BFD 2.31.1 seems broken
# in LTO builds; but gold (ELF-only) works with Clang.  GCC doesn't seem to
# play well with either gold or BFD.
#
# See:
# - https://bugzilla.redhat.com/show_bug.cgi?id=1693831
# - https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88643
# - https://sourceware.org/bugzilla/show_bug.cgi?id=24406
if(UNIX AND CMAKE_C_COMPILER_ID STREQUAL Clang)
    target_compile_definitions(${PROJECT_NAME}_test_static PUBLIC TEST_WRAP)
    target_link_options(${PROJECT_NAME}_test_static PUBLIC -fuse-ld=gold)
    add_wraps(${PROJECT_NAME}_test_static PUBLIC test.c)
endif()

#
# Dependencies.
#
add_pkg_config(TARGET ${PROJECT_NAME}_test_static PKG cmocka REQUIRED)
add_pkg_config(TARGET ${PROJECT_NAME}_test_static PKG libmicrohttpd REQUIRED)

#
# Tests.
#
foreach(test ${tests})
    string(REGEX REPLACE "/" "-" test_bin ${test})
    string(REGEX REPLACE "\.c$" "" test_bin ${test_bin})

    add_executable(${test_bin} ${test})
    add_test(${test_bin} ${test_bin})
    target_link_libraries(${test_bin} PRIVATE ${PROJECT_NAME}_test_static)
    set_tests_properties(${test_bin} PROPERTIES
        ENVIRONMENT G_DEBUG=fatal-warnings)
endforeach()

include(AddWraps)

file(GLOB_RECURSE tests
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test_*.c")

file(GLOB_RECURSE lib
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test.c" "dlp_*.c")

#
# Test library.
#
add_library(test_obj OBJECT ${lib})
target_compile_definitions(test_obj
    PUBLIC PROJECT_DIR="${PROJECT_SOURCE_DIR}"
    PUBLIC BUILD_DIR="${PROJECT_BINARY_DIR}")

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
# Tests.
#
foreach(test ${tests})
    string(REGEX REPLACE "/" "-" test_bin ${test})
    string(REGEX REPLACE "\.c$" "" test_bin ${test_bin})

    add_executable(${test_bin} ${test})
    add_test(${test_bin} ${test_bin})
    set(env
        G_DEBUG=fatal-warnings
        G_MESSAGES_DEBUG=all
        LLVM_PROFILE_FILE=${test_bin}-%m%c.profraw
        LSAN_OPTIONS=report_objects=1)
    set_tests_properties(${test_bin} PROPERTIES ENVIRONMENT "${env}")

    # See:
    # - https://gitlab.kitware.com/cmake/cmake/-/issues/14778
    # - https://gitlab.kitware.com/cmake/cmake/-/issues/18010
    # - https://gitlab.kitware.com/cmake/cmake/-/issues/18090
    target_include_directories(${test_bin}
        PRIVATE $<TARGET_PROPERTY:test_obj,INTERFACE_INCLUDE_DIRECTORIES>)
    target_compile_definitions(${test_bin}
        PRIVATE $<TARGET_PROPERTY:test_obj,INTERFACE_COMPILE_DEFINITIONS>)
    target_compile_options(${test_bin}
        PRIVATE $<TARGET_PROPERTY:test_obj,INTERFACE_COMPILE_OPTIONS>)
    target_link_options(${test_bin}
        PRIVATE $<TARGET_PROPERTY:test_obj,INTERFACE_LINK_OPTIONS>)
    target_link_libraries(${test_bin}
        PRIVATE $<TARGET_PROPERTY:test_obj,INTERFACE_LINK_LIBRARIES>
        PRIVATE test_obj
        PRIVATE ${PROJECT_NAME}_obj)
endforeach()

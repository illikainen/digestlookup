file(GLOB_RECURSE tests
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test_*.c")

file(GLOB_RECURSE utils
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test.c" "dlp_*.c")

# Clang CFI requires LTO.  However, LTO seems incompatible with symbol wrapping
# in GNU ld [1][2].
#
# LD_PRELOAD also seems broken with CFI, but CFI (and other sanitizers) can be
# disabled for only the preload library.  So, LD_PRELOAD is currently used for
# mocking.  Meh...
#
# See:
# [1] https://bugzilla.redhat.com/show_bug.cgi?id=1693831
# [2] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88643
list(REMOVE_ITEM utils "dlp_preload.c")
set(preload ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}_preload.so)
add_library(${PROJECT_NAME}_preload SHARED dlp_preload.c)
target_compile_definitions(${PROJECT_NAME}_preload
    PRIVATE -D_GNU_SOURCE)
target_compile_options(${PROJECT_NAME}_preload
    PRIVATE -fvisibility=default)
if(CMAKE_C_COMPILER_ID STREQUAL Clang)
    target_compile_options(${PROJECT_NAME}_preload
        PRIVATE -fno-sanitize=address -fno-sanitize=cfi -fno-sanitize=undefined)
endif()
target_link_options(${PROJECT_NAME}_preload
    PRIVATE -Wl,-z,undefs)

#
# Static test library.
#
add_library(${PROJECT_NAME}_test_static STATIC ${utils})
target_compile_definitions(${PROJECT_NAME}_test_static
    PUBLIC PROJECT_DIR="${PROJECT_SOURCE_DIR}"
    PUBLIC BUILD_DIR="${PROJECT_BINARY_DIR}")
target_link_libraries(${PROJECT_NAME}_test_static PUBLIC ${PROJECT_NAME}_static)

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
        ENVIRONMENT G_DEBUG=fatal-warnings
        ENVIRONMENT LD_PRELOAD=${preload})
endforeach()

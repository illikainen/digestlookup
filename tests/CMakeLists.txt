pkg_check_modules(CMOCKA cmocka)
if(NOT CMOCKA_FOUND)
    message(FATAL_ERROR "Cannot find cmocka")
endif()

pkg_check_modules(LIBMICROHTTPD libmicrohttpd)
if(NOT LIBMICROHTTPD_FOUND)
    message(FATAL_ERROR "Cannot find libmicrohttpd")
endif()

file(GLOB_RECURSE tests
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test_*.c")

file(GLOB_RECURSE utils
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "dlp_*.c")

add_library(${PROJECT_NAME}_test_static STATIC ${utils})
target_compile_definitions(${PROJECT_NAME}_test_static
    PUBLIC PROJECT_DIR="${PROJECT_SOURCE_DIR}")
target_include_directories(${PROJECT_NAME}_test_static
    SYSTEM PUBLIC ${CMOCKA_INCLUDE_DIRS}
    SYSTEM PUBLIC ${LIBMICROHTTPD_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}_test_static
    PUBLIC ${PROJECT_NAME}_static
    PUBLIC ${CMOCKA_LINK_LIBRARIES}
    PUBLIC ${LIBMICROHTTPD_LINK_LIBRARIES})

foreach(test ${tests})
    string(REGEX REPLACE "/" "-" test_bin ${test})
    string(REGEX REPLACE "\.c$" "" test_bin ${test_bin})

    add_executable(${test_bin} ${test})
    add_test(${test_bin} ${test_bin})
    target_link_libraries(${test_bin} PRIVATE ${PROJECT_NAME}_test_static)
    set_tests_properties(${test_bin} PROPERTIES
        ENVIRONMENT G_DEBUG=fatal-warnings)
endforeach()

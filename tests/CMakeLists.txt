pkg_check_modules(CMOCKA cmocka)
if(NOT CMOCKA_FOUND)
    message(FATAL_ERROR "Cannot find cmocka")
endif()

file(GLOB_RECURSE tests
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "test_*.c")

foreach(test ${tests})
    string(REGEX REPLACE "/" "-" test_bin ${test})
    string(REGEX REPLACE "\.c$" "" test_bin ${test_bin})

    add_executable(${test_bin} ${test})
    add_test(${test_bin} ${test_bin})
    target_compile_definitions(${test_bin}
        PRIVATE PROJECT_DIR="${PROJECT_SOURCE_DIR}")
    target_include_directories(${test_bin}
        SYSTEM PRIVATE ${CMOCKA_INCLUDE_DIRS})
    target_link_libraries(${test_bin}
        PRIVATE ${PROJECT_NAME}_static
        PRIVATE ${CMOCKA_LINK_LIBRARIES})
endforeach()

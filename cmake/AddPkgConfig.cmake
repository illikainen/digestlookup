# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

include(FindPkgConfig)

function(add_pkg_config)
    cmake_parse_arguments(ARGS "REQUIRED" "TARGET;PKG;SCOPE" "" "${ARGN}")

    set(mode "STATUS")
    if(ARGS_REQUIRED)
        set(mode "FATAL_ERROR")
    endif()

    set(scope "PRIVATE")
    if(ARGS_SCOPE)
        set(scope "${ARGS_SCOPE}")
    endif()

    pkg_check_modules(PKG ${ARGS_PKG})
    if(NOT PKG_FOUND)
        message("${mode}" "Cannot find ${ARGS_PKG}")
        return()
    endif()

    if(ARGS_TARGET)
        if(PKG_INCLUDE_DIRS)
            target_include_directories("${ARGS_TARGET}" SYSTEM
                "${scope}" "${PKG_INCLUDE_DIRS}")
        endif()
        if(PKG_CFLAGS)
            target_compile_options("${ARGS_TARGET}"
                "${scope}" "${PKG_CFLAGS}")
        endif()
        if(PKG_LINK_LIBRARIES)
            target_link_libraries("${ARGS_TARGET}"
                "${scope}" "${PKG_LINK_LIBRARIES}")
        endif()
    else()
        if(PKG_INCLUDE_DIRS)
            include_directories(SYSTEM "${PKG_INCLUDE_DIRS}")
        endif()
        if(PKG_CFLAGS)
            add_compile_options("${PKG_CFLAGS}")
        endif()
        if(PKG_LINK_LIBRARIES)
            link_libraries("${PKG_LINK_LIBRARIES}")
        endif()
    endif()

    message(STATUS "Found ${ARGS_PKG}")
endfunction()

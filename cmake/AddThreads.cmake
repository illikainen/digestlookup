# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

include(FindThreads)

function(add_threads)
    cmake_parse_arguments(ARGS "REQUIRED" "TARGET;PKG;SCOPE" "" "${ARGN}")

    set(mode "STATUS")
    if(ARGS_REQUIRED)
        set(mode "FATAL_ERROR")
    endif()

    set(scope "PRIVATE")
    if(ARGS_SCOPE)
        set(scope "${ARGS_SCOPE}")
    endif()

    if(NOT CMAKE_THREAD_LIBS_INIT)
        message("${mode}" "Cannot find thread library")
        return()
    endif()

    if(ARGS_TARGET)
        target_link_libraries("${ARGS_TARGET}" "${CMAKE_THREAD_LIBS_INIT}")
    else()
        link_libraries("${CMAKE_THREAD_LIBS_INIT}")
    endif()
endfunction()

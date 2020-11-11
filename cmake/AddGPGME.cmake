# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

function(add_gpgme)
    cmake_parse_arguments(ARGS "REQUIRED" "TARGET;PKG;SCOPE;THREAD"
        "" "${ARGN}")

    set(mode "STATUS")
    if(ARGS_REQUIRED)
        set(mode "FATAL_ERROR")
    endif()

    set(scope "PRIVATE")
    if(ARGS_SCOPE)
        set(scope "${ARGS_SCOPE}")
    endif()

    find_program(gpgme_config gpgme-config)
    if(NOT gpgme_config)
        message("${mode}" "GPGME: cannot find gpgme-config")
        return()
    endif()

    if(ARGS_THREAD)
        execute_process(
            COMMAND ${gpgme_config} --cflags --thread=${ARGS_THREAD}
            RESULT_VARIABLE gpgme_cflags_rc
            OUTPUT_VARIABLE gpgme_cflags
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND ${gpgme_config} --libs --thread=${ARGS_THREAD}
            RESULT_VARIABLE gpgme_libs_rc
            OUTPUT_VARIABLE gpgme_libs
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else()
        execute_process(
            COMMAND ${gpgme_config} --cflags
            RESULT_VARIABLE gpgme_cflags_rc
            OUTPUT_VARIABLE gpgme_cflags
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND ${gpgme_config} --libs
            RESULT_VARIABLE gpgme_libs_rc
            OUTPUT_VARIABLE gpgme_libs
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()

    if(gpgme_cflags_rc OR gpgme_libs_rc)
        message("${mode}" "GPGME: ${gpgme_config} failed")
        return()
    endif()

    if(ARGS_TARGET)
        if(gpgme_cflags)
            target_compile_options("${ARGS_TARGET}" "${gpgme_cflags}")
        endif()
        if(gpgme_libs)
            target_link_libraries("${ARGS_TARGET}" "${gpgme_libs}")
        endif()
    else()
        if(gpgme_cflags)
            add_compile_options("${gpgme_cflags}")
        endif()
        if(gpgme_libs)
            link_libraries("${gpgme_libs}")
        endif()
    endif()

    message(STATUS "Found GPGME")
endfunction()

# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

include(AddPkgConfig)

function(add_glib)
    cmake_parse_arguments(ARGS "REQUIRED;GIO;LOG_USE_STRUCTURED"
        "TARGET;SCOPE;LOG_DOMAIN" "" "${ARGN}")

    add_pkg_config(PKG glib-2.0 ${ARGN})
    if(ARGS_GIO)
        add_pkg_config(PKG gio-2.0 ${ARGN})
    endif()

    set(scope "PRIVATE")
    if(ARGS_SCOPE)
        set(scope "${ARGS_SCOPE}")
    endif()

    foreach(name LOG_USE_STRUCTURED LOG_DOMAIN)
        if(ARGS_${name})
            if(ARGS_${name} STREQUAL "TRUE")
                set(def "G_${name}=1")
            else()
                set(def "G_${name}=\"${ARGS_${name}}\"")
            endif()

            if(ARGS_TARGET)
                target_compile_definitions("${ARGS_TARGET}" "${scope}" "${def}")
            else()
                add_compile_definitions("${ARGS_TARGET}" "${def}")
            endif()
        endif()
    endforeach()
endfunction()

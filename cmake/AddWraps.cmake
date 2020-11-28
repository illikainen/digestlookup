# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

# The value of CMAKE_CURRENT_LIST_FILE differs depending on whether it's
# referenced while processing a file or if it's referenced in a function or
# macro.
set(ADD_WRAPS_FILE "${CMAKE_CURRENT_LIST_FILE}")

function(add_wraps target scope file)
    file(READ "${file}" content)
    string(REGEX MATCHALL "(\n| \\*?)__wrap_[^ \t(]+" wraps ${content})
    list(REMOVE_DUPLICATES wraps)

    foreach(wrap ${wraps})
        string(REGEX REPLACE ".*__wrap_" "" fn "${wrap}")
        target_link_options("${target}" "${scope}" "-Wl,--wrap=${fn}")
    endforeach()

    # This is a complete hack to rebuild the link options if `file` changes.
    get_filename_component(name "${file}" NAME_WE)
    if(NOT TARGET "add-wraps-${name}")
        add_custom_command(
            COMMAND "${CMAKE_COMMAND}" -E touch "${ADD_WRAPS_FILE}"
            OUTPUT "${ADD_WRAPS_FILE}"
            DEPENDS "${file}"
            VERBATIM
        )
        add_custom_target(
            "add-wraps-${name}"
            DEPENDS "${ADD_WRAPS_FILE}"
        )
        add_dependencies("${target}" "add-wraps-${name}")
    endif()
endfunction()

# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

function(add_wraps target scope file)
    file(READ "${file}" content)
    string(REGEX MATCHALL "(\n| \\*?)__wrap_[^ \t(]+" wraps ${content})
    list(REMOVE_DUPLICATES wraps)

    foreach(wrap ${wraps})
        string(REGEX REPLACE ".*__wrap_" "" fn "${wrap}")
        target_link_options("${target}" "${scope}" "-Wl,--wrap=${fn}")
    endforeach()
endfunction()

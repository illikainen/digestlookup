# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

function(add_resource path)
    cmake_parse_arguments(ARGS "INTERNAL" "STATIC"  "" "${ARGN}")

    find_program(cmd glib-compile-resources)
    if(NOT cmd)
        message(FATAL_ERROR "Cannot find glib-compile-resources")
    endif()

    # Allow resources relative to the directory with the GResource file.
    get_filename_component(dirname "${path}" DIRECTORY)
    get_filename_component(basename "${path}" NAME)

    # Retrieve the files in the resource description to re-run
    # add_custom_command() if any of them changes.
    execute_process(
        COMMAND "${cmd}" --generate-dependencies "${basename}"
        WORKING_DIRECTORY "${dirname}"
        RESULT_VARIABLE deps_rc
        OUTPUT_VARIABLE deps_out
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(deps_rc)
        message(FATAL_ERROR "Cannot generate GResource dependencies")
    endif()
    string(REPLACE "\n" ";" deps "${deps_out}")

    # Create a header and a source file instead of a binary bundle.
    set(args "--generate")
    if(ARGS_INTERNAL)
        list(APPEND args "--internal")
    endif()

    foreach(ext .h .c)
        # Convert name.gresource.xml to bindir/name_gresource.${ext}
        string(REGEX REPLACE "\\." "_" output "${basename}")
        string(REGEX REPLACE "_[^_]+$" "${ext}" output "${output}")
        string(PREPEND output "${CMAKE_CURRENT_BINARY_DIR}/")

        add_custom_command(
            OUTPUT "${output}"
            COMMAND "${cmd}" "${basename}" ${args} --target "${output}"
            MAIN_DEPENDENCY "${path}"
            WORKING_DIRECTORY "${dirname}"
            DEPENDS ${deps}
            VERBATIM
        )
        set_source_files_properties("${output}" PROPERTIES GENERATED TRUE)
        list(APPEND files "${output}")
    endforeach()

    # Build a static library.
    if(ARGS_STATIC)
        add_library("${ARGS_STATIC}" STATIC ${files})
        target_include_directories(
            "${ARGS_STATIC}" SYSTEM
            INTERFACE "${CMAKE_CURRENT_BINARY_DIR}"
        )
    endif()
endfunction()

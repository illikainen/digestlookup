# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

function(qa_test)
    qa_get(cmd QA_TEST_CMD REQUIRED)
    qa_get(cwd QA_TEST_CWD)
    if(cwd)
        set(cmd "${cwd}/${cmd}")
    endif()
    qa_get(args QA_TEST_ARGS)
    if(args)
        separate_arguments(args UNIX_COMMAND ${args})
    endif()

    file(GLOB profraw "${cmd}-*.profraw")
    if(profraw)
        file(REMOVE ${profraw})
    endif()

    execute_process(COMMAND ${cmd} ${args} RESULT_VARIABLE rc)
    if(rc)
        qa_error("${cmd} exited with '${rc}'")
    endif()
endfunction()

function(qa_fuzz)
    qa_get(cmd QA_FUZZ_CMD REQUIRED)
    qa_get(corpus QA_FUZZ_CORPUS REQUIRED)
    qa_get(cwd QA_FUZZ_CWD)
    if(cwd)
        set(cmd "${cwd}/${cmd}")
    endif()
    qa_get(args QA_FUZZ_ARGS)
    if(args)
        separate_arguments(args UNIX_COMMAND ${args})
    endif()

    file(GLOB profraw "${cmd}-*.profraw")
    if(profraw)
        file(REMOVE ${profraw})
    endif()

    execute_process(COMMAND ${cmd} ${args} ${corpus} RESULT_VARIABLE rc)
    if(rc)
        qa_error("${cmd} exited with '${rc}'")
    endif()
endfunction()

function(qa_get var name)
    cmake_parse_arguments(args "REQUIRED" "" "" "${ARGN}")

    set(value "$ENV{${name}}")
    if(NOT value)
        set(value ${${name}})
    endif()

    if(NOT value AND args_REQUIRED)
        qa_error("${name} is not set")
    endif()

    set("${var}" "${value}" PARENT_SCOPE)
endfunction()

function(qa_info)
    message(STATUS "${ARGN}")
endfunction()

function(qa_error)
    message(FATAL_ERROR "ERROR: ${ARGN}")
endfunction()

function(qa_main)
    qa_get(action QA_ACTION REQUIRED)
    if(action STREQUAL "test")
        qa_test()
    elseif(action STREQUAL "fuzz")
        qa_fuzz()
    else()
        qa_error("unknown action '${action}'")
    endif()
endfunction()

if(CMAKE_SCRIPT_MODE_FILE)
    qa_main()
endif()

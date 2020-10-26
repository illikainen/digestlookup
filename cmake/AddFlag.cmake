include(CMakePushCheckState)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

function(add_flag type flag)
    string(TOUPPER ${CMAKE_BUILD_TYPE} cmake_type)
    if(NOT ${type} MATCHES "ALL|${cmake_type}")
        return()
    endif()

    string(TOUPPER ${flag} flag_name)
    string(PREPEND flag_name HAVE)
    string(REGEX REPLACE "^-+" "" flag_name ${flag_name})
    string(REGEX REPLACE "=/.*" "" flag_name ${flag_name})
    string(REGEX REPLACE "[ ,+%=\./-]+" "_" flag_name ${flag_name})

    cmake_push_check_state(RESET)
    get_property(languages GLOBAL PROPERTY ENABLED_LANGUAGES)
    get_property(CMAKE_REQUIRED_FLAGS
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        PROPERTY COMPILE_OPTIONS)
    list(APPEND CMAKE_REQUIRED_FLAGS "${flag}")
    string(REPLACE ";" " " CMAKE_REQUIRED_FLAGS  "${CMAKE_REQUIRED_FLAGS}")

    # FIXME: this is horrible
    if(CXX IN_LIST languages)
        check_cxx_compiler_flag(${flag} ${flag_name})
    endif()
    if(C IN_LIST languages AND NOT ${flag_name})
        check_c_compiler_flag(${flag} ${flag_name})
    endif()
    cmake_pop_check_state()

    if(${flag_name})
        separate_arguments(flags UNIX_COMMAND ${flag})

        add_definitions(-D${flag_name})
        if(${flag} MATCHES "^-D")
            add_definitions(${flags})
        elseif(${flag} MATCHES "^-l")
            link_libraries(${flags})
        elseif(${flag} MATCHES "^-(Wl,|pie)")
            add_link_options(${flags})
        else()
            add_compile_options(${flags})
            add_link_options(${flags})
        endif()
    endif()
endfunction()

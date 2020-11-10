# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

include(FindCURL)
include(FindGnuTLS)
include(FindOpenSSL)
include(FindThreads)
include(GetPrerequisites)

function(add_curl)
    cmake_parse_arguments(ARGS "REQUIRED" "TARGET;SCOPE" "" "${ARGN}")

    set(mode "STATUS")
    if(ARGS_REQUIRED)
        set(mode "FATAL_ERROR")
    endif()

    set(scope "PRIVATE")
    if(ARGS_SCOPE)
        set(scope "${ARGS_SCOPE}")
    endif()

    if(NOT CURL_FOUND)
        message("${mode}" "Cannot find Curl")
        return()
    endif()

    foreach(curl_lib ${CURL_LIBRARIES})
        get_prerequisites(${curl_lib} curl_deps 0 0 "" "")
        foreach(curl_dep ${curl_deps})
            if(curl_dep MATCHES ".*ssl.*")
                set(CURL_WITH_OPENSSL 1)
            endif()

            if(curl_dep MATCHES ".*gnutls.*")
                set(CURL_WITH_GNUTLS 1)
            endif()

            # FIXME: check if curl is built with thread support on non-POSIX
            # systems!
            if(curl_dep MATCHES ".*pthread.*")
                set(CURL_WITH_PTHREADS 1)
            endif()
        endforeach()
    endforeach()

    # OpenSSL is thread safe from version 1.1.0.
    #
    # Make sure that OPENSSL_THREADS is defined.
    #
    # See:
    # - https://curl.haxx.se/libcurl/c/threadsafe.html
    if(CURL_WITH_OPENSSL AND OPENSSL_FOUND AND
            OPENSSL_VERSION VERSION_LESS 1.1.0)
        message(FATAL_ERROR "Curl with OpenSSL requires OpenSSL >=1.1.0")
    endif()

    # GnuTLS prior to 3.3.0 require explicit initialization.  Not sure if Curl
    # handles that or if it's up to the user so we lazily bail.  GnuTLS <3.3.0
    # was released in 2014 and most users seem to link against OpenSSL anyway.
    #
    # See:
    # - https://gnutls.org/manual/html_node/Thread-safety.html
    if(CURL_WITH_GNUTLS AND GNUTLS_FOUND AND
            GNUTLS_VERSION_STRING VERSION_LESS 3.3.0)
        message(FATAL_ERROR "Curl with GnuTLS requires GnuTLS >=3.3.0")
    endif()

    # Curl uses a threaded resolver by default if it's linked against POSIX
    # or Windows threads.  This check bails if neither thread library is
    # available.  Support for c-ares is currently ignored.
    #
    # See:
    # - https://curl.haxx.se/libcurl/c/threadsafe.html
    # - https://github.com/curl/curl/blob/curl-7_64_0/m4/curl-confopts.m4
    # - https://github.com/curl/curl/blob/curl-7_64_0/configure.ac#L3866
    if(NOT CMAKE_THREAD_LIBS_INIT OR
            NOT ((CMAKE_USE_PTHREADS_INIT AND CURL_WITH_PTHREADS) OR
                CMAKE_USE_WIN32_THREADS_INIT))
        message(FATAL_ERROR "No appropriate threading library found")
    endif()

    if(ARGS_TARGET)
        if(CURL_INCLUDE_DIRS)
            target_include_directories("${ARGS_TARGET}" SYSTEM
                    "${scope}" "${CURL_INCLUDE_DIRS}")
            endif()
            if(CURL_LIBRARIES)
                target_link_libraries("${ARGS_TARGET}"
                    "${scope}" "${CURL_LIBRARIES}")
            endif()
            if(CURL_WITH_OPENSSL AND OPENSSL_FOUND)
                target_compile_definitions("${ARGS_TARGET}"
                    "${scope}" HAVE_OPENSSL)
                target_include_directories("${ARGS_TARGET}" SYSTEM
                    "${scope}" "${OPENSSL_INCLUDE_DIR}")
            endif()
        endforeach()
    else()
        if(CURL_INCLUDE_DIRS)
            include_directories(SYSTEM "${CURL_INCLUDE_DIRS}")
        endif()
        if(CURL_LIBRARIES)
            link_libraries("${CURL_LIBRARIES}")
        endif()
        if(CURL_WITH_OPENSSL AND OPENSSL_FOUND)
            add_compile_definitions(HAVE_OPENSSL)
            include_directories(SYSTEM "${OPENSSL_INCLUDE_DIR}")
        endif()
    endif()

    message(STATUS "Found Curl")
endfunction()

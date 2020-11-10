#
# Compilers.
#
if(NOT DEFINED ENV{CC})
    find_program(CMAKE_C_COMPILER clang)
endif()

if(NOT DEFINED ENV{CXX})
    find_program(CMAKE_CXX_COMPILER clang++)
endif()

#
# Standard.
#
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

#
# Project.
#
cmake_minimum_required(VERSION 3.13)
project(digestlookup VERSION 0.0.0 LANGUAGES C)

#
# Modules.
#
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")
include(AddFlag)
include(CheckIPOSupported)
include(FindCURL)
include(FindGnuTLS)
include(FindOpenSSL)
include(FindPkgConfig)
include(FindThreads)
include(GetPrerequisites)

#
# Default to release builds.
#
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

#
# Export compile commands.
#
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#
# Enable IPO.
#
check_ipo_supported(RESULT have_ipo)
if(have_ipo)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

#
# Flags for all build types.
#
add_flag(ALL "-D__STDC_WANT_LIB_EXT1__=1")
add_flag(ALL "-D_POSIX_C_SOURCE=200809L")
add_flag(ALL "-D_FILE_OFFSET_BITS=64")
add_flag(ALL "-W")
add_flag(ALL "-Wall")
add_flag(ALL "-Weverything")
add_flag(ALL "-Wextra")
add_flag(ALL "-Wpedantic")
add_flag(ALL "-Werror=gcc-compat")
add_flag(ALL "-Werror=unused-result")
add_flag(ALL "-Wno-disabled-macro-expansion")
add_flag(ALL "-Wno-padded")

add_flag(ALL "-D_FORTIFY_SOURCE=2")
add_flag(ALL "-Wformat")
add_flag(ALL "-Wformat-security")
add_flag(ALL "-Werror=format-security")
add_flag(ALL "-flto")
add_flag(ALL "-fvisibility=hidden")
add_flag(ALL "-fstack-clash-protection")
add_flag(ALL "-fstack-protector-all")
add_flag(ALL "-ftrivial-auto-var-init=pattern")
add_flag(ALL "-Wl,-z,now")
add_flag(ALL "-Wl,-z,relro")
add_flag(ALL "-Wl,-z,defs")
add_flag(ALL "-Wl,--dynamicbase")
add_flag(ALL "-Wl,--nxcompat")
add_flag(ALL "-Wl,--high-entropy-va")

#
# Flags for release builds.
#
if(CMAKE_C_COMPILER_ID STREQUAL Clang AND CMAKE_CXX_COMPILER_ID STREQUAL Clang)
    # UBSan has a minimal runtime that's appropriate for release builds:
    # <https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html>
    #
    # However, note that UBSan is somewhat broken on older versions of
    # LLVM, so checks has to be enabled individually as opposed to
    # simply enabling the `undefind` group:
    # <https://reviews.llvm.org/rGf8d6836f7a69>
    #
    # CFI also seems appropriate for release builds:
    # <https://clang.llvm.org/docs/ControlFlowIntegrity.html>
    #
    # With that said, UBSan and/or CFI may or may not be designed for
    # production use in other compilers where the sanitizers are available;
    # hence the COMPILER_ID conditional.
    add_flag(RELEASE "-fsanitize-minimal-runtime")
    if(HAVE_FSANITIZE_MINIMAL_RUNTIME)
        foreach(sanitizer cfi integer nullability undefined)
            add_flag(RELEASE "-fsanitize=${sanitizer}")
            add_flag(RELEASE "-fno-sanitize-recover=${sanitizer}")
        endforeach()
    endif()
endif()

# PIE is only enabled in release builds because ASan doesn't seem to
# play well with it.
add_flag(RELEASE "-fPIE")
add_flag(RELEASE "-pie")

#
# Flags for debug builds.
#
add_flag(DEBUG "-O0")
add_flag(DEBUG "-fno-omit-frame-pointer")
add_flag(DEBUG "-fprofile-instr-generate=instr-%m%c.profraw")
add_flag(DEBUG "-fcoverage-mapping")

# FIXME: investigate why ASan with gcc 8.3.0 occasionally enters a seemingly
# infinite loop where the only output is AddressSanitizer:DEADLYSIGNAL.
# Does not seem reproducible in gdb.
if(CMAKE_C_COMPILER_ID STREQUAL Clang)
    foreach(sanitizer address cfi integer nullability thread undefined)
        string(TOUPPER ${sanitizer} sanitizer_env)
        if(NOT DEFINED ENV{NO_${sanitizer_env}})
            add_flag(DEBUG "-fsanitize=${sanitizer}")
            add_flag(DEBUG "-fno-sanitize-recover=${sanitizer}")
        endif()
    endforeach()
endif()

#
# Dependencies.
#
if(NOT PKG_CONFIG_FOUND)
    message(FATAL_ERROR "Cannot find pkg-config")
endif()

pkg_check_modules(GLIB glib-2.0)
if(NOT GLIB_FOUND)
    message(FATAL_ERROR "Cannot find GLib")
endif()
include_directories(SYSTEM ${GLIB_INCLUDE_DIRS})
link_libraries(${GLIB_LINK_LIBRARIES})

if(NOT CURL_FOUND)
    message(FATAL_ERROR "Cannot find Curl")
endif()
include_directories(SYSTEM ${CURL_INCLUDE_DIRS})
link_libraries(${CURL_LIBRARIES})

foreach(curl_lib ${CURL_LIBRARIES})
    get_prerequisites(${curl_lib} curl_deps 0 0 "" "")

    foreach(curl_dep ${curl_deps})
        if(curl_dep MATCHES ".*ssl.*")
            set(CURL_WITH_OPENSSL 1)
        endif()

        if(curl_dep MATCHES ".*gnutls.*")
            set(CURL_WITH_GNUTLS 1)
        endif()

        # FIXME: check if curl is built with a threaded resolver on
        # non-POSIX systems!
        if(curl_dep MATCHES ".*pthread.*")
            set(CURL_WITH_PTHREADS 1)
        endif()
    endforeach()
endforeach()

# OpenSSL is thread safe from version 1.1.0.  Note to self: make sure that
# OPENSSL_THREADS is defined.
#
# See:
# - https://curl.haxx.se/libcurl/c/threadsafe.html
if(CURL_WITH_OPENSSL AND OPENSSL_FOUND)
    if(OPENSSL_VERSION VERSION_LESS 1.1.0)
        message(FATAL_ERROR "Curl with OpenSSL requires OpenSSL >=1.1.0")
    endif()

    add_compile_definitions(HAVE_OPENSSL)
    include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
endif()

# GnuTLS prior to 3.3.0 require explicit initialization.  Not sure if Curl
# handles that or if it's up to the user so we lazily bail.  GnuTLS <3.3.0 was
# released in 2014 and most users seem to link against OpenSSL anyway.
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
link_libraries(${CMAKE_THREAD_LIBS_INIT})

#
# Transpile config.h.
#
configure_file(src/config.h.in config.h)

#
# Include directories.
#
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories("${CMAKE_SOURCE_DIR}/src")
get_property(include_dirs
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    PROPERTY INCLUDE_DIRECTORIES)

#
# Enable CTest.
#
enable_testing()

#
# Targets.
#
add_subdirectory(src)
add_subdirectory(tests)

#
# Check and fix targets.
#
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_custom_target(check
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "check"
        COMMAND "${Python3_EXECUTABLE}" utils/qa
        --build-path "${CMAKE_BINARY_DIR}" check)

    add_custom_target(fix
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "fix"
        COMMAND "${Python3_EXECUTABLE}" utils/qa
        --build-path "${CMAKE_BINARY_DIR}" fix)
endif()

#
# Build information.
#
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "CXX compiler: ${CMAKE_CXX_COMPILER}")

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
include(AddCURL)
include(AddFlag)
include(AddGLib)
include(AddGPGME)
include(AddPkgConfig)
include(AddThreads)
include(CheckIPOSupported)
include(GNUInstallDirs)

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

add_flag(ALL "-Wconditional-uninitialized")
add_flag(ALL "-Wformat=2")
add_flag(ALL "-Wformat-overflow=2")
add_flag(ALL "-Wformat-security")
add_flag(ALL "-Wformat-truncation=2")
add_flag(ALL "-Wfortify-source")
add_flag(ALL "-Wfree-nonheap-object")
add_flag(ALL "-Wgcc-compat")
add_flag(ALL "-Wimplicit")
add_flag(ALL "-Wincompatible-pointer-types")
add_flag(ALL "-Wmultistatement-macros")
add_flag(ALL "-Wnonnull")
add_flag(ALL "-Wnull-arithmetic")
add_flag(ALL "-Wnull-conversion")
add_flag(ALL "-Wnull-dereference")
add_flag(ALL "-Wnull-pointer-arithmetic")
add_flag(ALL "-Wreturn-type")
add_flag(ALL "-Wsentinel")
add_flag(ALL "-Wuninitialized")
add_flag(ALL "-Wunused-result")

add_flag(ALL "-Werror=conditional-uninitialized")
add_flag(ALL "-Werror=format-overflow")
add_flag(ALL "-Werror=format-security")
add_flag(ALL "-Werror=format-truncation")
add_flag(ALL "-Werror=fortify-source")
add_flag(ALL "-Werror=free-nonheap-object")
add_flag(ALL "-Werror=gcc-compat")
add_flag(ALL "-Werror=implicit")
add_flag(ALL "-Werror=incompatible-pointer-types")
add_flag(ALL "-Werror=multistatement-macros")
add_flag(ALL "-Werror=nonnull")
add_flag(ALL "-Werror=null-arithmetic")
add_flag(ALL "-Werror=null-conversion")
add_flag(ALL "-Werror=null-dereference")
add_flag(ALL "-Werror=null-pointer-arithmetic")
add_flag(ALL "-Werror=return-type")
add_flag(ALL "-Werror=sentinel")
add_flag(ALL "-Werror=uninitialized")
add_flag(ALL "-Werror=unused-result")

add_flag(ALL "-Wno-disabled-macro-expansion")
add_flag(ALL "-Wno-padded")

add_flag(ALL "-D_FORTIFY_SOURCE=2")
add_flag(ALL "-fanalyzer")
add_flag(ALL "-flto")
add_flag(ALL "-fvisibility=hidden")
add_flag(ALL "-fstack-clash-protection")
add_flag(ALL "-fstack-protector-all")
add_flag(ALL "-ftrivial-auto-var-init=pattern")
add_flag(ALL "-ftrapv")
add_flag(ALL "-Wl,-z,noexecstack")
add_flag(ALL "-Wl,-z,now")
add_flag(ALL "-Wl,-z,relro")
add_flag(ALL "-Wl,-z,defs")
add_flag(ALL "-Wl,--dynamicbase")
add_flag(ALL "-Wl,--nxcompat")
add_flag(ALL "-Wl,--high-entropy-va")

#
# Flags for release builds.
#
if(CMAKE_C_COMPILER_ID STREQUAL Clang)
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
    #
    # TODO: evaluate SafeStack <https://clang.llvm.org/docs/SafeStack.html>.
    add_flag(RELEASE "-fsanitize-minimal-runtime")
    if(HAVE_FSANITIZE_MINIMAL_RUNTIME)
        foreach(sanitizer cfi undefined bounds integer nullability
                float-divide-by-zero)
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
add_flag(DEBUG "-fprofile-instr-generate")
add_flag(DEBUG "-fcoverage-mapping")

# FIXME: investigate why ASan with gcc 8.3.0 occasionally enters a seemingly
# infinite loop where the only output is AddressSanitizer:DEADLYSIGNAL.
# Does not seem reproducible in gdb.
if(CMAKE_C_COMPILER_ID STREQUAL Clang)
    foreach(sanitizer address cfi undefined bounds integer nullability
            float-divide-by-zero thread)
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
add_curl(REQUIRED)
add_gpgme(REQUIRED THREAD pthread)
add_glib(REQUIRED GIO LOG_USE_STRUCTURED LOG_DOMAIN "${PROJECT_NAME}")
add_threads(REQUIRED)
add_pkg_config(REQUIRED PKG liblzma)

#
# Transpile config.h.
#
configure_file(src/config.h.in config.h ESCAPE_QUOTES)

#
# Include directories.
#
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories("${CMAKE_SOURCE_DIR}/src")

#
# Enable CTest.
#
enable_testing()

#
# Targets.
#
add_subdirectory(data)
add_subdirectory(src)
add_subdirectory(tests)

#
# Installation.
#
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

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

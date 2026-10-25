cmake_minimum_required(VERSION 3.20)

project(KryptonFS
    VERSION 0.1.0
    DESCRIPTION "Distributed encrypted virtual filesystem"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(KFS_BUILD_TESTS        "Build unit tests"                    ON)
option(KFS_WARNINGS_AS_ERRORS "Treat compiler warnings as errors"   ON)
option(KFS_SANITIZE           "Build with AddressSanitizer + UBSan" OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(CheckPIESupported)
    check_pie_supported()
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
else()
    message(WARNING
        "KryptonFS targets Linux (FUSE3, System V IPC, chroot). On "
        "${CMAKE_SYSTEM_NAME} only the portable common library and its "
        "tests build.")
endif()

include(cmake/KryptonDefaults.cmake)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_subdirectory(src/common)
add_subdirectory(src/crypto)
add_subdirectory(src/scanner)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Threads REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3>=3.10)
    add_subdirectory(src/sandbox)
    add_subdirectory(src/fs)
    add_subdirectory(src/fuse)
endif()
add_subdirectory(tools)
# Later phases add: src/net, src/node (4); src/telemetry (5).

if(KFS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

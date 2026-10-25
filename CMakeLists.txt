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

add_subdirectory(src/common)
# Later phases add: src/crypto, src/scanner (2); src/sandbox, src/fuse (3);
# src/net, src/node (4); src/telemetry (5).

if(KFS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

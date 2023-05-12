cmake_minimum_required(VERSION 3.30)
project(readpe)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_DISASSEMBLER "Build with basic disassembler support (deprecated)" OFF)
option(BUILD_STATIC "Build static executable" Off)
option(BUILD_STANDALONE "Build separate executables" OFF)
option(ENABLE_TESTS "Enable testing" On)

if(BUILD_DISASSEMBLER)
    add_subdirectory(lib/libudis86/libudis86)
endif()

add_subdirectory(lib/libpe)
add_subdirectory(src/plugins)
add_subdirectory(src)

if(ENABLE_TESTS)
    include("${CMAKE_SOURCE_DIR}/cmake/tests.cmake")
endif()


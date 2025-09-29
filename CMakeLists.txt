cmake_minimum_required(VERSION 3.20.0)
project(readpe)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_DISASSEMBLER "Build with basic disassembler support (deprecated)" OFF)
option(BUILD_LEGACY "Build support for legacy executables by link name" ON)
option(BUILD_STANDALONE "Build separate executables" OFF)
option(BUILD_STATIC "Build static executable" Off)
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

set(
    CPACK_PACKAGE_NAME ${PROJECT_NAME}
    CACHE STRING "The resulting package name"
)


set(CPACK_STRIP_FILES YES)


set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})


set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")


include(CPack)
configure_file ("${PROJECT_SOURCE_DIR}/cmake/cpackopt.cmake.in"
                "${PROJECT_BINARY_DIR}/cpackopt.cmake"
                @ONLY)
set (CPACK_PROJECT_CONFIG_FILE
     "${PROJECT_BINARY_DIR}/cpackopt.cmake")


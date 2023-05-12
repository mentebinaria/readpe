cmake_minimum_required(VERSION 3.30)
project(readpe)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_STATIC "Build static executable" Off)

add_subdirectory(lib/libpe)
add_subdirectory(lib/libudis86/libudis86)
add_subdirectory(src/plugins)
add_subdirectory(src)



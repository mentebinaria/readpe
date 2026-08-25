# This file is licensed under the MIT License

include(FetchContent)
include(CheckIncludeFile)

set(content)
if(MSVC)
    # set(dirent_SOURCE_DIR "${CMAKE_SOURCE_DIR}/extern/dirent-1.26")
    FetchContent_Declare(
        dirent
        URL https://github.com/tronkko/dirent/archive/refs/tags/1.26.zip
        URL_HASH SHA256=6ffcc318f00be192acb611c58aa58ee0cfd96776010680d7f38cf24f3dd8baf9
        URL_MD5 1ac86947cbba80c15585691dd421e0dc
        DOWNLOAD_EXTRACT_TIMESTAMP OLD
        SOURCE_SUBDIR "-"
    )
    list(APPEND content dirent)

    # set(dl_SOURCE_DIR "${CMAKE_SOURCE_DIR}/extern/dlfcn-win32-1.4.2")
    FetchContent_Declare(
        dl
        URL https://github.com/dlfcn-win32/dlfcn-win32/archive/refs/tags/v1.4.2.zip
        URL_HASH SHA256=7c85998ee4296303bde30e8e9c72c28e637b881e2211682915b53455a65a0d07
        URL_MD5 d0026d224377794ed2a6561500302ccc
        DOWNLOAD_EXTRACT_TIMESTAMP OLD
        SOURCE_SUBDIR "-"
    )
    list(APPEND content dl)
endif()

check_include_file(utlist.h utlist_FOUND)
if(NOT utlist_FOUND)
    # set(uthash_SOURCE_DIR "${CMAKE_SOURCE_DIR}/extern/uthash-2.3.0")
    FetchContent_Declare(
        uthash
        URL https://github.com/troydhanson/uthash/archive/refs/tags/v2.3.0.zip
        URL_HASH SHA256=b9a6c503a82a6c6e699e4bdccc2d4f2151cfff81e5e159b50eac89c7d226824d
        URL_MD5 fb22a40f4ec2181af2c21c2d71a8a30e
        DOWNLOAD_EXTRACT_TIMESTAMP OLD
        SOURCE_SUBDIR "-"
    )
    list(APPEND content uthash)
endif()

FetchContent_MakeAvailable(${content})

if(MSVC)
    add_library(dirent INTERFACE)
    target_include_directories(dirent INTERFACE ${dirent_SOURCE_DIR}/include)
    set_target_properties(dirent PROPERTIES
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${dirent_SOURCE_DIR}/include"
    )

    add_library(dl STATIC
        ${dl_SOURCE_DIR}/src/dlfcn.c
        ${dl_SOURCE_DIR}/src/dlfcn.h
    )
    target_include_directories(dl INTERFACE ${dl_SOURCE_DIR}/src)
    set_target_properties(dl PROPERTIES
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${dl_SOURCE_DIR}/src"
    )
endif()

add_library(uthash INTERFACE)
target_include_directories(uthash INTERFACE ${uthash_SOURCE_DIR}/src)
set_target_properties(uthash PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${uthash_SOURCE_DIR}/src"
)


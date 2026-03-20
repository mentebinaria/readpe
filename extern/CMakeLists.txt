include(FetchContent)

set(content)

if(MSVC)
    FetchContent_Declare(
        dirent
        URL https://github.com/tronkko/dirent/archive/refs/tags/1.26.zip
        URL_HASH SHA256=6ffcc318f00be192acb611c58aa58ee0cfd96776010680d7f38cf24f3dd8baf9
        URL_MD5 1ac86947cbba80c15585691dd421e0dc
        DOWNLOAD_EXTRACT_TIMESTAMP OLD
    )
    FetchContent_Declare(
        dlfcn-win32
        URL https://github.com/dlfcn-win32/dlfcn-win32/archive/refs/tags/v1.4.2.zip
        URL_HASH SHA256=7c85998ee4296303bde30e8e9c72c28e637b881e2211682915b53455a65a0d07
        URL_MD5 d0026d224377794ed2a6561500302ccc
        DOWNLOAD_EXTRACT_TIMESTAMP OLD
    )
    list(APPEND content dirent dlfcn-win32)
endif()

FetchContent_Declare(
    uthash
    URL https://github.com/troydhanson/uthash/archive/refs/tags/v2.3.0.zip
    URL_HASH SHA256=b9a6c503a82a6c6e699e4bdccc2d4f2151cfff81e5e159b50eac89c7d226824d
    URL_MD5 fb22a40f4ec2181af2c21c2d71a8a30e
    DOWNLOAD_EXTRACT_TIMESTAMP OLD
)
list(APPEND content uthash)
FetchContent_MakeAvailable(${content})

add_library(uthash INTERFACE)
target_include_directories(uthash INTERFACE ${uthash_SOURCE_DIR}/include)


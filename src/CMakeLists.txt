project(readpe LANGUAGES C)

set(HEADERS
    ../include/compat/strlcat.h
    ../include/compat/sys/queue.h

    ../include/common.h
    ../include/config.h
    ../include/output.h
    ../include/output_plugin.h
    ../include/plugin.h
    ../include/plugins.h
    ../include/readpe.h
    ../include/stack.h

    dylib.h
    legacy.h
)

set(SOURCES
    compat/strlcat.c

    main.c

    config.c
    directories.c
    dylib.c
    exports.c
    hash.c
    header.c
    imports.c
    malloc_s.c
    output.c
    output_plugin.c
    output_text.c
    plugin.c
    plugins.c
    resources.c
    section.c
    security.c
    certificates.c
    scan.c

    legacy/pehash.c
    legacy/peldd.c
    legacy/pepack.c
    legacy/peres.c
    legacy/pescan.c
    legacy/pesec.c
    legacy/pestr.c
    legacy/readpe.c
    legacy/ofs2rva.c
    legacy/rva2ofs.c
)

if(BUILD_DISASSEMBLER)
    list(APPEND SOURCES legacy/pedis.c )
endif()

if(BUILD_STATIC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_EXE_LINKER_FLAGS "-no-pie -static")

    # set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
    # target_compile_options(your_target_name [PUBLIC|PRIVATE] /MT)
    # target_link_options(your_target_name [PUBLIC|PRIVATE] /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
    # set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    # https://stackoverflow.com/questions/24648357/compiling-a-static-executable-with-cmake
    # set(CMAKE_MFC_FLAG 1)

endif()

if(WIN32)
    append( SOURCES
        windows/cpload.c
    )
endif()

add_compile_definitions(
    SHAREDIR=""
    PLUGINSDIR="src/plugins"
)



find_package(OpenSSL)

add_executable(readpe ${HEADERS} ${SOURCES})
target_include_directories(readpe PRIVATE
    "../include"
    "../lib"
    "../lib/libpe/include"
)

target_link_libraries(readpe PRIVATE pe OpenSSL::Crypto m)

if(BUILD_DISASSEMBLER)
    target_link_libraries(readpe PRIVATE udis86)
    target_compile_definitions(readpe
        READPE_DISASSEMBLER=1
    )
endif()

if(MSVC)
    target_compile_options(readpe PRIVATE /W4 /WX)
else()
    target_compile_options(readpe PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wundef
        -Wdouble-promotion
        -Wformat=2
        -Wformat-security
        -Wconversion
        -ggdb3
    )
endif()


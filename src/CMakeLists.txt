project(readpe LANGUAGES C VERSION ${readpe_VERSION})

set(HEADERS
    ${CMAKE_SOURCE_DIR}/include/readpe/config.h
    ${CMAKE_SOURCE_DIR}/include/readpe/output.h
    ${CMAKE_SOURCE_DIR}/include/readpe/readpe.h
    ${CMAKE_SOURCE_DIR}/include/readpe/plugin.h
    ${CMAKE_SOURCE_DIR}/include/readpe/helper.h

    ${CMAKE_SOURCE_DIR}/include/readpe/plugin/output.h

    plugins.h
    stack.h
    dylib.h
)

set(SOURCES
    main.c

    certificates.c
    config.c
    directories.c
    dylib.c
    exports.c
    hash.c
    header.c
    helper.c
    imports.c
    malloc_s.c
    output.c
    output_plugin.c
    output_text.c
    plugin.c
    plugins.c
    resources.c
    scan.c
    section.c
    security.c
)

if(READPE_LEGACY)
    if(BUILD_DISASSEMBLER)
        list(APPEND SOURCES legacy/pedis.c )
    endif()

    list(APPEND HEADERS
        legacy/legacy.h
    )
    list(APPEND SOURCES
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
endif()

# if(LIBPE_STATIC)
#     if(WIN32)
#         set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
#     else()
#         set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#         set(CMAKE_EXE_LINKER_FLAGS "-no-pie -static")
#     endif()
# endif()

if(WIN32)
    if(!MSVC)
        list(APPEND SOURCES windows/cpload.c)
    endif()

    # add_definitions(-DVER_COMPANYNAME_STR="")
    add_definitions(-DVER_FILEVERSION_STR="${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},0")
endif()

add_compile_definitions(
    SHAREDIR=""
    PLUGINSDIR="src/plugins"
)

if(MSVC)
    find_package(OpenSSL)
else()
    find_package(OpenSSL REQUIRED)
endif()

configure_file(version.h.in version.h @ONLY)
add_definitions(-DHAS_CMAKE_VERSION)

add_executable(readpe ${HEADERS} ${SOURCES})
target_include_directories(readpe PRIVATE
    "${CMAKE_SOURCE_DIR}/include/readpe"
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}"
)

if(LIBPE_LINK_SSDEEP)
    target_compile_definitions(pe PRIVATE
        -DLIBPE_LINK_SSDEEP=1
    )
endif()

target_link_libraries(readpe PRIVATE
    OpenSSL::Crypto
    readpe::compat
    readpe::libpe
    uthash
)

if(READPE_LEGACY)
    if(BUILD_DISASSEMBLER)
        target_link_libraries(readpe PRIVATE udis86)
        target_compile_definitions(readpe PRIVATE
            READPE_DISASSEMBLER=1
        )
    endif()

    target_compile_definitions(readpe PRIVATE
        READPE_LEGACY=1
    )
endif()

if(MSVC)
    target_link_libraries(readpe PRIVATE dirent)
    target_compile_options(readpe PRIVATE /W4 /WX)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_link_libraries(readpe PRIVATE m)
    target_compile_options(readpe PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -pedantic
        -Wshadow
        -Wundef
        -Wdouble-promotion
        -Wformat=2
        -Wformat-security
        -Wconversion
        -ggdb3
    )
endif()

install(TARGETS readpe
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)


project(readpe LANGUAGES C VERSION ${readpe_VERSION})

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(HEADERS
    ${CMAKE_SOURCE_DIR}/include/readpe/config.h
    ${CMAKE_SOURCE_DIR}/include/readpe/output.h
    ${CMAKE_SOURCE_DIR}/include/readpe/readpe.h
    ${CMAKE_SOURCE_DIR}/include/readpe/plugin.h
    ${CMAKE_SOURCE_DIR}/include/readpe/helper.h

    ${CMAKE_SOURCE_DIR}/include/readpe/plugin/output.h
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

    plugins.h
    stack.h
    dylib.h
)

if(READPE_BUILD_LINK_NAME_SUPPORT)
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

if(WIN32)
    # TODO
    # list(APPEND SOURCES windows/cpload.c)
endif()

if(BUILD_READPE_ONLY)
    find_package(libpe REQUIRED)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

configure_file(version.h.in version.h @ONLY)

add_executable(readpe ${HEADERS} ${SOURCES})
target_link_libraries(readpe PRIVATE
    OpenSSL::Crypto
    readpe::compat
    readpe::libpe
    uthash
)

target_include_directories(readpe PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/include/readpe"
    "${CMAKE_CURRENT_BINARY_DIR}"
)

target_include_directories(readpe PUBLIC
    $<BUILD_INTERFACE:${CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/readpe>
)

target_compile_definitions(readpe PRIVATE
    HAS_CMAKE_VERSION=1
    # -DVER_COMPANYNAME_STR=""
    VER_FILEVERSION_STR="${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},0"

    SHAREDIR=""
    PLUGINSDIR="plugins"
)

# Warnings for better code
if(MSVC)
    target_link_libraries(readpe PRIVATE dirent dl)
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

if(LIBPE_LINK_SSDEEP)
    target_compile_definitions(pe PRIVATE
        -DLIBPE_LINK_SSDEEP=1
    )
endif()

if(READPE_BUILD_LINK_NAME_SUPPORT)
    # TODO: Currently not in readpe
    if(BUILD_DISASSEMBLER)
        target_link_libraries(readpe PRIVATE udis86)
        target_compile_definitions(readpe PRIVATE
            READPE_DISASSEMBLER=1
        )
    endif()

    target_compile_definitions(readpe PRIVATE
        READPE_LINK_NAMES=1
    )
endif()

# Install readpe
install(TARGETS readpe
    EXPORT readpe-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(READPE_PACK_COMPLETION)
    install(FILES
        ${CMAKE_SOURCE_DIR}/tools/completion/readpe.bash
        ${CMAKE_SOURCE_DIR}/tools/completion/readpe.fsh
        ${CMAKE_SOURCE_DIR}/tools/completion/readpe.zsh
        DESTINATION ${CMAKE_INSTALL_DATADIR}/readpe
    )
endif()

# Install readpe headers for plugin development
if(READPE_PACK_HEADERS)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/readpe
        DESTINATION include/
        FILES_MATCHING
        PATTERN "*.h"
    )
endif()

# Install readpe cmake files for plugin development
if(READPE_PACK_CMAKE_FILES)
    export(EXPORT readpe-targets
        FILE "${CMAKE_CURRENT_BINARY_DIR}/readpe-targets.cmake"
           NAMESPACE readpe::
    )

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/readpe-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/readpe-config.cmake
        INSTALL_DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
        PATH_VARS
            CMAKE_INSTALL_INCLUDEDIR
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
    )

    install(EXPORT readpe-targets
            FILE readpe-targets.cmake
            NAMESPACE readpe::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/readpe
    )

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/readpe-config.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/readpe
    )
endif()


project(libpe LANGUAGES C VERSION ${readpe_VERSION})

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(HEADERS
    ${CMAKE_SOURCE_DIR}/include/libpe/context.h
    ${CMAKE_SOURCE_DIR}/include/libpe/directories.h
    ${CMAKE_SOURCE_DIR}/include/libpe/dir_import.h
    ${CMAKE_SOURCE_DIR}/include/libpe/dir_resources.h
    ${CMAKE_SOURCE_DIR}/include/libpe/dir_security.h
    ${CMAKE_SOURCE_DIR}/include/libpe/error.h
    ${CMAKE_SOURCE_DIR}/include/libpe/exports.h
    ${CMAKE_SOURCE_DIR}/include/libpe/hashes.h
    ${CMAKE_SOURCE_DIR}/include/libpe/hdr_dos.h
    ${CMAKE_SOURCE_DIR}/include/libpe/hdr_coff.h
    ${CMAKE_SOURCE_DIR}/include/libpe/hdr_optional.h
    ${CMAKE_SOURCE_DIR}/include/libpe/imports.h
    ${CMAKE_SOURCE_DIR}/include/libpe/macros.h
    ${CMAKE_SOURCE_DIR}/include/libpe/ordlookup.h
    ${CMAKE_SOURCE_DIR}/include/libpe/pe.h
    ${CMAKE_SOURCE_DIR}/include/libpe/resources.h
    ${CMAKE_SOURCE_DIR}/include/libpe/sections.h
    ${CMAKE_SOURCE_DIR}/include/libpe/types_resources.h
    ${CMAKE_SOURCE_DIR}/include/libpe/utils.h
)

set(SOURCES
    error.c
    exports.c
    hashes.c
    imports.c
    misc.c
    pe.c
    resources.c
    security.c
    utils.c
)

set(LIBPE_LINKING SHARED)
if(LIBPE_BUILD_STATIC)
    set(LIBPE_LINKING STATIC)
endif()

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(pe ${LIBPE_LINKING} ${HEADERS} ${SOURCES})
add_library(readpe::libpe ALIAS pe)

target_link_libraries(pe PRIVATE
    OpenSSL::Crypto
    readpe::compat
    uthash
)

target_include_directories(pe PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
)

target_include_directories(pe
  PUBLIC
    $<BUILD_INTERFACE:${CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/libpe>
)

# Warnings for better code
if(MSVC)
    target_compile_options(pe PRIVATE
        /W4
    )
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_link_libraries(pe PRIVATE m)
    target_compile_options(pe PRIVATE
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
    )
endif()

# Make sure to call it libpe.dll under windows
if(WIN32)
    set_target_properties(pe PROPERTIES PREFIX "lib")
endif()

# Slurp file instead of memory mapping
if(LIBPE_SLURP_PE_FILE)
    target_compile_definitions(pe PRIVATE
        -D_SLURP_PE_FILE
    )
endif()

# Link in libfuzzy (GPL)
if(LIBPE_LINK_SSDEEP)
    target_link_libraries(pe PRIVATE fuzzy)
    target_compile_definitions(pe PRIVATE
        -DLIBPE_LINK_SSDEEP=1
    )
endif()

# Install libpe
install(TARGETS pe
    EXPORT libpe-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install libpe headers
if(LIBPE_PACK_HEADERS)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/libpe
        DESTINATION include/
        FILES_MATCHING
        PATTERN "*.h"
    )
endif()

# Install cmake files for linking against libpe (find_package)
if(LIBPE_PACK_CMAKE_FILES)
    export(EXPORT libpe-targets
        FILE "${CMAKE_CURRENT_BINARY_DIR}/libpe-targets.cmake"
           NAMESPACE readpe::
    )

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/libpe-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/libpe-config.cmake
        INSTALL_DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
        PATH_VARS
            CMAKE_INSTALL_INCLUDEDIR
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
    )

    install(EXPORT libpe-targets
            FILE libpe-targets.cmake
            NAMESPACE readpe::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libpe
    )

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libpe-config.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libpe
    )
endif()

# Install pkg-config files as alternative of linking against libpe w\o cmake
if(LIBPE_PACK_PKGCONF_FILES)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/libpe.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/libpe.pc
        @ONLY
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libpe.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )
endif()


project(libpe LANGUAGES C VERSION ${readpe_VERSION})

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
if(LIBPE_STATIC)
    set(LIBPE_LINKING STATIC)
endif()

find_package(OpenSSL REQUIRED)

add_library(pe ${LIBPE_LINKING} ${HEADERS} ${SOURCES})

if(WIN32)
    set_target_properties(pe PROPERTIES PREFIX "lib")
endif()

target_link_libraries(pe PRIVATE
    OpenSSL::Crypto
    readpe::compat
    uthash
)

if(LIBPE_LINK_SSDEEP)
    target_link_libraries(pe PRIVATE fuzzy)
    target_compile_definitions(pe PRIVATE
        -DLIBPE_LINK_SSDEEP=1
    )
endif()

target_include_directories(pe SYSTEM PRIVATE
    "${uthash_INCLUDE_DIR}"
)
target_include_directories(pe PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
)

if(MSVC)
    target_compile_options(pe PRIVATE
        /W4
    )
else()
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

install (FILES ${HEADERS} DESTINATION include/libpe)
target_include_directories(pe
  PUBLIC
    $<BUILD_INTERFACE:${CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/libpe>
)
add_library(readpe::libpe ALIAS pe)

install(TARGETS pe
    EXPORT pe-targets
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
)

export(EXPORT pe-targets
       FILE "${CMAKE_BINARY_DIR}/pe-targets.cmake"
       NAMESPACE readpe::
)

include(CMakePackageConfigHelpers)
configure_package_config_file(pe-config.cmake.in ${CMAKE_BINARY_DIR}/pe-config.cmake
    INSTALL_DESTINATION "${CMAKE_BINARY_DIR}"
    # PATH_VARS ${CMAKE_SOURCE_DIR}/include
    NO_CHECK_REQUIRED_COMPONENTS_MACRO)

# Install the targets (install)
install(EXPORT pe-targets
        FILE pe-targets.cmake
        NAMESPACE readpe::
        DESTINATION "${CMAKE_BINARY_DIR}")

# Install the CMake config file
install(FILES ${CMAKE_BINARY_DIR}/pe-config.cmake
    DESTINATION "${CMAKE_BINARY_DIR}")


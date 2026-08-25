cmake_minimum_required(VERSION 3.31.0)

# Disable in-source builds
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

project(readpe LANGUAGES C VERSION 1.0.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

option(BUILD_DISASSEMBLER "Build with basic disassembler support (deprecated)" OFF)
option(BUILD_LIBPE_ONLY "Build libpe only" OFF)
option(BUILD_READPE_ONLY "Build readpe only (requires libpe to be installed)" OFF)
option(BUILD_READPE_PLUGINS "Build readpe plugins" ON)
option(ENABLE_TESTS "Enable testing" On)

option(READPE_BUILD_LINK_NAME_SUPPORT "Build support for old executables by link name" ON)
option(READPE_PACK_HEADERS "Package readpe headers (for plugin development)" OFF)
option(READPE_PACK_CMAKE_FILES "Package readpe cmake config files (for plugin development)" OFF)
option(READPE_PACK_COMPLETION "Package bash, fsh, and zsh completion files" ON)

if(WIN32)
    set(READPE_PACK_COMPLETION OFF)
endif()

# TODO:
# option(READPE_STANDALONE "Build separate executables" OFF)

option(LIBPE_SLURP_PE_FILE "Slurp PE file instead of memory mapping it" OFF)
option(LIBPE_BUILD_STATIC "Link libpe into readpe staticially" Off)

set(DEFAULT_LIBPE_PACK_DEV_FILES ON)
set(DEFAULT_LIBPE_LINK_SSDEEP OFF)
if(LIBPE_BUILD_STATIC)
    # We might as well use GPL code since readpe is GPL anyway
    set(DEFAULT_LIBPE_LINK_SSDEEP ON)
    # Don't need dev files if we compile it into readpe
    set(DEFAULT_LIBPE_PACK_DEV_FILES OFF)
endif()

option(LIBPE_LINK_SSDEEP "LINK SSDEEP GPL2 code into libpe" ${DEFAULT_LIBPE_LINK_SSDEEP})

option(LIBPE_PACK_HEADERS "Package libpe headers" ${DEFAULT_LIBPE_PACK_DEV_FILES})
option(LIBPE_PACK_CMAKE_FILES "Package libpe cmake config files" ${DEFAULT_LIBPE_PACK_DEV_FILES})
option(LIBPE_PACK_PKGCONF_FILES "Package libpe pkgconf files" OFF)

if(BUILD_LIBPE_ONLY OR BUILD_READPE_ONLY)
    set(ENABLE_TESTS OFF)
endif()

if(!VCPKG_ROOT)
    set(VCPKG_ROOT "$ENV{VCPKG_ROOT}")
endif()

add_subdirectory(extern)

if(MSVC)
    # vcpkg on Linux has issues hijacking find_package for Windows packages
    # Maybe I can figure out how this works better at some point
    # It might come down to running vcpkg through wine also
    # which probably means I would also run cmake through wine
    # Anyway this is a workaround for a niche case of a niche case
    if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
        include(cmake/toolchains/msvc-wine.cmake)
        set(OPENSSL_ROOT_DIR ${VCPKG_ROOT}/installed/x64-windows)
    endif()

    # SLURP_PE_FILE causes the analyzed PE file to be fully read into memory
    # instead of memory mapping it (which is a POSIX feature).
    # This is currently a workaround for Windows not supporting mmap
    set(LIBPE_SLURP_PE_FILE ON)

    # CRT_SECURE_NO_WARNINGS disables all warnings regarding the usage of
    # functions like sprintf instead of sprintf_s
    add_definitions(
        -D_CRT_SECURE_NO_WARNINGS
    )

    # MSVC debug builds also require urctbased.dll and VCRUNTIME140D.dll
    # This does not affect RelWithDebInfo hence why I would not package
    # these as they should be installed through Visual Studio and Windows

    # We are nice to windows users and just let them pack libcrypto
    install(PROGRAMS
        "${VCPKG_ROOT}/packages/openssl_x64-windows/bin/libcrypto-3-x64.dll"
        DESTINATION bin
    )
    set(LIBCRYPTO_PACKED TRUE)
endif()

if(CYGWIN)
    # TODO: These are probably not needed anymore
    ##  cp $(PEV_DIR)/userdb.txt $(ZIPDIR)
    ##  cp $(PEV_DIR)/windows/run.bat $(ZIPDIR)/
    install(PROGRAMS
        /usr/bin/cygwin1.dll
        /usr/bin/cygcrypto-3.dll
        /usr/bin/cygz.dll
        DESTINATION bin
    )
endif()

if(BUILD_DISASSEMBLER)
    add_subdirectory(lib/udis86/libudis86)
endif()

if(LIBPE_LINK_SSDEEP)
    add_subdirectory(lib/fuzzy)
endif()

add_subdirectory(lib/compat)

if(NOT BUILD_READPE_ONLY)
    add_subdirectory(lib/libpe)
endif()

if(NOT BUILD_LIBPE_ONLY)
    add_subdirectory(src)

    if(BUILD_READPE_PLUGINS)
        add_subdirectory(src/plugins)
    endif()
endif()

if(ENABLE_TESTS)
    include(${CMAKE_SOURCE_DIR}/cmake/tests.cmake)
endif()

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_SOURCE_DIR}/LICENSE)
set(CPACK_RESOURCE_FILE_README  ${CMAKE_SOURCE_DIR}/README.md)
set(CPACK_STRIP_FILES YES)

install(FILES
    ${CPACK_RESOURCE_FILE_LICENSE}
    ${CPACK_RESOURCE_FILE_README}
    TYPE DOC
)

include(CPack)
configure_file(${PROJECT_SOURCE_DIR}/cmake/cpackopt.cmake.in
               ${PROJECT_BINARY_DIR}/cpackopt.cmake
               @ONLY)
set(CPACK_PROJECT_CONFIG_FILE ${PROJECT_BINARY_DIR}/cpackopt.cmake)


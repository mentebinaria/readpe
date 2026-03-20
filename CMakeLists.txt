cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

project(readpe LANGUAGES C VERSION 1.0.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(BUILD_DISASSEMBLER "Build with basic disassembler support (deprecated)" OFF)
option(ENABLE_TESTS "Enable testing" On)

option(READPE_LEGACY "Build support for legacy executables by link name" ON)

# TODO:
# option(READPE_STANDALONE "Build separate executables" OFF)

option(LIBPE_STATIC "Link libpe into readpe staticially" Off)

set(DEFAULT_LINK_SSDEEP OFF)
if(LIBPE_STATIC)
    set(DEFAULT_LINK_SSDEEP ON)
endif()

option(LIBPE_LINK_SSDEEP "LINK SSDEEP GPL2 code into libpe" ${DEFAULT_LINK_SSDEEP})

include(dependencies)

if(MSVC)
    # vcpkg on Linux has issues hijacking find_package for Windows packages
    # Maybe I can figure out how this works better at some point
    # It might come down to running vcpkg through wine also
    # Anyway this is a workaround for a niche case of a niche case
    if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
        include(cmake/toolchains/msvc-wine.cmake)

        # My wine installation of msvc does not like my CRT
        add_definitions(
            -D_CRT_SECURE_NO_WARNINGS
        )

        set(OPENSSL_ROOT_DIR ${VCPKG_ROOT}/installed/x64-windows)
    endif()

    add_definitions(
        -D_SLURP_EXECUTABLE
    )

    # MSVC debug builds also require urctbased.dll and VCRUNTIME140D.dll
    # This does not affect RelWithDebInfo

    # TODO: This might not work on windows
    install(PROGRAMS
        "${VCPKG_ROOT}/installed/x64-windows/bin/libcrypto-3-x64.dll"
        DESTINATION bin
    )
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
add_subdirectory(lib/libpe)
add_subdirectory(src/plugins)
add_subdirectory(src)

if(ENABLE_TESTS)
    include("${CMAKE_SOURCE_DIR}/cmake/tests.cmake")
endif()

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README  "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_STRIP_FILES YES)

install(FILES
    "${CPACK_RESOURCE_FILE_LICENSE}"
    "${CPACK_RESOURCE_FILE_README}"
    TYPE DOC
)

include(CPack)
configure_file("${PROJECT_SOURCE_DIR}/cmake/cpackopt.cmake.in"
               "${PROJECT_BINARY_DIR}/cpackopt.cmake"
               @ONLY)
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_BINARY_DIR}/cpackopt.cmake")


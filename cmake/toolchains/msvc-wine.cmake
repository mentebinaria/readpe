# the name of the target operating system
set(CMAKE_SYSTEM_NAME Windows)

# Debug versions are only somewhat supported by msvc-wine
# See https://github.com/mstorsjo/msvc-wine for more info
# Anyway it's not worth it atm.
# Just use mingw64 for windows debug builds.

set(MSVC_WINE_ROOT_PATH "/opt/msvc")
set(VCPKG_ROOT "${MSVC_WINE_ROOT_PATH}/VC/vcpkg")

# enable_language(C,CXX)

# which compilers to use for C and C++
find_program(MSVC_WINE_CL
    NAMES
        cl
    REQUIRED
    PATHS
        "${MSVC_WINE_ROOT_PATH}/bin/x64"
)

# cl is used for both C and C++
set(CMAKE_C_COMPILER ${MSVC_WINE_CL})
set(CMAKE_CXX_COMPILER ${MSVC_WINE_CL})
set(ENV{CC} ${MSVC_WINE_CL})
set(ENV{CXX} ecl.exe)
set(ENV{PATH} "${MSVC_WINE_ROOT_PATH}:${VCPKG_ROOT}/installed/x64-windows/bin:$ENV{PATH}")

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH "${MSVC_WINE_ROOT_PATH}")

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# set(VCPKG_BUILD_TYPE release)


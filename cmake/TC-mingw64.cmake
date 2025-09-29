# the name of the target operating system
set(CMAKE_SYSTEM_NAME Windows)
# set(CMAKE_GENERATOR_PLATFORM "x64" CACHE STRING "" FORCE)

# enable_language(C,CXX)

# which compilers to use for C and C++
find_program(GNUCCi686W86Mingw32 NAMES
    i686-w64-mingw32-gcc
    i686-w64-mingw32-gcc-win32
    i686-w64-mingw32-gcc-posix
    REQUIRED
)
find_program(GNUPlusPlusi686W86Mingw32 NAMES
    i686-w64-mingw32-g++
    i686-w64-mingw32-g++-win32
    i686-w64-mingw32-g++-posix
    REQUIRED
)
set(CMAKE_C_COMPILER ${GNUCCi686W86Mingw32})
set(CMAKE_CXX_COMPILER ${GNUPlusPlusi686W86Mingw32})

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH /usr/i686-w64-mingw32)

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


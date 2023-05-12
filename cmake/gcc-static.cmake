# the name of the target operating system
set(CMAKE_SYSTEM_NAME linux-musl)

# which compilers to use for C and C++
set(CMAKE_C_COMPILER   gcc)
set(CMAKE_CXX_COMPILER g++)

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH
    /home/gogo/src/git.musl-libc.org/musl/lib
	/usr
)

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


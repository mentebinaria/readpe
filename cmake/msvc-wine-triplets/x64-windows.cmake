# VCPKG
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
# set(VCPKG_BUILD_TYPE release)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${VCPKG_ROOT_DIR}/scripts/toolchains/windows.cmake")

set(ENV{CC} cl.exe)
set(ENV{CXX} cl.exe)
set(ENV{PATH} "/opt/msvc/bin/x64:$ENV{PATH}")


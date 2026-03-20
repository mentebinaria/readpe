#!/usr/bin/env bash

ARCH=${ARCH:-"x64"}
BIN=${BIN:-"/opt/msvc/bin/$ARCH"}

ARCH=$(. "$BIN/msvcenv.sh" && echo $ARCH)
mkdir -p msvc-wine

export VCPKG_ROOT=/opt/msvc/VC/vcpkg

cat >msvc-wine/$ARCH-windows.cmake <<EOF
set(VCPKG_TARGET_ARCHITECTURE $ARCH)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
# set(VCPKG_BUILD_TYPE release)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE \${VCPKG_ROOT_DIR}/scripts/toolchains/mingw.cmake)

set(VCPKG_POLICY_ALLOW_OBSOLETE_MSVCRT enabled)
set(VCPKG_TARGET_IS_MINGW ON)
set(ENV{CC} x86_64-w64-mingw32-gcc)
set(ENV{CXX} x86_64-w64-mingw32-g++)

set(ENV{PATH} "$BIN:\$ENV{PATH}")
EOF

#  
# Install dependencies with classic mode
vcpkg install --vcpkg-root=$VCPKG_ROOT --triplet=x64-windows --overlay-triplets=./msvc-wine

cat >msvc-wine/$ARCH-windows.cmake <<EOF
set(VCPKG_TARGET_ARCHITECTURE $ARCH)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
# set(VCPKG_BUILD_TYPE release)
set(VCPKG_DISABLE_COMPILER_TRACKING ON)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE \${VCPKG_ROOT_DIR}/scripts/toolchains/windows.cmake)

set(ENV{CC} cl.exe)
set(ENV{CXX} cl.exe)

set(ENV{PATH} "$BIN:\$ENV{PATH}")
EOF

CMAKE_ARGS=(
    -G"Ninja Multi-Config"
    -DCMAKE_C_COMPILER=$BIN/cl
    -DCMAKE_CXX_COMPILER=$BIN/cl
    -DCMAKE_SYSTEM_NAME=Windows
    -DVCPKG_TARGET_TRIPLET=x64-windows
    # -DVCPKG_OVERLAY_TRIPLETS=./msvc-wine
    -DVCPKG_MANIFEST_INSTALL=OFF
    -DVCPKG_MANIFEST_MODE=ON
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
    # -DOpenSSL_DIR=$VCPKG_ROOT/installed/x64-windows/share/openssl
)

# Vcpkg uses pwsh and dumpbin to copy dependencies into the output directory for executables.
if command -v pwsh &>/dev/null; then
    echo "Powershell installed!"
    export PATH=$BIN:$PATH
else
    CMAKE_ARGS+=(
        -DVCPKG_APPLOCAL_DEPS=OFF
    )
fi

case $OSTYPE in
    darwin*)
        CMAKE_ARGS+=(
            # No winbind package available on macOS.
            # https://github.com/mstorsjo/msvc-wine/issues/6
            -DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded
        ) ;;
esac

# CMAKE_CONFIG=Debug
CMAKE_CONFIG=RelWithDebInfo
# CMAKE_CONFIG=Release

cmake -B msvc-wine -DCMAKE_BUILD_TYPE=${CMAKE_CONFIG}  "${CMAKE_ARGS[@]}"
cmake --build msvc-wine --config ${CMAKE_CONFIG} -- -v

cd msvc-wine
cpack -C ${CMAKE_CONFIG} -G 7Z


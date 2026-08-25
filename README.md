# readpe - PE Utils

Open source, full-featured, multiplatform command line toolkit to work with
and analyze PE (Portable Executables) binaries.

## How to get the source code

    git clone https://github.com/mentebinaria/readpe.git

## How to build on Linux

    cd readpe
    cmake -B build
    cmake --build build

**NOTE**: You may need to install CMake, and OpenSSL using your package manager. Examples:

    apt install cmake libssl-dev
    yum install cmake3 openssl-devel

## How to install on Linux

    cd readpe
    sudo cmake --install build
    echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/libpe.conf
    sudo ldconfig

## How to build on macOS

    cd readpe
    CFLAGS="-I/usr/local/opt/openssl/include/" LDFLAGS="-L/usr/local/opt/openssl/lib/" cmake -B build
    cmake --build build

**NOTE**: You may need to install CMake, OpenSSL and PCRE via [Homebrew](https://brew.sh):

    brew update
    brew install cmake openssl

## How to build on Windows using [Cygwin](https://cygwin.com))

    cd readpe
    cmake -B build
    cmake --build build

**NOTE**: The following packages must be installed along with your Cygwin:

| Category | Package       |
|----------|---------------|
| Archive  | zip           |
| Devel    | binutils      |
| Devel    | gcc-core      |
| Devel    | git           |
| Devel    | cmake         |
| Net      | libssl-devel  |

## How to build on Windows using Visual Studio [EXPERIMENTAL]

Open CMakeLists.txt in Visual Studio.

This is still highly experimental and bug reports are highly appriciated.

## FAQ

### Is this pev? / What happened to pev?

This repository used to be pev. We just moved the repository from a user account
to an organization account.

We also renamed the repository as the original name `pev` stood for PE Version
and does not reflect the current state of this application. We felt that readpe
was a good name as it is the most prominent tool.

### Where did libpe go?

Libpe has been absorbed into this repository since the two repositories are
tightly coupled and version controling them together made the most logical sense.

### I get a `fatal error: 'openssl/evp.h' file not found`. How can I fix that?

Please install OpenSSL for your system. Use a package manager to make things easier. If you're compiling pev in macOS,
make sure you've set both CFLAGS and LDFLAGS environment variables according.

Please check the [online documentation](https://pev.sourceforge.io/doc/manual/en_us/) for more details.

### I get an `error while loading shared libraries: libpe.so.1: cannot open shared object file: No such file or directory`. How can I fix that?

Please refer to ['How to install on Linux'](#how-to-install-on-linux).

## License

This project is licensed under the GNU General Public License version 2
with the exception of the contents of the lib folder which are licensed under the
GNU Lesser General Public License version 3.

A copy of these licenses can be found in the project root directory.

Files included as part of this software from outside sources:

| Files | Project/Author | License |
| --- | --- | --- |
| lib/compat/asprintf.c | [Thomas Gamper](https://github.com/eiszapfen2000/asprintf) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
| lib/compat/strlcat.c | [OpenBSD Project](https://www.openbsd.org/) | [ISC](https://opensource.org/license/isc) |
| lib/compat/getopt.c | [GNU C Library](https://sourceware.org/glibc) | [LGPL-2.1+](https://opensource.org/license/lgpl-2-1) |
| lib/compat/include/getopt.h | [GNU C Library](https://sourceware.org/glibc) | [LGPL-2.1+](https://opensource.org/license/lgpl-2-1) |
| lib/compat/include/unistd.h | [win32ports/unistd_h](https://github.com/win32ports/unistd_h) | [MIT](https://opensource.org/license/mit) |
| lib/compat/include/sys/queue.h | [FreeBSD Project](https://www.freebsd.org/) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |

Furthermore src/dylib.c, src/dylib.h, and src/stack.h were originally written under the [MIT License](https://opensource.org/license/mit) by Jardel Weyrich.

### Static linked libraries

#### uthash

Project can be found [here](https://troydhanson.github.io/uthash/)
Source code can be found [here](https://github.com/troydhanson/uthash)
Licensed under [BSD-1-Clause](https://opensource.org/license/bsd-1-clause)

#### dirent

Project can be found [here](https://github.com/tronkko/dirent)
Licensed under [MIT License](https://opensource.org/license/mit)

#### dlfcn-win32

Project can be found [here](https://github.com/dlfcn-win32/dlfcn-win32)
Licensed under [MIT License](https://opensource.org/license/mit)

### Dynamic linked libraries

#### OpenSSL

Project can be found [here](https://openssl-library.org/)
Source Code can be found [here](https://github.com/openssl/openssl)
Licensed under [Apache-2.0](https://opensource.org/license/apache-2.0)


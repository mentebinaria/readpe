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
with the exception of the contents of lib/libpe which are licensed under the
GNU Lesser General Public License version 3.

A copy of these licenses can be found respectively
in the project root and lib/libpe folders.

### Acknowledgments

Sources are given as acknowledgement for the original authors
and do not represent an endorsement of this project by said authors.

#### lib/compat/asprintf.c

Code written by [Thomas Gamper](https://github.com/eiszapfen2000/asprintf)
Licensed under [BSD-3-Clause License](https://opensource.org/license/bsd-3-clause)

#### lib/compat/strlcat.c

Code from the [OpenBSD Project](https://www.openbsd.org/)
Licensed under [ISC License](https://opensource.org/license/isc)

#### lib/compat/getopt.c lib/compat/include/getopt.h

Code from the [GNU C Library](https://sourceware.org/glibc)
Licensed under [LGPL-2.1+](https://opensource.org/license/lgpl-2-1)

#### lib/compat/include/unistd.h

Code from [win32ports/unistd_h](https://github.com/win32ports/unistd_h)
Licensed under the [MIT License](https://opensource.org/license/mit)

#### lib/compat/include/sys/queue.h

Code from the [FreeBSD Project](https://www.freebsd.org/)
Licensed under [BSD-3-Clause License](https://opensource.org/license/bsd-3-clause)

#### lib/fuzzy

Code from [SSDeep Project](https://ssdeep-project.github.io/ssdeep/index.html)
Licensed under [GPL-2.0+](https://opensource.org/license/gpl-2.0)

#### lib/udis86 include/udis86.h

Code from [Udis86 library](https://sourceforge.net/projects/udis86/)
Licensed under [BSD-2-Clause License](https://opensource.org/license/bsd-2-clause)

#### src/dylib.c src/dylib.h src/stack.h

Code written by Jardel Weyrich
Licensed under [MIT License](https://opensource.org/license/mit)

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


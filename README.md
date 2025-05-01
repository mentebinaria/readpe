# readpe - PE Utils

Open source, full-featured, multiplatform command line toolkit to work with
and analyze PE (Portable Executables) binaries.

## How to get the source code

    git clone https://github.com/mentebinaria/readpe.git

## How to build on Linux

    cd readpe
    make

**NOTE**: You may need to install OpenSSL using your package manager. Examples:

    apt install libssl-dev
    yum install openssl-devel

## How to install on Linux

    cd readpe
    sudo make install
    echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/libpe.conf
    sudo ldconfig

## How to build on macOS

    cd readpe
    CFLAGS="-I/usr/local/opt/openssl/include/" LDFLAGS="-L/usr/local/opt/openssl/lib/" make

**NOTE**: You may need to install OpenSSL and PCRE via [Homebrew](https://brew.sh):

    brew update
    brew install openssl

## How to build on Windows (via [Cygwin](https://cygwin.com))

    cd readpe
    make
    make zip

**NOTE**: The following packages must be installed along with your Cygwin:

| Category | Package       |
|----------|---------------|
| Archive  | zip           |
| Devel    | binutils      |
| Devel    | gcc-core      |
| Devel    | git           |
| Devel    | make          |
| Net      | libssl-devel  |

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

A copy of these licenses can be found respectively in the project root and lib/libpe.

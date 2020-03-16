# pev

Open source, full-featured, multiplatform command line toolkit to work with PE (Portable Executables) binaries.

[![Build Status](https://travis-ci.org/merces/pev.png)](https://travis-ci.org/merces/pev)

## How to get the source code

    git clone --recursive https://github.com/merces/pev.git

## How to build on Linux

    cd pev
    make

**NOTE**: You may need to install OpenSSL using your package manager. Examples:

    apt install libssl-dev
    yum install openssl-devel

## How to build on macOS

    cd pev
    CFLAGS="-I/usr/local/opt/openssl/include/" LDFLAGS="-L/usr/local/opt/openssl/lib/" make

**NOTE**: You may need to install OpenSSL and PCRE via [Homebrew](http://brew.sh/):

    brew update
    brew install openssl

## How to build on Windows (via [Cygwin](http://cygwin.com/))

    cd pev
    make
    make zip

**NOTE**: The following packages must be installed along with your Cygwin:

- gcc-core
- binutils
- make
- zip
- openssl-devel
- git (just to clone the repository and make things easier)

## FAQ

### I get a `fatal error: 'openssl/evp.h' file not found`. How can I fix that?

Please install OpenSSL for your system. Use a package manager to make things easier. If you're compiling pev in macOS,
make sure you've set both CFLAGS and LDFLAGS environment variables according.

### I get the one of the following errors when trying to compile with `make` command:

    $ make
    make[1]: *** No rule to make target 'all'.  Stop.
    make[1]: Leaving directory '/home/user/pev/lib/libpe'
    make: *** [Makefile:9: all] Error 2

    $ make
    cd lib/libpe && /Library/Developer/CommandLineTools/usr/bin/make all
    make[1]: *** No rule to make target `all'.  Stop.
    make: *** [all] Error 2

It seems libpe is missing. Have you forgot the `--recursive` switch of git clone command?
Anyway, download libpe source code, put it in the right directoy and try again:

    cd pev/lib
    rmdir libpe
    git clone https://github.com/merces/libpe.git
    cd ..
    make

Please check the [online documentation](http://pev.sourceforge.net/doc/manual/en_us) for more details.

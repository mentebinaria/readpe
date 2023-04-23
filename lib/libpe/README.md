# libpe

[![LGPLv3](https://www.gnu.org/graphics/lgplv3-88x31.png)](http://www.gnu.org/licenses/lgpl.html) ![C/C++ CI](https://github.com/merces/libpe/workflows/C/C++%20CI/badge.svg)

The PE library used by [pev](https://github.com/merces/pev) - the PE file toolkit purely written in C and available to many platforms.

## Features

- Support for both 32 and 64-bits PE files.
- ssdeep support (built-in libfuzzy).
- Disassemble support (built-in libudis86).
- Imphash support.
- Crypographic digests calculation (using OpeenSSL).

## How to get the source code

    git clone https://github.com/merces/libpe.git

## How to build on Linux

    cd libpe
    make

**NOTE**: You may need to install OpenSSL using your package manager. Examples:

    apt install libssl-dev
    yum install openssl-devel

## How to build on macOS

    cd libpe
    CFLAGS="-I/usr/local/opt/openssl/include/" LDFLAGS="-L/usr/local/opt/openssl/lib/" make

**NOTE**: You may need to install OpenSSL and PCRE via [Homebrew](http://brew.sh/):

    brew update
    brew install openssl

## Usage example

```c
#include <stdio.h>
#include "../include/libpe/pe.h"

int main(int argc, char *argv[]) {

    if (argc < 2)
        return 1;

    pe_ctx_t ctx;
    pe_err_e err = pe_load_file(&ctx, argv[1]);

    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return 1;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return 1;
    }

    if (!pe_is_pe(&ctx))
        return 1;

    printf("Entrypoint: %#llx\n", ctx.pe.entrypoint);

    return 0;
}
```

Compile with:

    cc -o example example.c -lpe

## Troubleshooting
- **Error while loading shared libraries: libpe.so.1**
  - The prefix used in libpe's makefile is `/usr/local/lib`
  - If your system isn't set to look here, you can add it to `ld.so.conf`
  - Alternatively, change prefix to whatever suits, ie. `/usr/lib`
  
- **Undefined reference to `log`**
  - Linux' glibc does not define math functions, they live instead in libm
  - Link against both libpe and libm to fix this (ie. `-lm`)

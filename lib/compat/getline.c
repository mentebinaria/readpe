/*
    getline.c - Standard C implimentation of POSIX getline function

    Copyright (C) 2026 readpe authors

    This file is part of readpe.

    readpe is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    readpe is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "compat.h"

#include <stdlib.h>

// #include <errno.h>

// #define ENOMEM 12
// #define EINVAL 22

#define LINELEN 80
#define LINEMAX 0x7FFFFFFF

ssize_t readpe_getline(char **restrict lineptr, size_t *restrict n,
                       FILE *restrict stream)
{

    if (lineptr == NULL || n == NULL) {
        // errno = EINVAL;
        return -1;
    }

    if (stream == NULL) {
        // errno = EINVAL;
        return -1;
    }

    if (*lineptr == NULL) {
        *lineptr = malloc(LINELEN);
        if (*lineptr == NULL) {
            // errno = ENOMEM;
            return -1;
        }
        *n = LINELEN;
    }

    size_t i;

    for (i = 0; i < LINEMAX; ++i) {
        int c = fgetc(stream);
        if (c == EOF) {
            return -1;
        }

        if (i > *n) {
            char *tempptr = realloc(*lineptr, *n + LINELEN);
            if (tempptr == NULL) {
                // errno = ENOMEM;
                return 1;
            }

            *lineptr = tempptr;
            *n += LINELEN;
        }

        (*lineptr)[i] = (char) c;
        if (c == '\n') {
            ++i;
            break;
        }
    }

    return (ssize_t) i;
}

#undef LINELEN
#undef LINEMAX


/*
    strndup.c - Standard C implimentation of POSIX strndup function

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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

char *readpe_strndup(const char *src, size_t size)
{
    if (size == 0) {
        return NULL;
    }

    char *str = calloc(size + 1, sizeof(char));

    if (! str) {
        return NULL;
    }

    strncpy(str, src, size);
    str[size] = '\0';

    return str;
}


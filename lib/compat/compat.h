/*
    compat.h - Compatability header for libpe/readpe

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

/*
 * Note to naming of POSIX functions:
 * MSVC has deprecated versions of POSIX functions
 * Hence most functions have an added readpe_ prefix
 */

#pragma once
#ifndef READPE_COMPAT_H
#define READPE_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(__unix__) || defined(__unix)                                       \
    || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

// ----------- //
// -- POSIX -- //
// ----------- //
#if defined(_POSIX_VERSION)

#include <strings.h>
#include <sys/stat.h>

#define readpe_access      access
#define readpe_getline     getline
#define readpe_mkdir       mkdir
#define readpe_strdup      strdup
#define readpe_strncasecmp strncasecmp
#define readpe_strndup     strndup
// -- POSIX END --

// --------------- //
// -- MSVC/UCRT -- //
// --------------- //
#elif defined(_MSC_VER)

#include <direct.h>
#include <io.h>
#include <stdint.h>

typedef unsigned int __mode_t;
typedef __mode_t     mode_t;
typedef int64_t      ssize_t;

#define F_OK               0
#define readpe_access      _access
#define readpe_mkdir(p, x) _mkdir(p)
#define readpe_strncasecmp _strnicmp

#if (__STDC_VERSION__ >= 202311L)
#define readpe_strdup  strdup
#define readpe_strndup strndup
#else
#define readpe_strdup _strdup
char *readpe_strndup(const char *src, size_t size);
#endif

ssize_t readpe_getline(char **restrict lineptr, size_t *restrict n,
                       FILE *restrict stream);
// -- MSVC/UCRT END --

// ---------------- //
// -- Standard C -- //
// ---------------- //
#else
/* TODO:
 * readpe_getline     Already implemented for MSVC
 * readpe_strndup     Already implemented for MSVC / C23 Standard
 * readpe_strdup      C23 Standard
 * readpe_access      Doable by trying to open the file
 * readpe_strncasecmp Doable but unicode makes this harder
 * readpe_mkdir       Impossible; Ironically easy with C++
 */
#error "Your compiler or operating system is currently not supported"
// -- Standard C END --
#endif

int    asprintf(char **restrict strp, const char *restrict fmt, ...);
int    vasprintf(char **restrict strp, const char *restrict fmt, va_list ap);
size_t bsd_strlcat(char *dst, const char *src, size_t siz);

#ifdef __cplusplus
}
#endif

#endif


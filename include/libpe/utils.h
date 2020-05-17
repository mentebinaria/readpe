/*
    libpe - the PE library

    Copyright (C) 2010 - 2017 libpe authors
    
    This file is part of libpe.

    libpe is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libpe is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LIBPE_UTILS_H
#define LIBPE_UTILS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef pe_utils_min
// IMPORTANT: Do not pass expressions as arguments because this macro evaluates each argument more than once!
#  define pe_utils_min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef pe_utils_max
// IMPORTANT: Do not pass expressions as arguments because this macro evaluates each argument more than once!
#  define pe_utils_max(a, b) (((a) > (b)) ? (a) : (b))
#endif

bool pe_utils_str_ends_with(const char *str, const char *suffix);
char *pe_utils_str_inplace_ltrim(char *str);
char *pe_utils_str_inplace_rtrim(char *str);
char *pe_utils_str_inplace_trim(char *str);
char *pe_utils_str_array_join(char *strings[], size_t count, char delimiter);
void pe_utils_str_widechar2ascii(char *output, const char *widechar, size_t size);

int pe_utils_round_up(int num_to_round, int multiple);
int pe_utils_is_file_readable(const char *path);

// IMPORTANT: This is not thread-safe - not reentrant.
const char *pe_utils_get_homedir(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

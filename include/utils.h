/*
	pev - the PE file analyzer toolkit

	utils.h

	Copyright (C) 2012 - 2014 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool utils_str_ends_with(const char *str, const char *suffix);
char *utils_str_inplace_ltrim(char *str);
char *utils_str_inplace_rtrim(char *str);
char *utils_str_inplace_trim(char *str);
char *utils_str_array_join(char *strings[], size_t count, char delimiter);

int utils_round_up(int num_to_round, int multiple);
int utils_is_file_readable(const char *path);

// IMPORTANT: This is not thread-safe - not reentrant.
const char *utils_get_homedir(void);

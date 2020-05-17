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

#include "libpe/utils.h"
#include "libpe/error.h"
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <inttypes.h>

bool pe_utils_str_ends_with(const char *str, const char *suffix) {
	if (str == NULL || suffix == NULL)
		return 0;

	size_t len_str = strlen(str);
	size_t len_suffix = strlen(suffix);
	if (len_suffix > len_str)
		return 0;

	return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

char *pe_utils_str_inplace_ltrim(char *str) {
	char *ptr = str;

	while (*ptr != '\0' && isspace(*ptr))
		ptr++;

	return ptr;
}

char *pe_utils_str_inplace_rtrim(char *str) {
	const size_t length = strlen(str);
	char *ptr = str + length - 1;

	while (ptr != str && isspace(*ptr))
		ptr--;

	// Move back to space.
	ptr++;

	// Replace it with '\0'.
	*ptr = '\0';

	return str;
}

char *pe_utils_str_inplace_trim(char *str) {
	char *begin = str;

	// leading spaces
	while (*begin != '\0' && isspace(*begin))
		begin++;

	if (*begin == '\0') // nothing left?
		return begin;

	// Trailing spaces
	const size_t length = strlen(begin);
	char *end = begin + length - 1;
	while (end != begin && isspace(*end))
		end--;

	end++; // Move to space

	// Overwrite space with null terminator
	*end = '\0';

	return begin;
}

char *pe_utils_str_array_join(char *strings[], size_t count, char delimiter) {
	if (strings == NULL || strings[0] == NULL)
		return strdup("");

	// Count how much memory the resulting string is going to need,
	// considering delimiters for each string. The last delimiter will
	// be a NULL terminator;
	size_t result_length = 0;
	for (size_t i = 0; i < count; i++) {
		result_length += strlen(strings[i]) + 1;
	}

	// Allocate the resulting string.
	char *result = malloc(result_length);
	if (result == NULL)
		return NULL; // Return NULL because it failed miserably!

	// Null terminate it.
	result[--result_length] = '\0';

	// Join all strings.
	char ** current_string = strings;
	char * current_char = current_string[0];
	for (size_t i = 0; i < result_length; i++) {
		if (*current_char != '\0') {
			result[i] = *current_char++;
		} else {
			// Reached the end of a string. Add a delimiter and move to the next one.
			result[i] = delimiter;
			current_string++;
			current_char = current_string[0];
		}
	}

	return result;
}

void pe_utils_str_widechar2ascii(char *output, const char *widechar, size_t length) {
	// quick & dirty UFT16 to ASCII conversion
	for (size_t p = 0; p <= length; p++) {
		memcpy(output + p, (uint16_t *)(widechar) + p, 1);
	}
}

int pe_utils_round_up(int num_to_round, int multiple) {
	if (multiple == 0)
		return 0;
	return (num_to_round + multiple - 1) / multiple * multiple;
}

int pe_utils_is_file_readable(const char *path) {
	// Open the file.
	const int fd = open(path, O_RDWR);
	if (fd == -1) {
		//perror("open");
		return LIBPE_E_OPEN_FAILED;
	}

	// Stat the fd to retrieve the file informations.
	// If file is a symlink, fstat will stat the pointed file, not the link.
	struct stat stat;
	int ret = fstat(fd, &stat);
	if (ret == -1) {
		close(fd);
		//perror("fstat");
		return LIBPE_E_FSTAT_FAILED;
	}

	// Check if we're dealing with a regular file.
	if (!S_ISREG(stat.st_mode)) {
		close(fd);
		//fprintf(stderr, "%s is not a file\n", path);
		return LIBPE_E_NOT_A_FILE;
	}

	close(fd);

	return LIBPE_E_OK;
}

// IMPORTANT: This is not thread-safe - not reentrant.
const char *pe_utils_get_homedir(void) {
	const char *homedir = getenv("HOME");
	if (homedir != NULL)
		return homedir;

	errno = 0;
	struct passwd *pwd = getpwuid(getuid());

	return pwd == NULL ? NULL : pwd->pw_dir;
}

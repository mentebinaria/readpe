/*
	libpe - the PE library

	Copyright (C) 2010 - 2014 libpe authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "utils.h"
#include "error.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

char *str_inplace_ltrim(char *str) {
	char *ptr = str;

	while (*ptr != '\0' && isspace(*ptr))
		ptr++;

	return ptr;
}

char *str_inplace_rtrim(char *str) {
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

char *str_inplace_trim(char *str) {
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

int pe_is_file_readable(const char *path) {
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

int pe_load_config(const char *path, callback_t cb) {
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	char line[1024];

	while (fgets(line, sizeof(line), fp) != NULL) {
		// comments
		if (*line == '#')
			continue;

		// remove newline
		for (size_t i=0; i < sizeof(line); i++) {
			if (line[i] == '\n' || i == sizeof(line) - 1) {
				line[i] = '\0';
				break;
			}
		}

		char *param = strtok(line, "=");
		char *value = strtok(NULL, "=");
		const char *trimmed_param = str_inplace_trim(param);
		const char *trimmed_value = str_inplace_trim(value);

		//printf("DEBUG: '%s'='%s'\n", trimmed_param, trimmed_value);
		cb(trimmed_param, trimmed_value);
	}

	fclose(fp);

	return 0;
}

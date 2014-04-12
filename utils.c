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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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

	while (fgets(line, sizeof(line), fp)) {
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
		const char *param = strtok(line, "=");
		const char *value = strtok(NULL, "=");

		cb(param, value);
	}

	fclose(fp);

	return 0;
}

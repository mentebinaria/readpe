/* vim:set ts=4 sw=4 noet: */
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

bool pe_utils_str_ends_with(const char* text, const char* pattern)
{
	if (!text || !pattern)
		return false;

	const size_t n = strspn(pattern, text);
	if (*(pattern + n) != '\0')
		return false;

	return !memcmp(text + strlen(text) - n, pattern, n);
}

char *pe_utils_str_inplace_ltrim(char *str) {
	return str + strspn( str, " \f\n\r\t\v" );
}

char *pe_utils_str_inplace_rtrim(char *str) {
	const size_t length = strlen(str);
	char *ptr = str + length - 1;

	// If str points to a empty string, ptr will point
	// to a place before str...
	while (ptr > str && isspace(*ptr))
		ptr--;

	// Move back to space.
	// Replace it with '\0'.
	*++ptr = 0;

	return str;
}

char *pe_utils_str_inplace_trim(char *str) {
	char *ptr;

	ptr = pe_utils_str_inplace_ltrim( str );
	return pe_utils_str_inplace_rtrim( ptr );
}

char *pe_utils_str_array_join(char *strings[], size_t count, char delimiter) {
	size_t i;

	if (strings == NULL || strings[0] == NULL)
		return strdup("");

	// Count how much memory the resulting string is going to need,
	// considering delimiters for each string. The last delimiter will
	// be a NUL terminator;
	size_t result_length = 0;
	for (i = 0; i < count; i++) {
		result_length += strlen(strings[i]) + 1;
	}

	// Allocate the resulting string.
	char *result = malloc(result_length);
	if (result == NULL)
		return NULL; // Return NULL because it failed miserably!

	// FIX: Instead of copying char by char, uses sprintf/strcpy to do it.
	char *p;

	p = result;
	for ( i = 0; i < count - 1; i++ )
	{
		int size;

		size = sprintf( p, "%s%c", strings[i], delimiter );
		p += size;
	}
	strcpy( p, strings[i] );

//	
//	// Null terminate it.
//	result[--result_length] = '\0';
//
//	// Join all strings.
//	char **current_string = strings;
//	char *current_char = current_string[0];
//	for (size_t i = 0; i < result_length; i++) {
//		if (*current_char != '\0') {
//			result[i] = *current_char++;
//		} else {
//			// Reached the end of a string. Add a delimiter and move to the next one.
//			result[i] = delimiter;
//			current_string++;
//			current_char = current_string[0];
//		}
//	}

	return result;
}

static char windows1252_char( uint16_t chr )
{
	// windows-1252 Unicode codepoints from 0x80 to 0x9f.
	// These 32 unicode codepoints was taken from Wikipedia:
	// 	  https://en.wikipedia.org/wiki/Windows-1252
	static const uint16_t w1252chrs[] = {
		0x20ac,
		0,			// invalid
		0x201a,	0x0192,	0x201e,	0x2026,	0x2020,	0x2021,	0x02c6,	0x2030,
		0x0160,	0x2039,	0x0152,
		0,			// invalid
		0x017d,
		0,			// invalid
		0,			// invalid
		0x2018, 0x2019,	0x201c,	0x201d,	0x2022,	0x2013,	0x2014,	0x02dc,
		0x2122,	0x0161,	0x203a,	0x0153,
		0,			// invalid
		0x017e,	0x0178
	};

	// Return any char in range of ASCII or ISO-8859-1.
	// FIXME: 0xa0 is a 'non breaking space'. It could be converted to ' ',
	//		  but I didn't. Feel free to do it if you need.
	if ( chr <= 0x7f || ( chr >= 0xa0 && chr <= 0xff ) )
		// if ( chr == 0xa0 ) return ' '; else
		return chr;

	// Return any char inside WINDOWS-1252 codepage range of 0x80 to 0x9f.
	for ( unsigned int i = 0; i < sizeof w1252chrs / sizeof w1252chrs[0]; i++ )
		if ( chr == w1252chrs[i] )
			return 0x80 + i;

	// Any other char returns 0 (to ignore).
    return 0;
}

void pe_utils_str_widechar2ascii(char *output, size_t output_size, const char *widechar, size_t widechar_count) {
	// FIX: Quick & dirty UFT16 to WINDOWS-1252 conversion
	size_t length = pe_utils_min(output_size - 1, widechar_count);
	uint16_t *p = (uint16_t *)widechar;
	while (length--) {
		char c = windows1252_char( *p );

		// ignores "invalid" char.
		if ( c )
			*output++ = c;

		p++;
	}

	*output = '\0';
}

// FIX: Don't need this here. Only used in pesec.c!
#if 0
int pe_utils_round_up(int num_to_round, int multiple) {
	if (multiple == 0)
		return 0;

	return (num_to_round + multiple - 1) / multiple * multiple;
}
#endif

// FIXME: Don't need to open the file!
// FIXME: I believe I saw the same routine inside another function in pe.c.
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

	// FIXME: Instead of using getpwuid() we could use
	//				getpwuid_r() to make this function 'thread-safe'.
	errno = 0;
	struct passwd *pwd = getpwuid(getuid());

	return pwd == NULL ? NULL : pwd->pw_dir;
}

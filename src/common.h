/*
	pev - the PE file analyzer toolkit
	
	common.h - common defitions for pev toolkit

	Copyright (C) 2012 pev authors

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

#ifndef COMMON_H
#define COMMON_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include <pe.h>
#include "output.h"

#define EXIT_ERROR(msg) \
{ \
	fprintf(stderr, "%s\n", msg); \
	exit(1); \
}

#define MAX_MSG 80
#define VERSION "0.60"
#define TOOLKIT "from pev " VERSION " <http://pev.sf.net> toolkit"
#define COPY \
"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n" \
"This is free software: you are free to change and redistribute it.\n" \
"There is NO WARRANTY, to the extent permitted by law."

#define SPACES 32 // spaces # for text-based output

void *xmalloc(size_t size);

#endif

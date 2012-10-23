/*
	pev - the PE file analyzer toolkit
	
	pestr.h - definitions for pestr.c

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

#ifndef PESTR_H 
#define PESTR_H

#include "common.h"
#include <ctype.h>
#include <pcre.h>

#define PROGRAM "pestr"
#define BUFSIZE 4
#define OVECCOUNT 30
#define LINE_BUFFER 2048

struct options {
   unsigned short strsize;
	bool offset;
	bool section;
	bool functions;
	bool net;
};

void parse_options(int argc, char *argv[]);

#endif

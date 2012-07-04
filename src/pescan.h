/*
	pev - the PE file analyzer toolkit
	
	pescan - definitions for pescan.c

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

#ifndef PESCAN_H 
#define PESCAN_H

#include "common.h"
#include <ctype.h>

#define PROGRAM "pescan"

void parse_options(int argc, char *argv[]);

struct options {
	bool show_offsets;
};

struct options config;

#endif

/*
	pev - PE information dump utility

	Copyright (C) 2010 - 2011 Coding 40°

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

#ifndef PARSER_H
#define PARSER_H
#include <stdbool.h>
#include <string.h>
#include "common.h"

void parse_options(int argc, char *argv[]);

struct options {
	bool all;
	bool dos;
	bool coff;
	bool opt;
	bool dirs;
	bool resources;
	bool product;
	bool all_headers;
	bool all_sections;
	short format;
};

#endif /* PARSER_H */

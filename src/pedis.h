/*
	pedis - PE section disassembler

	Copyright (C) 2010 - 2012 Fernando Mercês

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

#ifndef READPE_H 
#define READPE_H
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define PROGRAM "pedis"
#define VERSION "0.50"

#define SYN_ATT 1
#define SYN_INTEL 0

void parse_options(int argc, char *argv[]);

struct options {
	bool all_sections;
	char *section;
	bool syntax;
};

struct options config;

#endif

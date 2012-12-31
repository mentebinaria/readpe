/*
	pev - the PE file analyzer toolkit
	
	output.h - definitions for output results in differents formats
	
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

#ifndef OUTPUT_H
#define OUTPUT_H

void parse_format(const char *optarg);
void output(char *field, char *value);

typedef enum {
	FORMAT_TEXT = 1,
	FORMAT_HTML = 2,
	FORMAT_XML = 3,
	FORMAT_CSV = 4
} format_e;

extern format_e format;

#endif

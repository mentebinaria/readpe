/*
	pev - the PE file analyzer

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

#include "include/output.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define SPACES 30

/* OUTPUT FORMATS */
#define TEXT 1
#define HTML 2
#define XML 3
#define CSV 4

extern struct options config;

void to_text(char *field, char *value)
{
	size_t field_size = field ? strlen(field) : 0;
	
	if (field && value)
		printf("%s:%*c%s\n", field, (int) (SPACES-field_size), ' ', value);
	else if (field)
		printf("\n%s\n", field);
	else if (value)
		printf("%*c%s\n", (int) (SPACES-field_size+1), ' ', value);
}

void to_csv(const char *field, char *value)
{
	if (field && value)
		printf("%s,%s\n", field, value);
	else if (field)
		printf("\n%s\n", field);
	else if (value)
		printf(",%s\n", value);
}

void to_xml(char *field, char *value)
{
	// TODO output a valid xml
	if (value && field)
		printf("<%s>%s</%s>\n", field, value, field);
	else if (field)
		printf("<%s>\n", field);
}

void to_html(char *field, char *value)
{
	// TODO output a valid html
   	if (field && value)
		printf("<span><b>%s:</b> %s</span><br />\n", field, value);
	else if (field)
		printf("\n<p>%s</p>\n", field);
	else if (value)
		printf("<span>%s</span><br />\n", value);
}

void output(char *field, char *value)
{
	switch (config.format)
	{
		case TEXT:
			to_text(field, value);
			break;
			
		case CSV:
			to_csv(field, value);
			break;
			
		case XML:
			to_xml(field, value);
			break;
			
		case HTML:
			to_html(field, value);
			break;
			
		default:
			break;
	}
}

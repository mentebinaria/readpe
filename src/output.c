/*
	pev - the PE file analyzer toolkit
	
	output.c - functions to output results in different formats

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

#include <ctype.h>
#include "output.h"
#include "common.h"

format_e format;

void parse_format(const char *optarg)
{
	if (! strcmp(optarg, "text"))
		format = FORMAT_TEXT;
	else if (! strcmp(optarg, "xml"))
		format = FORMAT_XML;
	else if (! strcmp(optarg, "csv"))
		format = FORMAT_CSV;
	else if (! strcmp(optarg, "html"))
		format = FORMAT_HTML;
	else
		EXIT_ERROR("invalid format option");
}

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
	switch (format)
	{
		case FORMAT_CSV:
			to_csv(field, value);
			break;
			
		case FORMAT_XML:
			to_xml(field, value);
			break;
			
		case FORMAT_HTML:
			to_html(field, value);
			break;
			
		case FORMAT_TEXT:
		default:
			to_text(field, value);
			break;
	}
}

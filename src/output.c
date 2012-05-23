/*
	pev - the PE file analyzer toolkit
	
	output.c - functions to output results in different formats

	Copyright (C) 2012 Fernando Mercês
	Copyright (C) 2012 Gabriel Duarte

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

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include "output.h"
#include "common.h"

extern format_e format;

void parse_format(const char *optarg)
{
	start_out = 0;
	end_out = 0;
	
	if (! strcmp(optarg, "text"))
		format = FORMAT_TEXT;
	else if (! strcmp(optarg, "xml"))
	{
		format = FORMAT_XML;
	}
	else if (! strcmp(optarg, "csv"))
		format = FORMAT_CSV;
	else if (! strcmp(optarg, "html"))
		format = FORMAT_HTML;
	else
		EXIT_ERROR("invalid format option");
}
 /* intended to solve the problems of opening and closing headers */
void start_output()
{
	start_out = 1;
} /* to be implemented */


void end_output()
{
	end_out = 1;
 	output(NULL, NULL); 
 	/* wrapper to call output before the end
	 *to close the document.
	 */
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
	// TODO output a valid xml ???
	int i;
	char c;
	char *pt = NULL;
	
	if(1 == start_out)
	{
		printf("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" \
														  "<PE>\n");
		start_out = 0;
	}
	
	if(field) /* this is always valid or not? I don't think so... */
	{
		for(i = 0; field[i]; ++i);
	
		pt = (char*) malloc(sizeof(char*)*i);
		
		strcpy(pt, field);
		
		/* replace undesired characters */
	
		for(i = 0; *(pt+i); ++i)
		{
			if(*(pt+i) == ' ')
				*(pt+i) =  '_';
			if(*(pt+i) == '\\' || *(pt+i) == '/' || *(pt+i) == '(' 	
							 || *(pt+i) == ')' || *(pt+i) == '.')
				*(pt+i) = '_';
			if(isupper(*(pt+i)))
			{
				c = *(pt+i);
				*(pt+i) =  tolower(c);
			}
		}
		
		/* remove double underscores */
		
		for(i = 0; *(pt+i); ++i)
			if(*(pt+i) == '_' && *(pt+i+1) == '_')
				*(pt+i+1) = '\b';
			
			
		if (value)
			printf("\t<%s>%s</%s>\n", pt, value, pt);
		else
			printf("<%s></%s>\n", pt, pt);
		
		free((char*)pt);
	}
	
	if(1 == end_out)
	{
		printf("</PE>\n");
		end_out = 0;
	}
}
	


void to_html(char *field, char *value)
{
	// TODO output a valid html
	
	if(1 == start_out)
	{
		printf("<html>\n  <head>\n    <title>PE</title>\n  </head>\n"
				"<body>\n");
		start_out = 0;
	}
	

	if (field && value)
		printf("<span><b>%s:</b> %s</span><br />\n", field, value);
	else if (field)
		printf("\n<p>%s</p>\n", field);
	else if (value)
		printf("<span>%s</span><br />\n", value);
	
	if(1 == end_out)
	{
		printf("\n</body>\n</html>\n");
		end_out = 0;
	}
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

#define TEXT 1
#define HTML 2
#define XML 3
#define CSV 4

#include "include/output.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define SPACES 30

extern struct options config;

void delspace(char *str)
{
	char *p1 = str, *p2 = str;

	do  
		while (*p2 == ' ')
			p2++;
	while (*p1++ = *p2++);
}

void to_text(char *field, char *value)
{
	size_t field_size = field ? strlen(field) : 0;
	
	if (field && value)
		printf("%s:%*c%s\n", field, (int) (SPACES-field_size), ' ', value);
	else if (field)
		printf("\n%*c** %s **\n",(int) (SPACES-field_size)/2+1, ' ', field);
	else if (value)
		printf("%*c%s\n", (int) (SPACES-field_size+1), ' ', value);
}

void to_csv(char *field, char *value)
{
	printf("%s,%s\n", field, value);
}

void to_xml(char *field, char *value)
{
	delspace(field);

	if (value && field)
		printf("<%s>%s</%s>\n", field, value, field);
	else if (field)
		printf("<%s>\n", field);
}

void to_html(char *field, char *value)
{
	printf("<p>%s: %s</p>\n", field, value);
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

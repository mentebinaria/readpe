/* OUTPUT FORMATS */

#include "include/output.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define SPACES 30
#define TEXT 1
#define HTML 2
#define XML 3
#define CSV 4





extern struct options config;
const char *prev_field;

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

void to_csv(const char *field, char *value)
{
    if (prev_field && field)
    {
        if (!strcmp(field, prev_field))
            printf("%s,\t", value);
    }
    
    printf("%s,\t%s\n", field ? field : "", value ? value : "\n");
        
    prev_field = field;
    

}

void to_xml(char *field, char *value)
{
	// TODO remove spaces from xml fields name
	if (value && field)
		printf("<%s>%s</%s>\n", field, value, field);
	else if (field)
		printf("<%s>\n", field);
}

void to_html(char *field, char *value)
{
	// TODO validate this code
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

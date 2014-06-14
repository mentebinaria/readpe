/*
	pev - the PE file analyzer toolkit

	json.c - Principal implementation file for the JSON output plugin

	Copyright (C) 2012 - 2014 pev authors

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "output_plugin.h"

#define SPACES 32 // spaces # for text-based output


int num = 0;

static void to_format(
	const format_t *format,
	const output_type_e type,
	uint16_t level,
	const char *key,
	const char *value)
{
	size_t key_size = key ? strlen(key) : 0;

	char * const escaped_key = format->escape_fn(format, key);
	char * const escaped_value = format->escape_fn(format, value);

	

	switch (type) {
		case OUTPUT_TYPE_DOCUMENT_OPEN:
			printf("{\n");
			break;
		case OUTPUT_TYPE_DOCUMENT_CLOSE:
			printf("}");
			break;
		case OUTPUT_TYPE_SCOPE_OPEN:
			
				if((level %2)==1)
				{
					num = 0;	//restart because would be the first section
					printf(",\n\"%s\":{", escaped_key);
				}
			
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
				if((level %2)==1)
				{	
					printf("}");
				}
			
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value) {
				if(num==0)
				{
					printf("\"%s\":\t \"%s\"", escaped_key, escaped_value);
				}
				else
				{
					printf(",\n\"%s\":\t \"%s\"", escaped_key, escaped_value);
				}
			} else if (key)
				{
					printf("\"%s\":{", escaped_key);
				}
			
			num++;
			break;
	}

	if (escaped_key != NULL)
		free(escaped_key);
	if (escaped_value != NULL)
		free(escaped_value);
}

// ----------------------------------------------------------------------------

#define FORMAT_ID	6
#define FORMAT_NAME "json"

static const format_t g_format = {
	FORMAT_ID,
	FORMAT_NAME,
	&to_format,
	&escape,
	NULL
};

#define PLUGIN_TYPE "output"
#define PLUGIN_NAME FORMAT_NAME

int plugin_loaded(void) {
	//printf("Loading %s plugin %s\n", PLUGIN_TYPE, PLUGIN_NAME);
	return 0;
}

void plugin_unloaded(void) {
	//printf("Unloading %s plugin %s\n", PLUGIN_TYPE, PLUGIN_NAME);
}

int plugin_initialize(void) {
	int ret = output_plugin_register_format(&g_format);
	if (ret < 0)
		return -1;
	return 0;
}

void plugin_shutdown(void) {
	output_plugin_unregister_format(&g_format);
}

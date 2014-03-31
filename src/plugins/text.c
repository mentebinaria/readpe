/*
	pev - the PE file analyzer toolkit

	text.c - Principal implementation file for the TEXT output plugin

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

int g_num_opened_documents = 0;

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

	level -= g_num_opened_documents;

	switch (type) {
		case OUTPUT_TYPE_DOCUMENT_OPEN:
			g_num_opened_documents++;
			break;
		case OUTPUT_TYPE_DOCUMENT_CLOSE:
			g_num_opened_documents--;
			break;
		case OUTPUT_TYPE_SCOPE_OPEN:
			if (level > 0) {
				putchar('\n');
				printf(INDENT(level, "%s\n"), escaped_key);
			} else {
				putchar('\n');
				printf("%s\n", escaped_key);
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value) {
				if (level > 0)
					printf(INDENT(level, "%s:%*c%s\n"), escaped_key, (int)(SPACES - key_size), ' ', escaped_value);
				else
					printf("%s:%*c%s\n", escaped_key, (int)(SPACES - key_size), ' ', escaped_value);
			} else if (key) {
				if (level > 0)
					printf(INDENT(level, "\n%s\n"), escaped_key);
				else
					printf("\n%s\n", escaped_key);
			} else if (value) {
				if (level > 0)
					printf(INDENT(level, "%*c%s\n"), (int)(SPACES - key_size + 1), ' ', escaped_value);
				else
					printf("%*c%s\n", (int)(SPACES - key_size + 1), ' ', escaped_value);
			}
			break;
	}

	if (escaped_key != NULL)
		free(escaped_key);
	if (escaped_value != NULL)
		free(escaped_value);
}

// ----------------------------------------------------------------------------

#define FORMAT_ID	3
#define FORMAT_NAME "text"

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

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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "output_plugin.h"

#define SPACES 32 // spaces # for text-based output

static void to_format(
	const format_t *format,
	const output_type_e type,
	const output_scope_t *scope,
	const char *key,
	const char *value)
{
	static int indent = 0;
	static int num_attr = 0;

	char * const escaped_key = format->escape_fn(format, key);
	char * const escaped_value = format->escape_fn(format, value);
	const bool is_within_array = scope->parent_type == OUTPUT_SCOPE_TYPE_ARRAY;

	switch (type) {
		default:
			break;
		case OUTPUT_TYPE_SCOPE_OPEN:
			switch (scope->type) {
				default:
					break;
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					printf(INDENT(indent++, "{"));
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					if (num_attr > 0)
						putchar(',');
					putchar('\n');
					// NOTE: We don't want duplicate keys inside the array.
					if (key && !is_within_array)
						printf(INDENT(indent++, "\"%s\": {"), escaped_key);
					else
						printf(INDENT(indent++, "{"));
					num_attr = 0;
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					if (num_attr > 0)
						putchar(',');
					putchar('\n');
					// NOTE: We don't want duplicate keys inside the array.
					if (key && !is_within_array)
						printf(INDENT(indent++, "\"%s\": ["), escaped_key);
					else
						printf(INDENT(indent++, "["));
					num_attr = 0;
					break;
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			if (indent <= 0) {
				fprintf(stderr, "json: programming error? indent is <= 0");
				abort();
			}
			putchar('\n');
			switch (scope->type) {
				default:
					break;
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					printf(INDENT(--indent, "}"));
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					printf(INDENT(--indent, "}"));
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf(INDENT(--indent, "]"));
					break;
			}
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (num_attr > 0)
				putchar(',');
			putchar('\n');
			if (key && value)
				printf(INDENT(indent, "\"%s\": \"%s\""), escaped_key, escaped_value);
			else if (key)
				printf(INDENT(indent, "\"%s\""), escaped_key);
			else if (value)
				printf(INDENT(indent, "\"%s\""), escaped_value);
			num_attr++;
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

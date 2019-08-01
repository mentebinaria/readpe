/*
	pev - the PE file analyzer toolkit

	json.c - Principal implementation file for the JSON output plugin

	Copyright (C) 2012 - 2014 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pev_api.h"
#include "output_plugin.h"

const pev_api_t *g_pev_api = NULL;

// REFERENCE: https://tools.ietf.org/html/rfc7159
// JSON entities '"', '\', ...
static const entity_t g_entities[255] = {
	NULL,	"\\u0001","\\u0002","\\u0003","\\u0004","\\u0005","\\u0006","\\u0007","\\b","\\u0009", // 0-9
	"\\n",	"\\t",	"\\u000c","\\r","\\u000e","\\u000f","\\u0010","\\u0011","\\u0012","\\u0013", // 10-19
	"\\u0014","\\u0015","\\u0016","\\u0017","\\u0018","\\u0019","\\u001a","\\u001b","\\u001c","\\u001d", // 20-29
	"\\u001e","\\u001f",NULL,	NULL,	"\\\"",	NULL,	NULL,	NULL,	NULL,	NULL, // 30-39
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 40-49
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 50-59
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 60-69
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 70-79
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 80-89
	NULL,	NULL,	"\\\\",	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 90-99
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 100-109
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 110-119
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	"\\u007f",NULL,	NULL, // 120-129
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 130-139
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 140-149
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 150-159
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 160-169
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 170-179
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 180-189
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 190-199
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 200-209
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 210-219
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 220-229
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 230-239
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL, // 240-249
	NULL,	NULL,	NULL,	NULL,	NULL, // 250-254
};

static char *escape_json(const format_t *format, const char *str) {
	return g_pev_api->output->escape(format, str);
}

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
					num_attr = 0;
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					// Already printed an attribute in the same scope?
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
					// Already printed an attribute in the same scope?
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
					printf(INDENT(--indent, "}\n"));
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					printf(INDENT(--indent, "}"));
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf(INDENT(--indent, "]"));
					break;
			}
			// Increment the number of attributes because this scope is itself an
			// attribute.
			num_attr++;
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			// Already printed an attribute in the same scope?
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
	&escape_json,
	(entity_table_t)g_entities
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

int plugin_initialize(const pev_api_t *api) {
	g_pev_api = api;
	int ret = g_pev_api->output->output_plugin_register_format(&g_format);
	if (ret < 0)
		return -1;
	return 0;
}

void plugin_shutdown(void) {
	g_pev_api->output->output_plugin_unregister_format(&g_format);
}

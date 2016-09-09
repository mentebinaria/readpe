/*
	pev - the PE file analyzer toolkit

	text.c - Principal implementation file for the TEXT output plugin

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pev_api.h"
#include "output_plugin.h"

const pev_api_t *g_pev_api = NULL;

static char *escape_text(const format_t *format, const char *str) {
	return g_pev_api->output->escape(format, str);
}

#define SPACES 32 // spaces # for text-based output

static void to_format(
	const format_t *format,
	const output_type_e type,
	const output_scope_t *scope,
	const char *key,
	const char *value)
{
	static int indent = 0;

	char * const escaped_key = format->escape_fn(format, key);
	char * const escaped_value = format->escape_fn(format, value);

	switch (type) {
		default:
			break;
		case OUTPUT_TYPE_SCOPE_OPEN:
			switch (scope->type) {
				default:
					break;
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					if (key) {
						printf(INDENT(indent++, "%s\n"), escaped_key);
					} else {
						indent++;
					}
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					//putchar('\n');
					if (key) {
						printf(INDENT(indent++, "%s\n"), escaped_key);
					} else {
						indent++;
					}
					break;
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			indent--;
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
		{
			const size_t key_size = key ? strlen(key) : 0;
			if (key && value) {
				printf(INDENT(indent, "%s:%*c%s\n"), escaped_key, (int)(SPACES - key_size), ' ', escaped_value);
			} else if (key) {
				printf(INDENT(indent, "%s\n"), escaped_key);
			} else if (value) {
				printf(INDENT(indent, "%*c%s\n"), (int)(SPACES - key_size + 1), ' ', escaped_value);
			}
			break;
		}
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
	&escape_text,
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

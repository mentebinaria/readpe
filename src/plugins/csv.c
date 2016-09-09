/*
	pev - the PE file analyzer toolkit

	csv.c - Principal implementation file for the CSV output plugin

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

// REFERENCE: http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
// CSV entities ',', '"', '\n'
static const entity_t g_entities[255] = {
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	"\\n",	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	"\"\"",	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,
};

static char *escape_csv(const format_t *format, const char *str) {
	if (str == NULL)
		return NULL;
	// If `str` contains a line-break, or a double-quote, or a comma,
	// escape and enclose the entire `str` with double quotes.
	return strpbrk(str, "\n\",") != NULL
		? g_pev_api->output->escape_ex_quoted(str, format->entities_table)
		: g_pev_api->output->escape_ex(str, format->entities_table);
}

//
// The CSV output encloses fields with double quotes if they contain
// any of the following characters:
//
//   a) line-break;
//   b) double-quote;
//   c) comma;
//
// Apart from the enclosing, any double-quote character found is escaped
// to 2 double-quote characters.
//
// KNOWN BUG:
//
//   Our CSV output still doesn't follow the following rule:
//   > Each record "should" contain the same number of comma-separated
//   > fields.
//
// REFERENCE: http://en.wikipedia.org/wiki/Comma-separated_values
//
static void to_format(
	const format_t *format,
	const output_type_e type,
	const output_scope_t *scope,
	const char *key,
	const char *value)
{
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
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf("\n%s\n", escaped_key);
					break;
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			switch (scope->type) {
				default:
					break;
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf("\n");
					break;
			}
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value)
				printf("%s,%s\n", escaped_key, escaped_value);
			else if (key)
				printf("\n%s\n", escaped_key);
			else if (value)
				printf(",%s\n", escaped_value);
			break;
	}

	if (escaped_key != NULL)
		free(escaped_key);
	if (escaped_value != NULL)
		free(escaped_value);
}

// ----------------------------------------------------------------------------

#define FORMAT_ID	1
#define FORMAT_NAME "csv"

static const format_t g_format = {
	FORMAT_ID,
	FORMAT_NAME,
	&to_format,
	&escape_csv,
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

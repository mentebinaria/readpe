/*
	pev - the PE file analyzer toolkit

	html.c - Principal implementation file for the HTML output plugin

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
#include "pev_api.h"
#include "output_plugin.h"

const pev_api_t *g_pev_api = NULL;

// REFERENCE: http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
// HTML entities '"', '&', '\'', '<', '>', ...
static const entity_t g_entities[255] = {
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	"&quot;",NULL,	NULL,	NULL,	"&amp;","&apos;",
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	"&lt;",	NULL,	"&gt;",	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
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

static char *escape_html(const format_t *format, const char *str) {
	return g_pev_api->output->escape(format, str);
}

#define TEMPLATE_DOCUMENT_OPEN \
	"<!DOCTYPE html>\n" \
	"<html lang=\"en\" dir=\"ltr\">\n" \
	"<head>\n" \
	"    <meta charset=\"utf-8\">\n" \
	"    <title>%s</title>\n" \
	"</head>\n" \
	"<body>\n"

#define TEMPLATE_DOCUMENT_CLOSE \
	"</body>\n" \
	"</html>\n"

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
	const bool is_within_array = scope->parent_type == OUTPUT_SCOPE_TYPE_ARRAY;

	switch (type) {
		default:
			break;
		case OUTPUT_TYPE_SCOPE_OPEN:
		{
			// NOTE: HTML doesn't allow `div` inside `ul`. If we're inside a `ul`, it
			// 		 means the parent is an array, so we can safely replace `div` by `li`.
			const char * wrap_el = is_within_array ? "li" : "div";
			switch (scope->type) {
				default:
					break;
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					printf(TEMPLATE_DOCUMENT_OPEN, g_pev_api->output->output_cmdline());
					indent++;
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					printf(INDENT(indent++, "<%s class=\"object\">\n"), wrap_el);
					printf(INDENT(indent,   "<h2>%s</h2>\n"), escaped_key);
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf(INDENT(indent++, "<%s class=\"array\">\n"), wrap_el);
					printf(INDENT(indent,   "<h2>%s</h2>\n"), escaped_key);
					printf(INDENT(indent++, "<ul>\n"));
					break;
			}
			break;
		}
		case OUTPUT_TYPE_SCOPE_CLOSE:
		{
			if (indent <= 0) {
				fprintf(stderr, "html: programming error? indent is <= 0");
				abort();
			}
			// NOTE: HTML doesn't allow `div` inside `ul`. If we're inside a `ul`, it
			// 		 means the parent is an array, so we can safely replace `div` by `li`.
			const char * wrap_el = is_within_array ? "li" : "div";
			switch (scope->type) {
				default:
					break;
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					printf(TEMPLATE_DOCUMENT_CLOSE);
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					printf(INDENT(--indent, "</%s>\n"), wrap_el);
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf(INDENT(--indent, "</ul>\n"));
					printf(INDENT(--indent, "</%s>\n"), wrap_el);
					break;
			}
			break;
		}
		case OUTPUT_TYPE_ATTRIBUTE:
		{
			const char * wrap_el = scope->type == OUTPUT_SCOPE_TYPE_ARRAY ? "li" : "p";
			if (key && value) {
				printf(INDENT(indent, "<%s><span class=\"key\"><b>%s</b></span>: <span class=\"value\">%s</span></%s>\n"), wrap_el, escaped_key, escaped_value, wrap_el);
			} else if (key) {
				putchar('\n');
				printf(INDENT(indent, "<%s><span class=\"key\"><b>%s</b></span></%s>\n"), wrap_el, escaped_key, wrap_el);
			} else if (value) {
				printf(INDENT(indent, "<%s><span class=\"value\">%s</span></%s>\n"), wrap_el, escaped_value, wrap_el);
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

#define FORMAT_ID	2
#define FORMAT_NAME "html"

static const format_t g_format = {
	FORMAT_ID,
	FORMAT_NAME,
	&to_format,
	&escape_html,
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

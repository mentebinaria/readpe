/*
	pev - the PE file analyzer toolkit

	html.c - Principal implementation file for the HTML output plugin

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
#include "output_plugin.h"

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

	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			switch (scope->type) {
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					printf(TEMPLATE_DOCUMENT_OPEN, output_cmdline());
					indent++;
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					printf(INDENT(indent++, "<div class=\"object\">\n"));
					printf(INDENT(indent,   "<h2>%s</h2>\n"), escaped_key);
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf(INDENT(indent++, "<div class=\"array\">\n"));
					printf(INDENT(indent,   "<h2>%s</h2>\n"), escaped_key);
					printf(INDENT(indent++, "<ul>\n"));
					break;
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			if (indent <= 0) {
				fprintf(stderr, "html: programming error? indent is <= 0");
				abort();
			}
			switch (scope->type) {
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
					printf(TEMPLATE_DOCUMENT_CLOSE);
					break;
				case OUTPUT_SCOPE_TYPE_OBJECT:
					printf(INDENT(--indent, "</div>\n"));
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					printf(INDENT(--indent, "</ul>\n"));
					printf(INDENT(--indent, "</div>\n"));
					break;
			}
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
		{
			const char * wrap_el = NULL;
			switch (scope->type) {
				case OUTPUT_SCOPE_TYPE_DOCUMENT:
				case OUTPUT_SCOPE_TYPE_OBJECT:
					wrap_el = "p";
					break;
				case OUTPUT_SCOPE_TYPE_ARRAY:
					wrap_el = "li";
					break;
			}
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
	&escape,
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

int plugin_initialize(void) {
	int ret = output_plugin_register_format(&g_format);
	if (ret < 0)
		return -1;
	return 0;
}

void plugin_shutdown(void) {
	output_plugin_unregister_format(&g_format);
}

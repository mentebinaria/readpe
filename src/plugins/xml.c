/*
	pev - the PE file analyzer toolkit

	xml.c - Principal implementation file for the XML output plugin

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
// XML entities '"', '&', '\'', '<', '>'
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

static void to_format(
	const format_t *format,
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value)
{
	// FIXME(jweyrich): Somehow output the XML root element.

	char * const escaped_key = format->escape_fn(format, key);
	char * const escaped_value = format->escape_fn(format, value);

	//
	// Quoting http://www.w3schools.com/xml/xml_elements.asp
	//
	// XML Naming Rules
	//   XML elements must follow these naming rules:
	//     Names can contain letters, numbers, and other characters
	//     Names cannot start with a number or punctuation character
	//     Names cannot start with the letters xml (or XML, or Xml, etc)
	//     Names cannot contain spaces
	//
	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			if (level > 0)
				printf(INDENT(level, "<scope name=\"%s\">\n"), escaped_key);
			else
				printf("<scope name=\"%s\">\n", escaped_key);
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			if (level > 0)
				printf(INDENT(level, "</scope>\n"));
			else
				printf("</scope>\n");
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value) {
				if (level > 0)
					printf(INDENT(level, "<attribute name=\"%s\">%s</attribute>\n"), escaped_key, escaped_value);
				else 
					printf("<attribute name=\"%s\">%s</attribute>\n", escaped_key, escaped_value);
			} else if (key) {
				if (level > 0)
					printf(INDENT(level, "<attribute name=\"%s\">\n"), escaped_key);
				else
					printf("<attribute name=\"%s\">\n", escaped_key);
			}
			break;
	}

	if (escaped_key != NULL)
		free(escaped_key);
	if (escaped_value != NULL)
		free(escaped_value);
}

// ----------------------------------------------------------------------------

#define PLUGIN_TYPE "output"
#define PLUGIN_NAME "xml"
#define FORMAT_ID	4

static const format_t g_format = {
	FORMAT_ID,
	"xml",
	&to_format,
	&escape,
	(entity_table_t)g_entities
};

int plugin_loaded(void) {
	//printf("Loading %s plugin %s\n", PLUGIN_TYPE, PLUGIN_NAME);
	int ret = output_plugin_register_format(&g_format);
	if (ret < 0)
		return -1;
	return 0;
}

void plugin_unloaded(void) {
	//printf("Unloading %s plugin %s\n", PLUGIN_TYPE, PLUGIN_NAME);
}

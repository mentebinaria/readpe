/*
	pev - the PE file analyzer toolkit
	
	output.c - functions to output results in different formats

	Copyright (C) 2012 pev authors

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

#include <ctype.h>
#include "output.h"
#include "common.h"
#include "compat/strlcat.h"

#define STACK_PREFIX PEV_OUTPUT_
#define STACK_ELEMENT_TYPE const char *
#include "stack.h"

//
// Type definitions
//

typedef enum {
	OUTPUT_TYPE_SCOPE_OPEN = 1,
	OUTPUT_TYPE_SCOPE_CLOSE = 2,
	OUTPUT_TYPE_ATTRIBUTE = 3
} output_type_e;

typedef void (*output_fn)(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value);

struct _format_t; // Forward declaration
typedef char * (*escape_fn)(
	const struct _format_t *format,
	const char *str);

typedef char * const entity_t;
typedef char ** const entity_table_t;

typedef struct _format_t {
	const format_e format;
	const char *name;
	const output_fn output_fn;
	const escape_fn escape_fn;
	const entity_table_t entities_table;
} format_t;

//
// Declaration of format specific things
//

static void to_text(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value);
static void to_html(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value);
static void to_xml(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value);
static void to_csv(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value);

static const entity_t g_html_entities[255];
static const entity_t g_xml_entities[255];
static const entity_t g_csv_entities[255];

static char *escape_csv(const format_t *format, const char *str);
static char *escape(const format_t *format, const char *str);

//
// Global variables
//

static format_t *g_format = NULL;
static STACK_TYPE *g_scope_stack = NULL;
static int g_argc = 0;
static char **g_argv = NULL;
static char *g_cmdline = NULL;

static format_t g_supported_formats[] = {
	{ FORMAT_TEXT,		"text",	&to_text,	&escape, 		NULL							},
	{ FORMAT_HTML,		"html",	&to_html,	&escape, 		(entity_table_t)g_html_entities	},
	{ FORMAT_XML,		"xml",	&to_xml,	&escape, 		(entity_table_t)g_xml_entities	},
	{ FORMAT_CSV,		"csv",	&to_csv,	&escape_csv,	(entity_table_t)g_csv_entities	},
	{ FORMAT_INVALID,	NULL,	NULL,		NULL,			NULL							}
};

//
// Definition of internal functions
//

static format_t *output_lookup_format(format_e format) {
	for (size_t i = 0; i < LIBPE_SIZEOF_ARRAY(g_supported_formats); i++) {
		// TODO(jweyrich): Should we use strcasecmp? Conforms to 4.4BSD and POSIX.1-2001, but not to C89 nor C99.
		if (g_supported_formats[i].format == format)
			return &g_supported_formats[i];
	}

	return NULL;
}

static char *output_join_array_of_strings(char *strings[], size_t count, char delimiter) {
	if (strings == NULL || strings[0] == NULL)
		return strdup("");

	// Count how much memory the resulting string is going to need,
	// considering delimiters for each string. The last delimiter will
	// be a NULL terminator;
	size_t result_length = 0;
	for (size_t i = 0; i < count; i++) {
		result_length += strlen(strings[i]) + 1;
	}

	// Allocate the resulting string.
	char *result = malloc(result_length);
	if (result == NULL)
		return NULL; // Return NULL because it failed miserably!

	// Null terminate it.
	result[--result_length] = '\0';

	// Join all strings.
	char ** current_string = strings;
	char * current_char = current_string[0];
	for (size_t i = 0; i < result_length; i++) {
		if (*current_char != '\0') {
			result[i] = *current_char++;
		} else {
			// Reached the end of a string. Add a delimiter and move to the next one.
			result[i] = delimiter;
			current_string++;
			current_char = current_string[0];
		}
	}

	return result;
}

//
// Indentation macros
//

#define INDENT_TAB_SIZE			4
#define INDENT_COLUMNS_(level)	(int)((int)(level) * (int)INDENT_TAB_SIZE + 1)
#define INDENT_FORMAT_			"%*s"
#define INDENT_ARGS_(level)		INDENT_COLUMNS_(level), " "
#define INDENT(level, format)	INDENT_FORMAT_ format, INDENT_ARGS_(level)

//
// Escaping
// REFERENCE: http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
//

// HTML entities '"', '&', '\'', '<', '>', ...
static const entity_t g_html_entities[255] = {
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

// XML entities '"', '&', '\'', '<', '>'
static const entity_t g_xml_entities[255] = {
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

// CSV entities ',', '"', '\n'
// TODO(jweyrich): Escape ',' - Are we going to enclose the str in quotes?
static const entity_t g_csv_entities[255] = {
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	"\\n",	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	"\"\"",	NULL,	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,	",",	NULL,	NULL,	NULL,	NULL,	NULL,
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

static size_t escape_count_chars_ex(const char *str, size_t len, const entity_table_t entities) {
	size_t result = 0;
	for (size_t i = 0; i < len; i++) {
		const unsigned char index = (unsigned char)str[i];
		const entity_t entity = entities[index];
		result += entity == NULL ? 1 : strlen(entity);
	}
	return result;
}

#if 0
static size_t escape_count_chars(const format_t *format, const char *str, size_t len) {
	return escape_count_chars_ex(str, len, format->entities_table);
}
#endif

static char *escape_ex(const char *str, const entity_table_t entities) {
	if (str == NULL)
		return NULL;

	if (str[0] == '\0')
		return strdup("");

	if (entities == NULL)
		return strdup(str);

	const size_t old_length = strlen(str);
	const size_t new_length = escape_count_chars_ex(str, old_length, entities);
	if (old_length == new_length)
		return strdup(str);

	char *new_str = malloc(new_length + 1); // Extra byte for NULL terminator
	if (new_str == NULL)
		abort();

	new_str[new_length] = '\0';

	size_t consumed = 0;
	for (size_t i = 0; i < old_length; i++) {
		const unsigned char index = (unsigned char)str[i];
		const entity_t entity = entities[index];
		if (entity == NULL) {
			new_str[consumed++] = str[i];
		} else {
			const size_t entity_len = strlen(entity);
			memcpy(new_str + consumed, entity, entity_len);
			consumed += entity_len;
		}
	}

	return new_str;
}

static char *escape(const format_t *format, const char *str) {
	return escape_ex(str, format->entities_table);
}

static char *escape_csv(const format_t *format, const char *str) {
	return escape_ex(str, format->entities_table);
}

//
// Definition of format specific functions
//

static void to_text(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value)
{
	size_t key_size = key ? strlen(key) : 0;

	char * const escaped_key = g_format->escape_fn(g_format, key);
	char * const escaped_value = g_format->escape_fn(g_format, value);
	
	switch (type) {
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
}

static void to_csv(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value)
{
	(void)level;

	char * const escaped_key = g_format->escape_fn(g_format, key);
	char * const escaped_value = g_format->escape_fn(g_format, value);

	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			printf("\n%s\n", escaped_key);
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			printf("\n");
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

static void to_xml(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value)
{
	// FIXME(jweyrich): Somehow output the XML root element.

	char * const escaped_key = g_format->escape_fn(g_format, key);
	char * const escaped_value = g_format->escape_fn(g_format, value);

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

static void to_html(
	const output_type_e type,
	const uint16_t level,
	const char *key,
	const char *value)
{
	// FIXME(jweyrich): Somehow output the HTML document with a body.

	char * const escaped_key = g_format->escape_fn(g_format, key);
	char * const escaped_value = g_format->escape_fn(g_format, value);
	
	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			if (level > 0) {
				printf(INDENT(level, "<section>\n"));
				printf(INDENT(level+1, "<h1>%s</h1>\n"), escaped_key);
			} else {
				printf("<section>\n");
				printf(INDENT(1, "<h1>%s</h1>\n"), escaped_key);
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			if (level > 0)
				printf(INDENT(level, "</section>\n"));
			else
				printf("</section>\n");
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value) {
				if (level > 0)
					printf(INDENT(level, "<p><span><b>%s</b></span>: <span>%s</span></p>\n"), escaped_key, escaped_value);
				else 
					printf("<p><span><b>%s</b></span>: <span>%s</span></p>\n", escaped_key, escaped_value);
			} else if (key) {
				if (level > 0) {
					putchar('\n');
					printf(INDENT(level, "<p><span><b>%s</b></span></p>\n"), escaped_key);
				} else {
					putchar('\n');
					printf("<p><span><b>%s</b></span></p>\n", escaped_key);
				}
			} else if (value) {
				if (level > 0)
					printf(INDENT(level, "<p><span>%s</span></p>\n"), escaped_value);
				else
					printf("<p><span>%s</span></p>\n", escaped_value);
			}
			break;
	}

	if (escaped_key != NULL)
		free(escaped_key);
	if (escaped_value != NULL)
		free(escaped_value);
}

//
// API
//

void output(const char *key, const char *value) {
	output_keyval(key, value);
}

void output_init(void) {
	g_format = output_lookup_format(FORMAT_TEXT);
	g_scope_stack = STACK_ALLOC(15);
	if (g_scope_stack == NULL)
		abort();
}

void output_term(void) {
	if (g_cmdline != NULL)
		free(g_cmdline);

	// TODO(jweyrich): Should we loop to pop + close + output every scope?
	if (g_scope_stack != NULL)
		free(g_scope_stack);
}

void output_set_cmdline(int argc, char *argv[]) {
	g_argc = argc;
	g_argv = argv;
	g_cmdline = output_join_array_of_strings(g_argv, g_argc, ' ');
	if (g_cmdline == NULL)
		abort();
	//printf("cmdline = %s\n", g_cmdline);
}

format_e output_format(void) {
	return g_format->format;
}

format_e output_parse_format(const char *format_name) {
	format_e format = FORMAT_INVALID;

	for (size_t i = 0; i < LIBPE_SIZEOF_ARRAY(g_supported_formats); i++) {
		// TODO(jweyrich): Should we use strcasecmp? Conforms to 4.4BSD and POSIX.1-2001, but not to C89 nor C99.
		if (strcmp(format_name, g_supported_formats[i].name) == 0) {
			format = g_supported_formats[i].format;
			break;
		}
	}

	return format;
}

int output_set_format(const format_e format) {
	switch (format) {
		default:
		case FORMAT_INVALID:
			//fprintf(stderr, "invalid output format\n");
			return -2;
		case FORMAT_TEXT:
		case FORMAT_HTML:
		case FORMAT_XML:
		case FORMAT_CSV:
			g_format = output_lookup_format(format);
			return 0;
	}
}

int output_set_format_by_name(const char *format_name) {
	const format_e format = output_parse_format(format_name);
	return output_set_format(format);
}

void output_open_scope(const char *scope_name) {
	const char *key = scope_name;
	const char *value = NULL;
	const output_type_e type = OUTPUT_TYPE_SCOPE_OPEN;
	const uint16_t level = STACK_COUNT(g_scope_stack);

	if (g_format != NULL)
		g_format->output_fn(type, level, key, value);

	int ret = STACK_PUSH(g_scope_stack, scope_name);
	if (ret < 0)
		abort();
}

void output_close_scope(void) {
	const char *scope_name = NULL;
	int ret = STACK_POP(g_scope_stack, &scope_name);
	if (ret < 0)
		abort();

	const char *key = scope_name;
	const char *value = NULL;
	const output_type_e type = OUTPUT_TYPE_SCOPE_CLOSE;
	const uint16_t level = STACK_COUNT(g_scope_stack);

	if (g_format != NULL)
		g_format->output_fn(type, level, key, value);
}

void output_keyval(const char *key, const char *value) {
	const output_type_e type = OUTPUT_TYPE_ATTRIBUTE;
	const uint16_t level = STACK_COUNT(g_scope_stack);

	if (g_format != NULL)
		g_format->output_fn(type, level, key, value);
}

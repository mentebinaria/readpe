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

typedef enum {
	OUTPUT_TYPE_SCOPE_OPEN = 1,
	OUTPUT_TYPE_SCOPE_CLOSE = 2,
	OUTPUT_TYPE_ATTRIBUTE = 3
} output_type_e;

static format_e g_format;
static STACK_TYPE *g_scope_stack = NULL;
static int g_argc;
static char **g_argv;
static char *g_cmdline;

#define INDENT_TAB_SIZE			4
#define INDENT_COLUMNS_(level)	(int)((int)(level) * (int)INDENT_TAB_SIZE + 1)
#define INDENT_FORMAT_			"%*s"
#define INDENT_ARGS_(level)		INDENT_COLUMNS_(level), " "
#define INDENT(level, format)	INDENT_FORMAT_ format, INDENT_ARGS_(level)

static void to_text(const output_type_e type, const char *key, const char *value) {
	const uint16_t level = STACK_COUNT(g_scope_stack);
	size_t key_size = key ? strlen(key) : 0;
	
	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			if (level > 0) {
				putchar('\n');
				printf(INDENT(level, "%s\n"), key);
			} else {
				putchar('\n');
				printf("%s\n", key);
			}
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value) {
				if (level > 0)
					printf(INDENT(level, "%s:%*c%s\n"), key, (int)(SPACES - key_size), ' ', value);
				else 
					printf("%s:%*c%s\n", key, (int)(SPACES - key_size), ' ', value);
			} else if (key) {
				if (level > 0)
					printf(INDENT(level, "\n%s\n"), key);
				else 
					printf("\n%s\n", key);
			} else if (value) {
				if (level > 0)
					printf(INDENT(level, "%*c%s\n"), (int)(SPACES - key_size + 1), ' ', value);
				else 
					printf("%*c%s\n", (int)(SPACES - key_size + 1), ' ', value);
			}
			break;
	}
}

static void to_csv(const output_type_e type, const char *key, const char *value) {
	// FIXME(jweyrich): Escape key/value so they don't break the CSV.
	// ',' and '\n' ?
	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			printf("\n%s\n", key);
			break;
		case OUTPUT_TYPE_SCOPE_CLOSE:
			printf("\n");
			break;
		case OUTPUT_TYPE_ATTRIBUTE:
			if (key && value)
				printf("%s,%s\n", key, value);
			else if (key)
				printf("\n%s\n", key);
			else if (value)
				printf(",%s\n", value);
			break;
	}
}

static void to_xml(const output_type_e type, const char *key, const char *value) {
	const uint16_t level = STACK_COUNT(g_scope_stack);

	// FIXME(jweyrich): Somehow output the XML root element.
	// FIXME(jweyrich): Escape key/value so they don't break the XML.
	// REFERENCE: http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
	// quot  "
	// amp   &
	// apos  '
	// lt    <
	// gt    >

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
				printf(INDENT(level, "<scope name=\"%s\">\n"), key);
			else
				printf("<scope name=\"%s\">\n", key);
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
					printf(INDENT(level, "<attribute name=\"%s\">%s</attribute>\n"), key, value);
				else 
					printf("<attribute name=\"%s\">%s</attribute>\n", key, value);
			} else if (key) {
				if (level > 0)
					printf(INDENT(level, "<attribute name=\"%s\">\n"), key);
				else
					printf("<attribute name=\"%s\">\n", key);
			}
			break;
	}
}

static void to_html(const output_type_e type, const char *key, const char *value) {
	const uint16_t level = STACK_COUNT(g_scope_stack);

	// FIXME(jweyrich): Somehow output the HTML document with a body.
	// FIXME(jweyrich): Escape key/value so they don't break the HTML.
	// REFERENCE: http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
	// quot		"	U+0022 (34)		HTML 2.0	HTMLspecial
	// amp		&	U+0026 (38)		HTML 2.0	HTMLspecial
	// apos		'	U+0027 (39)		XHTML 1.0	HTMLspecial
	// lt		<	U+003C (60)		HTML 2.0	HTMLspecial
	// gt		>	U+003E (62)		HTML 2.0	HTMLspecial
	// nbsp		 	U+00A0 (160)	HTML 3.2	HTMLlat1
	// iexcl	¡	U+00A1 (161)	HTML 3.2	HTMLlat1
	// cent		¢	U+00A2 (162)	HTML 3.2	HTMLlat1
	// pound	£	U+00A3 (163)	HTML 3.2	HTMLlat1
	// curren	¤	U+00A4 (164)	HTML 3.2	HTMLlat1
	// yen		¥	U+00A5 (165)	HTML 3.2	HTMLlat1
	// brvbar	¦	U+00A6 (166)	HTML 3.2	HTMLlat1
	// sect		§	U+00A7 (167)	HTML 3.2	HTMLlat1
	// uml		¨	U+00A8 (168)	HTML 3.2	HTMLlat1
	// copy		©	U+00A9 (169)	HTML 3.2	HTMLlat1
	// ordf		ª	U+00AA (170)	HTML 3.2	HTMLlat1
	// laquo	«	U+00AB (171)	HTML 3.2	HTMLlat1
	// not		¬	U+00AC (172)	HTML 3.2	HTMLlat1
	// shy		 	U+00AD (173)	HTML 3.2	HTMLlat1
	// reg		®	U+00AE (174)	HTML 3.2	HTMLlat1
	// macr		¯	U+00AF (175)	HTML 3.2	HTMLlat1
	// deg		°	U+00B0 (176)	HTML 3.2	HTMLlat1
	// plusmn	±	U+00B1 (177)	HTML 3.2	HTMLlat1
	// sup2		²	U+00B2 (178)	HTML 3.2	HTMLlat1
	// sup3		³	U+00B3 (179)	HTML 3.2	HTMLlat1
	// acute	´	U+00B4 (180)	HTML 3.2	HTMLlat1
	// micro	µ	U+00B5 (181)	HTML 3.2	HTMLlat1
	// para		¶	U+00B6 (182)	HTML 3.2	HTMLlat1
	// middot	·	U+00B7 (183)	HTML 3.2	HTMLlat1
	// cedil	¸	U+00B8 (184)	HTML 3.2	HTMLlat1
	// sup1		¹	U+00B9 (185)	HTML 3.2	HTMLlat1
	// ordm		º	U+00BA (186)	HTML 3.2	HTMLlat1
	// raquo	»	U+00BB (187)	HTML 3.2	HTMLlat1
	// frac14	¼	U+00BC (188)	HTML 3.2	HTMLlat1
	// frac12	½	U+00BD (189)	HTML 3.2	HTMLlat1
	// frac34	¾	U+00BE (190)	HTML 3.2	HTMLlat1
	// iquest	¿	U+00BF (191)	HTML 3.2	HTMLlat1
	// Agrave	À	U+00C0 (192)	HTML 2.0	HTMLlat1
	// Aacute	Á	U+00C1 (193)	HTML 2.0	HTMLlat1
	// Acirc	Â	U+00C2 (194)	HTML 2.0	HTMLlat1
	// Atilde	Ã	U+00C3 (195)	HTML 2.0	HTMLlat1
	// Auml		Ä	U+00C4 (196)	HTML 2.0	HTMLlat1
	// Aring	Å	U+00C5 (197)	HTML 2.0	HTMLlat1
	// AElig	Æ	U+00C6 (198)	HTML 2.0	HTMLlat1
	// Ccedil	Ç	U+00C7 (199)	HTML 2.0	HTMLlat1
	// Egrave	È	U+00C8 (200)	HTML 2.0	HTMLlat1
	// Eacute	É	U+00C9 (201)	HTML 2.0	HTMLlat1
	// Ecirc	Ê	U+00CA (202)	HTML 2.0	HTMLlat1
	// Euml		Ë	U+00CB (203)	HTML 2.0	HTMLlat1
	// Igrave	Ì	U+00CC (204)	HTML 2.0	HTMLlat1
	// Iacute	Í	U+00CD (205)	HTML 2.0	HTMLlat1
	// Icirc	Î	U+00CE (206)	HTML 2.0	HTMLlat1
	// Iuml		Ï	U+00CF (207)	HTML 2.0	HTMLlat1
	// ETH		Ð	U+00D0 (208)	HTML 2.0	HTMLlat1
	// Ntilde	Ñ	U+00D1 (209)	HTML 2.0	HTMLlat1
	// Ograve	Ò	U+00D2 (210)	HTML 2.0	HTMLlat1
	// Oacute	Ó	U+00D3 (211)	HTML 2.0	HTMLlat1
	// Ocirc	Ô	U+00D4 (212)	HTML 2.0	HTMLlat1
	// Otilde	Õ	U+00D5 (213)	HTML 2.0	HTMLlat1
	// Ouml		Ö	U+00D6 (214)	HTML 2.0	HTMLlat1
	// times	×	U+00D7 (215)	HTML 3.2	HTMLlat1
	// Oslash	Ø	U+00D8 (216)	HTML 2.0	HTMLlat1
	// Ugrave	Ù	U+00D9 (217)	HTML 2.0	HTMLlat1
	// Uacute	Ú	U+00DA (218)	HTML 2.0	HTMLlat1
	// Ucirc	Û	U+00DB (219)	HTML 2.0	HTMLlat1
	// Uuml		Ü	U+00DC (220)	HTML 2.0	HTMLlat1
	// Yacute	Ý	U+00DD (221)	HTML 2.0	HTMLlat1
	// THORN	Þ	U+00DE (222)	HTML 2.0	HTMLlat1
	// szlig	ß	U+00DF (223)	HTML 2.0	HTMLlat1
	// agrave	à	U+00E0 (224)	HTML 2.0	HTMLlat1
	// aacute	á	U+00E1 (225)	HTML 2.0	HTMLlat1
	// acirc	â	U+00E2 (226)	HTML 2.0	HTMLlat1
	// atilde	ã	U+00E3 (227)	HTML 2.0	HTMLlat1
	// auml		ä	U+00E4 (228)	HTML 2.0	HTMLlat1
	// aring	å	U+00E5 (229)	HTML 2.0	HTMLlat1
	// aelig	æ	U+00E6 (230)	HTML 2.0	HTMLlat1
	// ccedil	ç	U+00E7 (231)	HTML 2.0	HTMLlat1
	// egrave	è	U+00E8 (232)	HTML 2.0	HTMLlat1
	// eacute	é	U+00E9 (233)	HTML 2.0	HTMLlat1
	// ecirc	ê	U+00EA (234)	HTML 2.0	HTMLlat1
	// euml		ë	U+00EB (235)	HTML 2.0	HTMLlat1
	// igrave	ì	U+00EC (236)	HTML 2.0	HTMLlat1
	// iacute	í	U+00ED (237)	HTML 2.0	HTMLlat1
	// icirc	î	U+00EE (238)	HTML 2.0	HTMLlat1
	// iuml		ï	U+00EF (239)	HTML 2.0	HTMLlat1
	// eth		ð	U+00F0 (240)	HTML 2.0	HTMLlat1
	// ntilde	ñ	U+00F1 (241)	HTML 2.0	HTMLlat1
	// ograve	ò	U+00F2 (242)	HTML 2.0	HTMLlat1
	// oacute	ó	U+00F3 (243)	HTML 2.0	HTMLlat1
	// ocirc	ô	U+00F4 (244)	HTML 2.0	HTMLlat1
	// otilde	õ	U+00F5 (245)	HTML 2.0	HTMLlat1
	// ouml		ö	U+00F6 (246)	HTML 2.0	HTMLlat1
	// divide	÷	U+00F7 (247)	HTML 3.2	HTMLlat1
	// oslash	ø	U+00F8 (248)	HTML 2.0	HTMLlat1
	// ugrave	ù	U+00F9 (249)	HTML 2.0	HTMLlat1
	// uacute	ú	U+00FA (250)	HTML 2.0	HTMLlat1
	// ucirc	û	U+00FB (251)	HTML 2.0	HTMLlat1
	// uuml		ü	U+00FC (252)	HTML 2.0	HTMLlat1
	// yacute	ý	U+00FD (253)	HTML 2.0	HTMLlat1
	// thorn	þ	U+00FE (254)	HTML 2.0	HTMLlat1
	// yuml		ÿ	U+00FF (255)	HTML 2.0	HTMLlat1
	
	switch (type) {
		case OUTPUT_TYPE_SCOPE_OPEN:
			if (level > 0) {
				printf(INDENT(level, "<section>\n"));
				printf(INDENT(level+1, "<h1>%s</h1>\n"), key);
			} else {
				printf("<section>\n");
				printf(INDENT(1, "<h1>%s</h1>\n"), key);
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
					printf(INDENT(level, "<p><span><b>%s</b></span>: <span>%s</span></p>\n"), key, value);
				else 
					printf("<p><span><b>%s</b></span>: <span>%s</span></p>\n", key, value);
			} else if (key) {
				if (level > 0) {
					putchar('\n');
					printf(INDENT(level, "<p><span><b>%s</b></span></p>\n"), key);
				} else {
					putchar('\n');
					printf("<p><span><b>%s</b></span></p>\n", key);
				}
			} else if (value) {
				if (level > 0)
					printf(INDENT(level, "<p><span>%s</span></p>\n"), value);
				else
					printf("<p><span>%s</span></p>\n", value);
			}
			break;
	}
}

void output(const char *key, const char *value) {
	output_keyval(key, value);
}

void output_init(void) {
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

void output_set_cmdline(int argc, char *argv[]) {
	g_argc = argc;
	g_argv = argv;
	g_cmdline = output_join_array_of_strings(g_argv, g_argc, ' ');
	if (!g_cmdline)
		abort();
	//printf("cmdline = %s\n", g_cmdline);
}

format_e format_output(void) {
	return g_format;
}

format_e output_parse_format(const char *format_name) {
	format_e format;

	// TODO(jweyrich): Should we use strcasecmp? Conforms to 4.4BSD and POSIX.1-2001, but not to C89 nor C99.
	if (! strcmp(format_name, "text"))
		format = FORMAT_TEXT;
	else if (! strcmp(format_name, "xml"))
		format = FORMAT_XML;
	else if (! strcmp(format_name, "csv"))
		format = FORMAT_CSV;
	else if (! strcmp(format_name, "html"))
		format = FORMAT_HTML;
	else
		format = FORMAT_INVALID;

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
			g_format = format;
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

	switch (g_format) {
		case FORMAT_CSV:
			to_csv(type, key, value);
			break;
		case FORMAT_XML:
			to_xml(type, key, value);
			break;
		case FORMAT_HTML:
			to_html(type, key, value);
			break;
		default:
		case FORMAT_TEXT:
			to_text(type, key, value);
			break;
	}

	int ret = STACK_PUSH(g_scope_stack, scope_name);
	if (ret < 0)
		abort();
}

void output_close_scope(void) {
	const char *scope_name = NULL;
	int ret = STACK_POP(g_scope_stack, &scope_name);
	if (ret < 0)
		abort();

	//char key[255];
	//key[0] = '/';
	//key[1] = '\0';
	//bsd_strlcat(key, scope_name, sizeof(key));
	const char *key = scope_name;
	const char *value = NULL;
	const output_type_e type = OUTPUT_TYPE_SCOPE_CLOSE;

	switch (g_format) {
		case FORMAT_CSV:
			to_csv(type, key, value);
			break;
		case FORMAT_XML:
			to_xml(type, key, value);
			break;
		case FORMAT_HTML:
			to_html(type, key, value);
			break;
		default:
		case FORMAT_TEXT:
			break;
	}
}

void output_keyval(const char *key, const char *value) {
	const output_type_e type = OUTPUT_TYPE_ATTRIBUTE;

	switch (g_format) {
		case FORMAT_CSV:
			to_csv(type, key, value);
			break;
		case FORMAT_XML:
			to_xml(type, key, value);
			break;
		case FORMAT_HTML:
			to_html(type, key, value);
			break;
		default:
		case FORMAT_TEXT:
			to_text(type, key, value);
			break;
	}
}

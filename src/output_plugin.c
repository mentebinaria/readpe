/*
	pev - the PE file analyzer toolkit

	output_plugin.c - Symbols and APIs to be used by output plugins.

	Copyright (C) 2014 pev authors

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

#include "output_plugin.h"
#include <stdlib.h>
#include <string.h>

size_t escape_count_chars_ex(const char *str, size_t len, const entity_table_t entities) {
	size_t result = 0;
	for (size_t i = 0; i < len; i++) {
		const unsigned char index = (unsigned char)str[i];
		const entity_t entity = entities[index];
		result += entity == NULL ? 1 : strlen(entity);
	}
	return result;
}

// Returns a new copy of `str` enclosed with quotes.
static char *strdup_quoted(const char *str) {
	if (str == NULL)
		return NULL;

	const size_t old_length = strlen(str);
	const size_t new_length = old_length + 2;

	char *new_str = malloc(new_length + 1); // Extra byte for NULL terminator
	if (new_str == NULL)
		return NULL;

	new_str[0] = '"';
	new_str[new_length - 1] = '"';
	new_str[new_length] = '\0';

	memcpy(new_str + 1, str, old_length);

	return new_str;
}

#if 0
static size_t escape_count_chars(const format_t *format, const char *str, size_t len) {
	return escape_count_chars_ex(str, len, format->entities_table);
}
#endif

char *escape_ex_quoted(const char *str, const entity_table_t entities) {
	if (str == NULL)
		return NULL;

	if (str[0] == '\0')
		return strdup("\"\"");

	if (entities == NULL)
		return strdup_quoted(str);

	const size_t old_length = strlen(str);
	const size_t new_length = escape_count_chars_ex(str, old_length, entities) + 2; // Extra bytes for quotes

	char *new_str = malloc(new_length + 1); // Extra byte for NULL terminator
	if (new_str == NULL)
		abort();

	new_str[0] = '"';
	new_str[new_length - 1] = '"';
	new_str[new_length] = '\0';

	// `consumed` starts in 1 because of the initial quote.
	size_t consumed = 1;
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

char *escape_ex(const char *str, const entity_table_t entities) {
	if (str == NULL)
		return NULL;

	if (str[0] == '\0')
		return strdup("");

	if (entities == NULL)
		return strdup(str);

	const size_t old_length = strlen(str);
	const size_t new_length = escape_count_chars_ex(str, old_length, entities);

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

char *escape(const format_t *format, const char *str) {
	return escape_ex(str, format->entities_table);
}

char *escape_quoted(const format_t *format, const char *str) {
	return escape_ex_quoted(str, format->entities_table);
}

// These 2 are implemented in `output.c`.
extern int output_plugin_register_format(const format_t *format);
extern void output_plugin_unregister_format(const format_t *format);

output_plugin_api_t *output_plugin_api_ptr(void) {
	static output_plugin_api_t api = {
		.output_cmdline = output_cmdline,
		.output_plugin_register_format = output_plugin_register_format,
		.output_plugin_unregister_format = output_plugin_unregister_format,
		.escape_count_chars_ex = escape_count_chars_ex,
		.escape_ex = escape_ex,
		.escape_ex_quoted = escape_ex_quoted,
		.escape = escape,
		.escape_quoted = escape_quoted
	};
	return &api;
}

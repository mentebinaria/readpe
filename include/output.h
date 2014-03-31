/*
	pev - the PE file analyzer toolkit

	output.h - Symbols and APIs to be used to output data in multiple formats.

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

#ifndef OUTPUT_H
#define OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef int format_id_t;

typedef enum {
	OUTPUT_TYPE_DOCUMENT_OPEN	= 1,
	OUTPUT_TYPE_DOCUMENT_CLOSE	= 2,
	OUTPUT_TYPE_SCOPE_OPEN		= 3,
	OUTPUT_TYPE_SCOPE_CLOSE		= 4,
	OUTPUT_TYPE_ATTRIBUTE		= 5
} output_type_e;

struct _format_t; // Forward declaration

typedef void (*output_fn)(
	const struct _format_t *format,
	const output_type_e type,
	uint16_t level,
	const char *key,
	const char *value);

typedef char * (*escape_fn)(
	const struct _format_t *format,
	const char *str);

typedef char * const entity_t;
typedef char ** const entity_table_t;

typedef struct _format_t {
	const format_id_t id;
	const char *name;
	const output_fn output_fn;
	const escape_fn escape_fn;
	const entity_table_t entities_table;
} format_t;

void output_init(void); // IMPORTANT: Requires the text plugin to be already loaded.
void output_term(void);
const char *output_cmdline(void);
void output_set_cmdline(int argc, char *argv[]);
const format_t *output_format(void);
const format_t *output_parse_format(const char *format_name);
void output_set_format(const format_t *format);
int output_set_format_by_name(const char *format_name);
size_t output_available_formats(char *buffer, size_t size, char separator);
void output_open_document(void);
void output_open_document_with_name(const char *document_name);
void output_close_document(void);
void output_open_scope(const char *scope_name);
void output_close_scope(void);
void output(const char *key, const char *value);
void output_keyval(const char *key, const char *value);

#ifdef __cplusplus
} //extern "C"
#endif

#endif

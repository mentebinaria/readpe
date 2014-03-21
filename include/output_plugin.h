/*
	pev - the PE file analyzer toolkit

	output_plugin.h - Symbols and APIs to be used by output plugins.

	Copyright (C) 2014 pev authors

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

#pragma once

#include "plugin.h"
#include "output.h"

//
// Type definitions
//

// All definitions are in output.h

//
// Indentation macros
//

#define INDENT_TAB_SIZE			4
#define INDENT_COLUMNS_(level)	(int)((int)(level) * (int)INDENT_TAB_SIZE + 1)
#define INDENT_FORMAT_			"%*s"
#define INDENT_ARGS_(level)		INDENT_COLUMNS_(level), " "
#define INDENT(level, format)	INDENT_FORMAT_ format, INDENT_ARGS_(level)

//
// Public API specific for output plugins.
//

int output_plugin_register_format(const format_t *format);
void output_plugin_unregister_format(const format_t *format);

size_t escape_count_chars_ex(const char *str, size_t len, const entity_table_t entities);
char *escape_ex(const char *str, const entity_table_t entities);
char *escape_ex_quoted(const char *str, const entity_table_t entities);
char *escape(const format_t *format, const char *str);
char *escape_quoted(const format_t *format, const char *str);

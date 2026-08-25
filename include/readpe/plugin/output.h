/* vim :set ts=4 sw=4 sts=4 et : */
/*
    readpe - the PE file analyzer toolkit

    output_plugin.h - Symbols and APIs to be used by output plugins.

    Copyright (C) 2014 - 2025 readpe authors

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

#pragma once
#ifndef READPE_OUTPUT_PLUGIN_H
#define READPE_OUTPUT_PLUGIN_H

#include "../output.h"
#include "../plugin.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Type definitions
//

// All definitions are in output.h

//
// Indentation macros
//

#define INDENT_TAB_SIZE        4
#define INDENT_COLUMNS_(level) (int) ((int) (level) * (int) INDENT_TAB_SIZE)
#define INDENT_FORMAT_         "%*s"
#define INDENT_ARGS_(level)    INDENT_COLUMNS_(level), ""
#define INDENT(level, format)  INDENT_FORMAT_ format, INDENT_ARGS_(level)

//
// Public API specific for output plugins.
//

typedef const char *(*output_plugin_cmdline_fn_t)(void);
typedef int (*output_plugin_register_format_fn_t)(const format_t *format);
typedef void (*output_plugin_unregister_format_fn_t)(const format_t *format);
typedef size_t (*output_plugin_escape_count_chars_ex_fn_t)(
    const char *str, size_t len, const entity_table_t entities);
typedef char *(*output_plugin_escape_fn_t)(const format_t *format,
                                           const char     *str);
typedef char *(*output_plugin_escape_ex_fn_t)(const char          *str,
                                              const entity_table_t entities);

struct readpe_output_api {
    const output_plugin_cmdline_fn_t               cmdline;
    const output_plugin_register_format_fn_t       register_format;
    const output_plugin_unregister_format_fn_t     unregister_format;
    const output_plugin_escape_fn_t                escape;
    const output_plugin_escape_ex_fn_t             escape_ex;
    const output_plugin_escape_fn_t                escape_quoted;
    const output_plugin_escape_ex_fn_t             escape_ex_quoted;
    const output_plugin_escape_count_chars_ex_fn_t escape_count_chars_ex;
};

struct readpe_output_plugin {
    const struct readpe_plugin readpe_plugin;
    const struct format       *format;
};

struct readpe_output_api *readpe_output_api_ptr(void);

#ifdef __cplusplus
}
#endif
#endif // READPE_OUTPUT_PLUGIN_H


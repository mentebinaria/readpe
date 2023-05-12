/* vim :set ts=4 sw=4 sts=4 et : */
/*
    readpe - the PE file analyzer toolkit

    Copyright (C) 2013 - 2025 readpe authors

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

#include "output.h"
#include "readpe.h"

#include <libpe/context.h>
#include <libpe/directories.h>
#include <libpe/macros.h>
#include <libpe/pe.h>

void print_imports(pe_ctx_t *ctx)
{
    output_open_scope("Imported functions", OUTPUT_SCOPE_TYPE_ARRAY);

    const pe_imports_t *imports = pe_imports(ctx);
    for (size_t i = 0; i < imports->dll_count; i++) {
        const pe_imported_dll_t *dll = &imports->dlls[i];
        output_open_scope("Library", OUTPUT_SCOPE_TYPE_OBJECT);
        output("Name", dll->name);
        output_open_scope("Functions", OUTPUT_SCOPE_TYPE_ARRAY);

        for (size_t j = 0; j < dll->functions_count; j++) {
            const pe_imported_function_t *func = &dll->functions[j];
            output_open_scope("Function", OUTPUT_SCOPE_TYPE_OBJECT);
            {
                if (func->ordinal) {
                    char ordinal_str[16];
                    snprintf(ordinal_str, sizeof(ordinal_str) - 1, "%" PRIu16,
                             func->ordinal);
                    output("Ordinal", ordinal_str);
                } else {
                    char hint_str[16];
                    snprintf(hint_str, sizeof(hint_str) - 1, "%" PRIu16,
                             func->hint);
                    output("Hint", hint_str);
                    output("Name", func->name);
                }
            }
            output_close_scope(); // Function
        }

        output_close_scope(); // Functions
        output_close_scope(); // Library
    }

    output_close_scope(); // Imported functions
}

void print_dependencies(pe_ctx_t *ctx)
{
    output_open_scope("Dependencies", OUTPUT_SCOPE_TYPE_ARRAY);
    const pe_imports_t *imports = pe_imports(ctx);
    for (size_t i = 0; i < imports->dll_count; i++) {
        const pe_imported_dll_t *dll = &imports->dlls[i];
        output(dll->name, NULL);
    }
    output_close_scope();
}


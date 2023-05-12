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

void print_exports(pe_ctx_t *ctx)
{
    output_open_scope("Exported functions", OUTPUT_SCOPE_TYPE_ARRAY);

    const pe_exports_t *exports = pe_exports(ctx);

    if (exports->functions_count > 0) {
        output_open_scope("Library", OUTPUT_SCOPE_TYPE_OBJECT);
        output("Name", exports->name);
        output_open_scope("Functions", OUTPUT_SCOPE_TYPE_ARRAY);
    }

    for (size_t i = 0; i < exports->functions_count; i++) {
        const pe_exported_function_t *func = &exports->functions[i];
        if (func->address != 0) {
            output_open_scope("Function", OUTPUT_SCOPE_TYPE_OBJECT);

            char ordinal_str[32] = {0};
            char address_str[16] = {0};
            snprintf(ordinal_str, sizeof(ordinal_str) - 1, "%" PRIu32,
                     func->ordinal);
            snprintf(address_str, sizeof(address_str) - 1, "%#" PRIx32,
                     func->address);

            if (func->fwd_name != NULL) {
                char full_name[300 * 2 + 4];
                snprintf(full_name, sizeof(full_name) - 1, "%s -> %s",
                         func->name, func->fwd_name);
                output("Ordinal", ordinal_str);
                output("Address", address_str);
                output("Name", full_name);
            } else {
                output("Ordinal", ordinal_str);
                output("Address", address_str);
                output("Name", func->name);
            }

            output_close_scope(); // Function
        }
    }

    if (exports->functions_count > 0) {
        output_close_scope(); // Functions
        output_close_scope(); // Library
    }

    output_close_scope(); // Exported functions
}


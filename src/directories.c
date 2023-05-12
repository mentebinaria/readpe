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

#include "common.h"
#include "output.h"
#include "readpe.h"

#include <libpe/macros.h>
#include <libpe/pe.h>
#include <stdint.h>
#include <string.h>

IMAGE_DATA_DIRECTORY **get_pe_directories(pe_ctx_t *ctx)
{
    IMAGE_DATA_DIRECTORY **directories = pe_directories(ctx);
    if (directories == NULL) {
        LIBPE_WARNING("directories not found");
    }

    return directories;
}

void print_directories(pe_ctx_t *ctx)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
    typedef struct {
        ImageDirectoryEntry entry;
        const char *const   name;
    } ImageDirectoryEntryName;
    static const ImageDirectoryEntryName directoryEntryNames[] = {
        {IMAGE_DIRECTORY_ENTRY_EXPORT,         "Export Table"}, // "Export directory",
        {IMAGE_DIRECTORY_ENTRY_IMPORT,         "Import Table"}, // "Import directory",
        {IMAGE_DIRECTORY_ENTRY_RESOURCE,
         "Resource Table"                                    }, // "Resource directory",
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION,
         "Exception Table"                                   }, // "Exception directory",
        {IMAGE_DIRECTORY_ENTRY_SECURITY,
         "Certificate Table"                                 }, // "Security directory",
        {IMAGE_DIRECTORY_ENTRY_BASERELOC,
         "Base Relocation Table"                             }, // "Base relocation table",
        {IMAGE_DIRECTORY_ENTRY_DEBUG,          "Debug"       }, // "Debug directory",
        {IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
         "Architecture"                                      }, // "Architecture-specific data",
        {IMAGE_DIRECTORY_ENTRY_GLOBALPTR,      "Global Ptr"  }, // "Global pointer",
        {IMAGE_DIRECTORY_ENTRY_TLS,
         "Thread Local Storage (TLS)"                        }, // "Thread local storage (TLS)
                                        // directory",
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
         "Load Config Table"                                 }, // "Load configuration directory",
        {IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
         "Bound Import"                                      }, // "Bound import directory",
        {IMAGE_DIRECTORY_ENTRY_IAT,
         "Import Address Table (IAT)"                        }, // "Import address table (IAT)",
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
         "Delay Import Descriptor"                           }, // "Delay import table",
        {IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
         "CLR Runtime Header"                                }, // "COM descriptor table"
        {IMAGE_DIRECTORY_RESERVED,             ""            }  // "Reserved"
    };
    // static const size_t max_directory_entry = LIBPE_SIZEOF_ARRAY(names);
#endif
    output_open_scope("Data directories", OUTPUT_SCOPE_TYPE_ARRAY);

    const uint32_t num_directories = pe_directories_count(ctx);
    if (num_directories == 0 || num_directories > MAX_DIRECTORIES) {
        return;
    }

    IMAGE_DATA_DIRECTORY **directories = pe_directories(ctx);
    if (directories == NULL) {
        return;
    }

    static char s[MAX_MSG];

    for (uint32_t i = 0; i < num_directories; i++) {
        if (directories[i]->Size) {
            // output_open_scope("Directory", OUTPUT_SCOPE_TYPE_OBJECT);
            snprintf(s, MAX_MSG, "%#x (%" PRIu32 " bytes)",
                     directories[i]->VirtualAddress, directories[i]->Size);
            output(pe_directory_name(i), s);
            // output_close_scope(); // Directory
        }
    }

    output_close_scope(); // Data directories
}

void print_directory_list(pe_ctx_t *ctx, bool verbose)
{

    output_open_scope("Data directories", OUTPUT_SCOPE_TYPE_ARRAY);
    // output_open_scope(NULL, OUTPUT_SCOPE_TYPE_ARRAY);
    const uint32_t num_directories = pe_directories_count(ctx);
    if (num_directories == 0 || num_directories > MAX_DIRECTORIES) {
        return;
    }

    IMAGE_DATA_DIRECTORY **directories = pe_directories(ctx);
    if (directories == NULL) {
        return;
    }

    static char s[MAX_MSG];

    for (uint32_t i = 0; i < num_directories; i++) {
        if (directories[i]->Size) {
            if (verbose) {
                output_open_scope("Directory", OUTPUT_SCOPE_TYPE_OBJECT);
                snprintf(s, MAX_MSG, "%#x (%" PRIu32 " bytes)",
                         directories[i]->VirtualAddress, directories[i]->Size);
                output(pe_directory_name(i), s);
                output_close_scope(); // Directory
            } else {
                output(NULL, pe_directory_name(i));
            }
        }
    }

    output_close_scope(); // Data directories
}


/* vim: set ts=4 sw=4 noet: */
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

#include <libpe/context.h>
#include <libpe/macros.h>

void print_sections(pe_ctx_t *ctx)
{

    output_open_scope("Sections", OUTPUT_SCOPE_TYPE_ARRAY);

    const uint32_t num_sections = pe_sections_count(ctx);
    if (num_sections == 0 || num_sections > MAX_SECTIONS) {
        output_close_scope(); // Sections
        return;
    }

    IMAGE_SECTION_HEADER **sections = pe_sections(ctx);
    if (sections == NULL) {
        LIBPE_WARNING("unable to read sections");
        output_close_scope(); // Sections
        return;
    }

    for (uint32_t i = 0; i < num_sections; i++) {
        print_section(ctx, sections[i], NULL);
    }

    output_close_scope(); // sections
}

void print_sections_list(pe_ctx_t *ctx)
{
    output_open_scope("Sections", OUTPUT_SCOPE_TYPE_ARRAY);

    const uint32_t num_sections = pe_sections_count(ctx);
    if (num_sections == 0 || num_sections > MAX_SECTIONS) {
        output_close_scope(); // Sections
        return;
    }

    IMAGE_SECTION_HEADER **sections = pe_sections(ctx);
    if (sections == NULL) {
        LIBPE_WARNING("unable to read sections");
        output_close_scope(); // Sections
        return;
    }

    static char section_name_buffer[SECTION_NAME_SIZE + 1];

    for (uint32_t i = 0; i < num_sections; i++) {
        const char *section_name = pe_section_name(
            ctx, sections[i], section_name_buffer, sizeof(section_name_buffer));
        output(NULL, section_name);
    }

    output_close_scope(); // Sections
}

void print_section(pe_ctx_t *ctx, IMAGE_SECTION_HEADER *section,
                   const char *section_name)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
    static const char *const flags_name[]
        = {"contains executable code",
           "contains initialized data",
           "contains uninitialized data",
           "contains data referenced through the GP",
           "contains extended relocations",
           "can be discarded as needed",
           "cannot be cached",
           "is not pageable",
           "can be shared in memory",
           "is executable",
           "is readable",
           "is writable"};
#endif
    // valid flags only for executables referenced in pecoffv8
    static const SectionCharacteristics valid_flags[]
        = {IMAGE_SCN_CNT_CODE,
           IMAGE_SCN_CNT_INITIALIZED_DATA,
           IMAGE_SCN_CNT_UNINITIALIZED_DATA,
           IMAGE_SCN_GPREL,
           IMAGE_SCN_LNK_NRELOC_OVFL,
           IMAGE_SCN_MEM_DISCARDABLE,
           IMAGE_SCN_MEM_NOT_CACHED,
           IMAGE_SCN_MEM_NOT_PAGED,
           IMAGE_SCN_MEM_SHARED,
           IMAGE_SCN_MEM_EXECUTE,
           IMAGE_SCN_MEM_READ,
           IMAGE_SCN_MEM_WRITE};

    static const size_t max_flags = LIBPE_SIZEOF_ARRAY(valid_flags);

    static char         s[MAX_MSG];
    output_open_scope("Section", OUTPUT_SCOPE_TYPE_OBJECT);

    if (section_name == NULL) {
        static char section_name_buffer[SECTION_NAME_SIZE + 1];
        section_name = pe_section_name(ctx, section, section_name_buffer,
                                       sizeof(section_name_buffer));
    }

    output("Name", section_name);

    snprintf(s, MAX_MSG, "%#x (%" PRIu32 " bytes)", section->Misc.VirtualSize,
             section->Misc.VirtualSize);
    output("Virtual Size", s);

    snprintf(s, MAX_MSG, "%#x", section->VirtualAddress);
    output("Virtual Address", s);

    snprintf(s, MAX_MSG, "%#x (%" PRIu32 " bytes)", section->SizeOfRawData,
             section->SizeOfRawData);
    output("Size Of Raw Data", s);

    snprintf(s, MAX_MSG, "%#x", section->PointerToRawData);
    output("Pointer To Raw Data", s);

    snprintf(s, MAX_MSG, "%" PRIu16, section->NumberOfRelocations);
    output("Number Of Relocations", s);

    snprintf(s, MAX_MSG, "%#x", section->Characteristics);
    output("Characteristics", s);

    output_open_scope("Characteristic Names", OUTPUT_SCOPE_TYPE_ARRAY);

    for (size_t j = 0; j < max_flags; j++) {
        if (section->Characteristics & (uint32_t) valid_flags[j]) {
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
            snprintf(s, MAX_MSG, "%s", flags_name[j]);
            output(NULL, s);
#else
            const char *characteristic_name
                = pe_section_characteristic_name(valid_flags[j]);
            char formatted_characteristic_name[32];
            if (characteristic_name == NULL) {
                snprintf(formatted_characteristic_name,
                         sizeof(formatted_characteristic_name) - 1,
                         "UNKNOWN[%#x]", valid_flags[j]);
                characteristic_name = formatted_characteristic_name;
            }
            output(NULL, characteristic_name);
#endif
        }
    }

    output_close_scope(); // Characteristic Names

    output_close_scope(); // Section
}

void print_section_by_name(pe_ctx_t *ctx, const char *section_name)
{
    IMAGE_SECTION_HEADER *section = pe_section_by_name(ctx, section_name);
    // IMAGE_SECTION_HEADER **sections = pe_sections(ctx);
    print_section(ctx, section, section_name);
}


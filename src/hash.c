/* vim :set ts=4 sw=4 sts=4 et : */
/*
    readpe - the PE file analyzer toolkit

    Copyright (C) 2012 - 2025 readpe authors

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

#include "libpe/macros.h"
#include "libpe/pe.h"
#include "modes.h"
#include "readpe/helper.h"
#include "readpe/output.h"
#include "readpe/readpe.h"
#include "readpe/settings.h"

#include <stdlib.h>
#include <string.h>

static void print_basic_hash(const unsigned char *data, size_t data_size)
{
    if (! data || ! data_size) {
        return;
    }

    const char *basic_hashes[] = {"md5", "sha1", "sha256"
#ifdef LIBPE_LINK_SSDEEP
                                  ,
                                  "ssdeep"
#endif
    };
    const size_t hash_value_size = pe_hash_recommended_size();
    char        *hash_value      = malloc_s(hash_value_size);

    for (size_t i = 0; i < sizeof(basic_hashes) / sizeof(char *); i++) {
        memset(hash_value, 0, hash_value_size);
        pe_hash_raw_data(hash_value, hash_value_size, basic_hashes[i], data,
                         data_size);
        output(basic_hashes[i], hash_value);
    }

    free(hash_value);
}

void print_content_hash(pe_ctx_t *ctx)
{
    const unsigned char *data      = ctx->map_addr;
    uint64_t             data_size = pe_filesize(ctx);

    output_open_scope("file", OUTPUT_SCOPE_TYPE_OBJECT);
    output("filepath", ctx->path);
    print_basic_hash(data, data_size);

    char *imphash = NULL;

    // imphash = pe_imphash(&ctx, LIBPE_IMPHASH_FLAVOR_MANDIANT);
    // output("imphash (Mandiant)", imphash);
    // free(imphash);

    imphash = pe_imphash(ctx, LIBPE_IMPHASH_FLAVOR_PEFILE);

    if (imphash) {
        output("imphash", imphash);
        free(imphash);
    }

    output_close_scope(); // file
}

void print_dos_header_hash(pe_ctx_t *ctx)
{
    const IMAGE_DOS_HEADER *dos_hdr   = pe_dos(ctx);
    const unsigned char    *data      = (const unsigned char *) dos_hdr;
    uint64_t                data_size = sizeof(IMAGE_DOS_HEADER);
    print_basic_hash(data, data_size);
}

void print_coff_header_hash(pe_ctx_t *ctx)
{
    const IMAGE_COFF_HEADER *coff_hdr  = pe_coff(ctx);
    const unsigned char     *data      = (const unsigned char *) coff_hdr;
    uint64_t                 data_size = sizeof(IMAGE_COFF_HEADER);
    print_basic_hash(data, data_size);
}

void print_optional_header_hash(pe_ctx_t *ctx)
{
    const unsigned char *data      = NULL;
    uint64_t             data_size = 0;

    const IMAGE_OPTIONAL_HEADER *opt_hdr = pe_optional(ctx);
    switch (opt_hdr->type) {
    case MAGIC_ROM:
        if (! pe_can_read(ctx, opt_hdr->_rom,
                          sizeof(IMAGE_ROM_OPTIONAL_HEADER))) {
            // TODO: Should we report something?
            break;
        }
        data      = (const unsigned char *) opt_hdr->_rom;
        data_size = sizeof(IMAGE_ROM_OPTIONAL_HEADER);
        break;
    case MAGIC_PE32:
        if (! pe_can_read(ctx, opt_hdr->_32,
                          sizeof(IMAGE_OPTIONAL_HEADER_32))) {
            // TODO: Should we report something?
            break;
        }
        data      = (const unsigned char *) opt_hdr->_32;
        data_size = sizeof(IMAGE_OPTIONAL_HEADER_32);
        break;
    case MAGIC_PE64:
        if (! pe_can_read(ctx, opt_hdr->_64,
                          sizeof(IMAGE_OPTIONAL_HEADER_64))) {
            // TODO: Should we report something?
            break;
        }
        data      = (const unsigned char *) opt_hdr->_64;
        data_size = sizeof(IMAGE_OPTIONAL_HEADER_64);
        break;
    }

    print_basic_hash(data, data_size);
}

void print_sections_hash(pe_ctx_t *ctx)
{
    const unsigned char         *data      = NULL;
    uint64_t                     data_size = 0;
    unsigned                     c         = pe_sections_count(ctx);
    IMAGE_SECTION_HEADER **const sections  = pe_sections(ctx);

    for (unsigned int i = 0; i < c; i++) {
        data_size = sections[i]->SizeOfRawData;
        data      = LIBPE_PTR_ADD(ctx->map_addr, sections[i]->PointerToRawData);

        if (! pe_can_read(ctx, data, data_size)) {
            LIBPE_WARNING("Unable to read section data");
        } else {
            output_open_scope("section", OUTPUT_SCOPE_TYPE_OBJECT);
            output("section_name", (char *) sections[i]->Name);
            if (data_size) {
                print_basic_hash(data, data_size);
            }
            output_close_scope(); // section
        }
    }
}

static void print_section_hash(pe_ctx_t                   *ctx,
                               const IMAGE_SECTION_HEADER *section_ptr)
{
    const unsigned char *data      = NULL;
    uint64_t             data_size = 0;

    if (section_ptr != NULL) {
        if (section_ptr->SizeOfRawData > 0) {
            const uint8_t *section_data_ptr
                = LIBPE_PTR_ADD(ctx->map_addr, section_ptr->PointerToRawData);
            // fprintf(stderr, "map_addr = %p\n", ctx.map_addr);
            // fprintf(stderr, "section_data_ptr = %p\n", section_data_ptr);
            // fprintf(stderr, "SizeOfRawData = %u\n",
            // section_ptr->SizeOfRawData);
            if (! pe_can_read(ctx, section_data_ptr,
                              section_ptr->SizeOfRawData)) {
                EXIT_ERROR("The requested section has an invalid size");
            }
            data      = (const unsigned char *) section_data_ptr;
            data_size = section_ptr->SizeOfRawData;
        } else {
            data      = (const unsigned char *) "";
            data_size = 0;
        }
    }

    char name[9] = {0};
    strncpy(name, (char *) section_ptr->Name, 8);
    name[8] = 0;

    if (data != NULL) {
        output("section_name", (char *) name);
        print_basic_hash(data, data_size);
    }
}

void print_section_hash_by_index(pe_ctx_t *ctx, unsigned int index)
{

    IMAGE_SECTION_HEADER **const sections     = pe_sections(ctx);
    const uint16_t               num_sections = pe_sections_count(ctx);
    if (num_sections == 0 || index > num_sections) {
        EXIT_ERROR("The requested section could not be found on this binary");
    }
    const IMAGE_SECTION_HEADER *section = sections[index - 1];
    print_section_hash(ctx, section);
}

void print_section_hash_by_name(pe_ctx_t *ctx, char *name)
{
    const IMAGE_SECTION_HEADER *section = pe_section_by_name(ctx, name);
    if (section == NULL) {
        EXIT_ERROR("The requested section could not be found on this binary");
    }
    print_section_hash(ctx, section);
}

void print_hash(pe_ctx_t *ctx, const struct readpe_settings *settings)
{
    switch (settings->context) {
    case MODE_HEADERS:
        output_open_scope("headers", OUTPUT_SCOPE_TYPE_ARRAY);

        output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
        output("header_name", "IMAGE_DOS_HEADER");
        print_dos_header_hash(ctx);
        output_close_scope(); // header

        output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
        output("header_name", "IMAGE_COFF_HEADER");
        print_coff_header_hash(ctx);
        output_close_scope(); // header

        output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
        output("header_name", "IMAGE_OPTIONAL_HEADER");
        print_optional_header_hash(ctx);
        output_close_scope(); // header
        output_close_scope(); // headers
        break;
    case MODE_HEADERS_DOS:
        print_dos_header_hash(ctx);
        break;
    case MODE_HEADERS_COFF:
        print_coff_header_hash(ctx);
        break;
    case MODE_HEADERS_OPTIONAL:
        print_optional_header_hash(ctx);
        break;
    case MODE_SECTIONS:
        output_open_scope("sections", OUTPUT_SCOPE_TYPE_ARRAY);
        print_sections_hash(ctx);
        output_close_scope(); // sections
        break;
    case MODE_SECTION:
        if (settings->section_name != NULL) {
            print_section_hash_by_name(ctx, settings->section_name);
        } else if (settings->section_index > 0) {
            print_section_hash_by_index(ctx, settings->section_index);
        }
        break;
    default:
        print_content_hash(ctx);
        break;
    }
}


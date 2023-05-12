/* vim: set ts=4 sw=4 noet: */
/*
        readpe - the PE file analyzer toolkit

        readpe.h

        Copyright (C) 2023 readpe authors

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
#ifndef READPE_READPE_H
#define READPE_READPE_H

#include <libpe/context.h>
#include <libpe/pe.h>
#include <libpe/resources.h>
#include <libpe/types_resources.h>
#include <libpe/utlist.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CERT_FORMAT_X509 = 1,
    CERT_FORMAT_PEM  = 2,
    CERT_FORMAT_DER  = 3
} cert_format_e;

typedef enum HASH_ALGORITHMS {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SSDEEP,
    HASH_IMPHASH,
    HASH_ALL
} hash_alghorithms_e;

struct readpe_settings {
    int          mode;
    int          context;

    char        *format;
    // bool help;
    bool         list;
    bool         verbose;
    bool         file_version;

    bool         res_info;
    bool         res_named;
    bool         res_statistics;
    bool         res_tree;

    bool         str_offset;
    bool         str_section;
    unsigned int str_min_length;

    void        *cert_out;
    void        *cert_format;

    char        *section_name;
    unsigned int section_index;

    bool         all;
};

// typedef struct {
//     const char *certoutform;
//     const char *certout;
// } certificate_settings;

// ------------------------------------------------------------------------- //

void print_dos_header(pe_ctx_t *ctx);
void print_coff_header(pe_ctx_t *ctx);
void print_optional_header(pe_ctx_t *ctx);

void print_section(pe_ctx_t *ctx, IMAGE_SECTION_HEADER *section,
                   const char *section_name);
void print_section_by_name(pe_ctx_t *ctx, const char *section_name);
void print_sections(pe_ctx_t *ctx);
void print_sections_list(pe_ctx_t *ctx);

IMAGE_DATA_DIRECTORY **get_pe_directories(pe_ctx_t *ctx);
void                   print_directories(pe_ctx_t *ctx);
void                   print_directory_list(pe_ctx_t *ctx, bool verbose);
void                   print_imports(pe_ctx_t *ctx);
void                   print_exports(pe_ctx_t *ctx);
void                   print_dependencies(pe_ctx_t *ctx);

void                   print_resources(pe_ctx_t *ctx);
void                   print_resources_list(pe_ctx_t *ctx);
void                   print_resources_stats(pe_ctx_t *ctx);
void                   print_file_version(pe_ctx_t *ctx);
void                   extract_all_resources(pe_ctx_t *ctx, bool named);

void print_hash(pe_ctx_t *ctx, const struct readpe_settings *settings);
void print_content_hash(pe_ctx_t *ctx);
void print_dos_header_hash(pe_ctx_t *ctx);
void print_coff_header_hash(pe_ctx_t *ctx);
void print_optional_header_hash(pe_ctx_t *ctx);
void print_sections_hash(pe_ctx_t *ctx);
void print_section_hash_by_name(pe_ctx_t *ctx, char *name);
void print_section_hash_by_index(pe_ctx_t *ctx, unsigned int index);

void pe_scan(pe_ctx_t *ctx, bool verbose);
bool stack_cookies(pe_ctx_t *ctx);
void print_securities(pe_ctx_t *ctx);
void print_certificates(pe_ctx_t *ctx, const char *format, const char *out);
void print_certificates_info(pe_ctx_t *ctx, const char *format, const char *out,
                             bool verbose);

// ------------------------------------------------------------------------- //

typedef struct {
    unsigned short strsize;
    bool           offset;
    bool           section;
} string_settings;

void print_strings(pe_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif


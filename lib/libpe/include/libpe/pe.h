/*
    libpe - the PE library

    Copyright (C) 2010 - 2017 libpe authors
    
    This file is part of libpe.

    libpe is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libpe is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LIBPE_H
#define LIBPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "macros.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "context.h"
#include "error.h"
#include "hdr_dos.h"
#include "hdr_coff.h"
#include "hdr_optional.h"
#include "directories.h"
#include "sections.h"
#include "hashes.h"
#include "imports.h"
#include "exports.h"
#include "resources.h"
#include "utils.h"

#define MAGIC_MZ 0x5a4d // Belongs to the DOS header
#define MAX_DIRECTORIES 16
#define MAX_SECTIONS 96

// TODO(jweyrich): Does the PE spec define a length limit for
//                 function names and import/export library names?
#define MAX_DLL_NAME 256
#define MAX_FUNCTION_NAME 512

static const uint32_t IMAGE_ORDINAL_FLAG32 = 0x80000000;
static const uint64_t IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;

#define SIGNATURE_NE 0x454E // NE\0\0 in little-endian
#define SIGNATURE_PE 0x4550 // PE\0\0 in little-endian

typedef enum {
	LIBPE_OPT_NOCLOSE_FD = (1 << 0), // Keeps `stream` open for further usage.
	LIBPE_OPT_OPEN_RW    = (1 << 1)  // Open file for read and writing
} pe_option_e;

typedef uint16_t pe_options_e; // bitmasked pe_option_e values

// General functions
bool pe_can_read(const pe_ctx_t *ctx, const void *ptr, size_t size);
pe_err_e pe_load_file(pe_ctx_t *ctx, const char *path);
pe_err_e pe_load_file_ext(pe_ctx_t *ctx, const char *path, pe_options_e options);
pe_err_e pe_unload(pe_ctx_t *ctx);
pe_err_e pe_parse(pe_ctx_t *ctx);
bool pe_is_loaded(const pe_ctx_t *ctx);
bool pe_is_pe(const pe_ctx_t *ctx);
bool pe_is_dll(const pe_ctx_t *ctx);
uint64_t pe_filesize(const pe_ctx_t *ctx);
IMAGE_SECTION_HEADER *pe_rva2section(pe_ctx_t *ctx, uint64_t rva);
uint64_t pe_rva2ofs(const pe_ctx_t *ctx, uint64_t rva);
uint64_t pe_ofs2rva(const pe_ctx_t *ctx, uint64_t ofs);

// Header functions
IMAGE_DOS_HEADER *pe_dos(pe_ctx_t *ctx);
IMAGE_COFF_HEADER *pe_coff(pe_ctx_t *ctx);
IMAGE_OPTIONAL_HEADER *pe_optional(pe_ctx_t *ctx);
uint32_t pe_directories_count(const pe_ctx_t *ctx);
IMAGE_DATA_DIRECTORY **pe_directories(pe_ctx_t *ctx);
IMAGE_DATA_DIRECTORY *pe_directory_by_entry(pe_ctx_t *ctx, ImageDirectoryEntry entry);
uint16_t pe_sections_count(const pe_ctx_t *ctx);
IMAGE_SECTION_HEADER **pe_sections(pe_ctx_t *ctx);
IMAGE_SECTION_HEADER *pe_section_by_name(pe_ctx_t *ctx, const char *section_name);
const char *pe_section_name(const pe_ctx_t *ctx, const IMAGE_SECTION_HEADER *section_hdr, char *out_name, size_t out_name_size);

const char *pe_machine_type_name(MachineType type);
const char *pe_image_characteristic_name(ImageCharacteristics characteristic);
const char *pe_image_dllcharacteristic_name(ImageDllCharacteristics characteristic);
const char *pe_windows_subsystem_name(WindowsSubsystem subsystem);
const char *pe_directory_name(ImageDirectoryEntry entry);
const char *pe_section_characteristic_name(SectionCharacteristics characteristic);

// Hash functions
size_t pe_hash_recommended_size(void);
bool pe_hash_raw_data(char *output, size_t output_size, const char *alg_name, const unsigned char *data, size_t data_size);
pe_hash_headers_t *pe_get_headers_hashes(pe_ctx_t *ctx);
pe_hash_sections_t *pe_get_sections_hash(pe_ctx_t *ctx);
pe_hash_t *pe_get_file_hash(pe_ctx_t *ctx);
char *pe_imphash(pe_ctx_t *ctx, pe_imphash_flavor_e flavor);

// Imports functions
pe_imports_t *pe_imports(pe_ctx_t *ctx);

// Exports functions
pe_exports_t *pe_exports(pe_ctx_t *ctx);

// Resources functions
pe_resources_t *pe_resources(pe_ctx_t *ctx);

// Misc functions
double pe_calculate_entropy_file(pe_ctx_t *ctx);
bool pe_fpu_trick(pe_ctx_t *ctx);
int pe_get_cpl_analysis(pe_ctx_t *ctx);
int pe_has_fake_entrypoint(pe_ctx_t *ctx);
int pe_get_tls_callback(pe_ctx_t *ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

/*
    libpe - the PE library

    Copyright (C) 2010 - 2023 libpe authors
    
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

#ifndef LIBPE_CONTEXT_H
#define LIBPE_CONTEXT_H

#include <stdio.h>
#include <inttypes.h>

#include "hdr_dos.h"
#include "hdr_coff.h"
#include "hdr_optional.h"
#include "directories.h" 
#include "sections.h"
#include "imports.h"
#include "exports.h"
#include "hashes.h"
#include "types_resources.h"

typedef struct {
	// DOS header
	IMAGE_DOS_HEADER *dos_hdr;
	// Signature
	uint32_t signature;
	// COFF header
	IMAGE_COFF_HEADER *coff_hdr;
	// Optional header
	void *optional_hdr_ptr;
	IMAGE_OPTIONAL_HEADER optional_hdr;
	// Directories
	uint32_t num_directories;
	void *directories_ptr;
	IMAGE_DATA_DIRECTORY **directories; // array up to MAX_DIRECTORIES
	// Sections
	uint16_t num_sections;
	void *sections_ptr;
	IMAGE_SECTION_HEADER **sections; // array up to MAX_SECTIONS
	uint64_t entrypoint;
	uint64_t imagebase;
} pe_file_t;

typedef struct {
	// Parsed directories
	pe_imports_t *imports;
	pe_exports_t *exports;
	// Hashes
	pe_hash_headers_t *hash_headers;
	pe_hash_sections_t *hash_sections;
	pe_hash_t *hash_file;
	// Resources
	pe_resources_t *resources;
} pe_cached_data_t;

typedef struct pe_ctx {
	FILE *stream;
	char *path;
	void *map_addr;
	off_t map_size;
	uintptr_t map_end;
	pe_file_t pe;
	pe_cached_data_t cached_data;
} pe_ctx_t;

#endif

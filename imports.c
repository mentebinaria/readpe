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

#include "libpe/imports.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

uint32_t get_dll_count(pe_ctx_t *ctx) {
	uint32_t count = 0;

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		return count;

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "import directory not found\n");
		return count;
	}

	uint64_t ofs = pe_rva2ofs(ctx, va);

	while (1) {
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			return count;
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		
		const uint64_t aux = ofs; // Store current ofs
		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk
			? id->u1.OriginalFirstThunk
			: id->FirstThunk);
		if (ofs == 0)
			break;

		count++;
		ofs = aux; // Restore previous ofs
	}

	return count;	
}

uint32_t get_functions_count(pe_ctx_t *ctx, uint64_t offset) {
	uint64_t ofs = offset;
	uint32_t count = 0;

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
			{
				const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32)))
					return count;

				// Type punning
				const uint32_t thunk_type = *(uint32_t *)thunk;
				if (thunk_type == 0)
					return count;

				const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
				const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
				if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME)))
					return count;

				ofs += sizeof(IMAGE_THUNK_DATA32);
				break;
			}
			case MAGIC_PE64:
			{
				const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64)))
					return count;

				const uint64_t thunk_type = *(uint64_t *)thunk;
				if (thunk_type == 0)
					return count;

				uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
				const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
				if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME)))
					return count;

				ofs += sizeof(IMAGE_THUNK_DATA64);
				break;
			}
		}
		count++;
	}

	return count;
}

pe_imported_function_t get_imported_functions(pe_ctx_t *ctx, uint64_t offset, uint32_t functions_count, char *hint_str, size_t size_hint_str, char *fname, size_t size_fname) {
	pe_imported_function_t sample;
	memset(&sample, 0, sizeof(pe_imported_function_t));

	sample.err = LIBPE_E_OK;
	sample.count = functions_count;

	const size_t names_size = functions_count * sizeof(char *);
	sample.names = malloc(names_size);
	if (sample.names == NULL) {
		sample.err = LIBPE_E_ALLOCATION_FAILURE;
		return sample;
	}
	memset(sample.names, 0, names_size);

	// allocate space for each string.
	const size_t name_size = MAX_FUNCTION_NAME;
	for (uint32_t i=0; i < functions_count; i++) {
		char *name = malloc(name_size);
		if (name == NULL) {
			sample.err = LIBPE_E_ALLOCATION_FAILURE;
			return sample;
		}
		memset(name, 0, name_size);
		sample.names[i] = name;
	}

	bool is_ordinal = false;
	uint64_t ofs = offset;

	for (uint32_t i=0; i < functions_count; i++) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
			{
				const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
					sample.err = LIBPE_E_ALLOCATION_FAILURE;
					return sample;
				}

				// Type punning
				const uint32_t thunk_type = *(uint32_t *)thunk;
				if (thunk_type == 0) {
					sample.err = LIBPE_E_TYPE_PUNNING_FAILED;
					return sample;
				}

				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

				if (is_ordinal) {
					snprintf(hint_str, size_hint_str-1, "%"PRIu32,
						thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
				} else {
					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						sample.err = LIBPE_E_ALLOCATION_FAILURE;
						return sample;// Do something so that the API notifes of the error
					}

					snprintf(hint_str, size_hint_str-1, "%d", imp_name->Hint);
					strncpy(fname, (char *)imp_name->Name, size_fname-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[size_fname - 1] = '\0';
					//size_t fname_len = strlen(fname);
				}
				ofs += sizeof(IMAGE_THUNK_DATA32);
				break;
			}
			case MAGIC_PE64:
			{
				const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
					sample.err = LIBPE_E_ALLOCATION_FAILURE;
					return sample; // DO something so that API notifies of the error
				}

				// Type punning
				const uint64_t thunk_type = *(uint64_t *)thunk;
				if (thunk_type == 0) {
					sample.err = LIBPE_E_TYPE_PUNNING_FAILED;
					return sample;
				}

				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG64) != 0;

				if (is_ordinal) {
					snprintf(hint_str, size_hint_str-1, "%llu",
						thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64);
				} else {
					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						sample.err = LIBPE_E_ALLOCATION_FAILURE;
						return sample; // Do something so that API notifies of the error
					}

					snprintf(hint_str, size_hint_str-1, "%d", imp_name->Hint);
					strncpy(fname, (char *)imp_name->Name, size_fname-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[size_fname - 1] = '\0';
					//size_t fname_len = strlen(fname);
				}
				ofs += sizeof(IMAGE_THUNK_DATA64);
				break;
			}
		}

		if (is_ordinal)
			memcpy(sample.names[i], hint_str, 16);
		else
			memcpy(sample.names[i], fname, MAX_FUNCTION_NAME);
	}

	return sample;
}

pe_import_t pe_get_imports(pe_ctx_t *ctx) {
	pe_import_t imports;
	memset(&imports, 0, sizeof(pe_import_t));

	imports.err = LIBPE_E_OK;
	
	imports.dll_count = get_dll_count(ctx);
	if (imports.dll_count == 0)
		return imports;

	const size_t dll_names_size = imports.dll_count * sizeof(char *);
	imports.dll_names = malloc(dll_names_size);
	if (imports.dll_names == NULL) {
		imports.err = LIBPE_E_ALLOCATION_FAILURE;
		return imports;
	}
	memset(imports.dll_names, 0, dll_names_size);

	for (uint32_t i=0; i < imports.dll_count; i++) {
		const size_t dll_name_size = MAX_DLL_NAME;
		char *dll_name = malloc(dll_name_size);
		if (dll_name == NULL) {
			imports.err = LIBPE_E_ALLOCATION_FAILURE;
			return imports;
		}
		memset(dll_name, 0, dll_name_size);
		imports.dll_names[i] = dll_name;
	}

	const size_t functions_size = imports.dll_count * sizeof(pe_imported_function_t *);
	imports.functions = malloc(functions_size);
	if (imports.functions == NULL) {
		imports.err = LIBPE_E_ALLOCATION_FAILURE;
		return imports;
	}
	memset(imports.functions, 0, functions_size);

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL) {
		// TODO: report error?
		return imports;
	}

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		// TODO: report error?
		return imports;
	}

	uint64_t ofs = pe_rva2ofs(ctx, va);

	for (uint32_t i=0; i < imports.dll_count; i++) {
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			break;
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs

		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		const char *dll_name_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);

		if (!pe_can_read(ctx, dll_name_ptr, 1)) {
			// TODO: Should we report something?
			break;
		}

		char dll_name[MAX_DLL_NAME];

		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		strncpy(dll_name, dll_name_ptr, sizeof(dll_name)-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll_name[sizeof(dll_name) - 1] = '\0';

		//	imports.names[i] = dll_name;
		memcpy(imports.dll_names[i], dll_name, MAX_DLL_NAME);
		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk
			? id->u1.OriginalFirstThunk
			: id->FirstThunk);
		if (ofs == 0) {
			break;
		}

		char hint_str[16];
		char fname[MAX_FUNCTION_NAME];
		memset(hint_str, 0, sizeof(hint_str));
		memset(fname, 0, sizeof(fname));

		size_t size_hint_str = sizeof(hint_str);
		size_t size_fname = sizeof(fname);
		uint32_t functions_count = get_functions_count(ctx, ofs);

		imports.functions[i] = get_imported_functions(ctx, ofs, functions_count, hint_str,size_hint_str, fname, size_fname);
		if (imports.functions[i].err != LIBPE_E_OK) {
			imports.err = imports.functions[i].err;
			return imports;
		}

		ofs = aux; // Restore previous ofs
	}

	return imports;
}

void pe_dealloc_imports(pe_import_t imports) {
	for (uint32_t i=0; i < imports.dll_count; i++) {
		free(imports.dll_names[i]);

		for (uint32_t j=0; j < imports.functions[i].count; j++) {
			free(imports.functions[i].names[j]);
		}

		free(imports.functions[i].names);
	}
	free(imports.dll_names);
	free(imports.functions);
}

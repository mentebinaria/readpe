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

#include "libpe/pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

static uint32_t get_dll_count(pe_ctx_t *ctx) {
	uint32_t count = 0;

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		return count;

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		// TODO: report error?
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

static uint32_t get_functions_count(pe_ctx_t *ctx, uint64_t offset) {
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

				bool is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

				if (!is_ordinal) {
					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME)))
						return count;
				}

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

				bool is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;
				
				if (!is_ordinal) {
					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME)))
						return count;
				}

				ofs += sizeof(IMAGE_THUNK_DATA64);
				break;
			}
		}

		count++;
	}

	return count;
}

static pe_err_e parse_imported_functions(pe_ctx_t *ctx, pe_imported_dll_t *imported_dll, uint64_t offset) {
	imported_dll->err = LIBPE_E_OK;
	imported_dll->functions_count = get_functions_count(ctx, offset);

	const size_t size_functions = imported_dll->functions_count * sizeof(pe_imported_function_t);
	imported_dll->functions = malloc(size_functions);
	if (imported_dll->functions == NULL) {
		imported_dll->err = LIBPE_E_ALLOCATION_FAILURE;
		return imported_dll->err;
	}
	memset(imported_dll->functions, 0, size_functions);

	char fname[MAX_FUNCTION_NAME] = {0};
	const size_t size_fname = sizeof(fname);

	bool is_ordinal = false;
	uint16_t ordinal = 0;
	uint16_t hint = 0;
	uint64_t ofs = offset;

	for (uint32_t i=0; i < imported_dll->functions_count; i++) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
			{
				const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
					imported_dll->err = LIBPE_E_INVALID_THUNK;
					return imported_dll->err;
				}

				// Type punning
				const uint32_t thunk_type = *(uint32_t *)thunk;
				if (thunk_type == 0) {
					imported_dll->err = LIBPE_E_INVALID_THUNK;
					return imported_dll->err;
				}

				// If the MSB of the member is 1, the function is exported by ordinal.
				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

				if (is_ordinal) {
					hint = 0;
					ordinal = (thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32) & 0xffff;
				} else {
					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						imported_dll->err = LIBPE_E_ALLOCATION_FAILURE;
						return imported_dll->err;
					}

					hint = imp_name->Hint;
					ordinal = 0;

					strncpy(fname, (char *)imp_name->Name, size_fname-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[size_fname - 1] = '\0';
				}

				ofs += sizeof(IMAGE_THUNK_DATA32);
				break;
			}
			case MAGIC_PE64:
			{
				const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
					imported_dll->err = LIBPE_E_ALLOCATION_FAILURE;
					return imported_dll->err; // DO something so that API notifies of the error
				}

				// Type punning
				const uint64_t thunk_type = *(uint64_t *)thunk;
				if (thunk_type == 0) {
					imported_dll->err = LIBPE_E_INVALID_THUNK;
					return imported_dll->err;
				}

				// If the MSB of the member is 1, the function is exported by ordinal.
				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG64) != 0;

				if (is_ordinal) {
					hint = 0; // No hint
					ordinal = (thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64) & 0xffff;
				} else {
					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						imported_dll->err = LIBPE_E_ALLOCATION_FAILURE;
						return imported_dll->err;
					}

					hint = imp_name->Hint;
					ordinal = 0; // No ordinal

					strncpy(fname, (char *)imp_name->Name, size_fname-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[size_fname - 1] = '\0';
				}

				ofs += sizeof(IMAGE_THUNK_DATA64);
				break;
			}
		}

		imported_dll->functions[i].hint = hint;
		imported_dll->functions[i].ordinal = ordinal;

		if (!is_ordinal) {
			imported_dll->functions[i].name = strdup(fname);
			if (imported_dll->functions[i].name == NULL) {
				imported_dll->err = LIBPE_E_ALLOCATION_FAILURE;
				return imported_dll->err;
			}
		}
	}

	return LIBPE_E_OK;
}

pe_imports_t *pe_imports(pe_ctx_t *ctx) {
	if (ctx->cached_data.imports != NULL)
		return ctx->cached_data.imports;

	pe_imports_t *imports = ctx->cached_data.imports = malloc(sizeof(pe_imports_t));
	if (imports == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}
	memset(imports, 0, sizeof(pe_imports_t));

	imports->err = LIBPE_E_OK;
	
	imports->dll_count = get_dll_count(ctx);
	if (imports->dll_count == 0)
		return imports;

	// Allocate array to store DLLs
	const size_t dll_array_size = imports->dll_count * sizeof(pe_imported_dll_t);
	imports->dlls = malloc(dll_array_size);
	if (imports->dlls == NULL) {
		imports->err = LIBPE_E_ALLOCATION_FAILURE;
		return imports;
	}
	memset(imports->dlls, 0, dll_array_size);

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL) {
		return imports;
	}

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		// TODO: report error?
		return imports;
	}

	uint64_t ofs = pe_rva2ofs(ctx, va);

	for (uint32_t i=0; i < imports->dll_count; i++) {
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

		pe_imported_dll_t * const dll = &imports->dlls[i];

		// Allocate string to store DLL name
		const size_t dll_name_size = MAX_DLL_NAME;
		dll->name = malloc(dll_name_size);
		if (dll->name == NULL) {
			imports->err = LIBPE_E_ALLOCATION_FAILURE;
			return imports;
		}
		memset(dll->name, 0, dll_name_size);

		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		strncpy(dll->name, dll_name_ptr, dll_name_size-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll->name[dll_name_size - 1] = '\0';

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk
			? id->u1.OriginalFirstThunk
			: id->FirstThunk);
		if (ofs == 0) {
			break;
		}
	
		pe_err_e parse_err = parse_imported_functions(ctx, dll, ofs);
		if (parse_err != LIBPE_E_OK) {
			imports->err = parse_err;
			return imports;
		}

		ofs = aux; // Restore previous ofs
	}

	return imports;
}

void pe_imports_dealloc(pe_imports_t *obj) {
	if (obj == NULL)
		return;

	for (uint32_t i=0; i < obj->dll_count; i++) {
		const pe_imported_dll_t *dll = &obj->dlls[i];
		for (uint32_t j=0; j < dll->functions_count; j++) {
			const pe_imported_function_t *function = &dll->functions[j];
			free(function->name);
		}
		free(dll->name);
		free(dll->functions);
	}
	free(obj->dlls);
	free(obj);
}

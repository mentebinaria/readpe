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

#include "libpe/exports.h"

#include <stdlib.h>
#include <string.h>

pe_exports_t pe_get_exports(pe_ctx_t *ctx) {
	pe_exports_t exports;
	memset(&exports, 0, sizeof(pe_exports_t));

	exports.err = LIBPE_E_OK;

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL) { 
		exports.err =	LIBPE_E_EXPORTS_DIR;
		return exports;
	}

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		exports.err = LIBPE_E_EXPORTS_VA;
		return exports;
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	const IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
		exports.err = LIBPE_E_EXPORTS_CANT_READ_EXP;
		return exports;
	}

	ofs = pe_rva2ofs(ctx, exp->AddressOfNames);
	const uint32_t *rva_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, rva_ptr, sizeof(uint32_t))) {
		exports.err = LIBPE_E_EXPORTS_CANT_READ_RVA;
		return exports;
	}

	// If `NumberOfNames == 0` then all functions are exported by ordinal.
	// Otherwise `NumberOfNames` must be equal to `NumberOfFunctions`
	if (exp->NumberOfNames != 0 && exp->NumberOfNames != exp->NumberOfFunctions) {
		exports.err = LIBPE_E_EXPORTS_FUNC_NEQ_NAMES;
		return exports;
	}

	uint64_t offset_to_AddressOfFunctions = pe_rva2ofs(ctx, exp->AddressOfFunctions);
	uint64_t offset_to_AddressOfNames = pe_rva2ofs(ctx, exp->AddressOfNames);
	uint64_t offset_to_AddressOfNameOrdinals = pe_rva2ofs(ctx, exp->AddressOfNameOrdinals);

	//
	// The format of IMAGE_EXPORT_DIRECTORY can be seen in http://i.msdn.microsoft.com/dynimg/IC60608.gif
	//

	// We want to use `NumberOfFunctions` for looping as it's the total number of functions/symbols
	// exported by the module. On the other hand, `NumberOfNames` is the number of
	// functions/symbols exported by name only.

	exports.functions_count = exp->NumberOfFunctions;
	const size_t functions_size = exp->NumberOfFunctions * sizeof(pe_exported_function_t);
	exports.functions = malloc(functions_size);
	if (exports.functions == NULL) {
		exports.err = LIBPE_E_ALLOCATION_FAILURE;
		return exports;
	}
	memset(exports.functions, 0, functions_size);

	for (uint32_t i=0; i < exp->NumberOfFunctions; i++) {
		uint64_t entry_ordinal_list_ptr = offset_to_AddressOfNameOrdinals + sizeof(uint16_t) * i;
		uint16_t *entry_ordinal_list = LIBPE_PTR_ADD(ctx->map_addr, entry_ordinal_list_ptr);

		uint64_t entry_va_list_ptr = offset_to_AddressOfFunctions + sizeof(uint32_t) * i;
		uint32_t *entry_va_list = LIBPE_PTR_ADD(ctx->map_addr, entry_va_list_ptr);

		uint64_t entry_name_list_ptr = offset_to_AddressOfNames + sizeof(uint32_t) * i;
		uint32_t *entry_name_list = LIBPE_PTR_ADD(ctx->map_addr, entry_name_list_ptr);

		if (!pe_can_read(ctx, entry_ordinal_list, sizeof(uint32_t))) {
			break;
		}

		if (!pe_can_read(ctx, entry_va_list, sizeof(uint32_t))) {
			break;
		}

		if (!pe_can_read(ctx, entry_name_list, sizeof(uint32_t))) {
			break;
		}

		// Add `Base` to the element of `AddressOfNameOrdinals` array to get the correct ordinal..
		//const uint16_t entry_ordinal = exp->Base + *entry_ordinal_list;
		const uint32_t entry_va = *entry_va_list;
		const uint32_t entry_name_rva = *entry_name_list;
		const uint64_t entry_name_ofs = pe_rva2ofs(ctx, entry_name_rva);
		const char *entry_name = LIBPE_PTR_ADD(ctx->map_addr, entry_name_ofs);

		// Validate whether it's ok to access at least 1 byte after entry_name.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, entry_name, 1)) {
			break;
		}

		exports.functions[i].addr = entry_va;

		char fname[300] = { 0 };
		const size_t fname_size = sizeof(fname);
		strncpy(fname, entry_name, fname_size-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		fname[fname_size - 1] = '\0';

		// Check whether the exported function is forwarded.
		// It's forwarded if its RVA is inside the exports section.
		if (entry_va >= va && entry_va <= va + dir->Size) {
			// When a symbol is forwarded, its RVA points to a string containing
			// the name of the DLL and symbol to which it is forwarded.
			const uint64_t fw_entry_name_ofs = pe_rva2ofs(ctx, entry_va);
			const char *fw_entry_name = LIBPE_PTR_ADD(ctx->map_addr, fw_entry_name_ofs);

			// Validate whether it's ok to access at least 1 byte after fw_entry_name.
			// It might be '\0', for example.
			if (!pe_can_read(ctx, fw_entry_name, 1)) {
				break;
			}

			char fname_forwarded[sizeof(fname) * 2 + 4] = { 0 }; // Twice the size plus " -> ".
			
			const size_t function_name_size = sizeof(fname_forwarded);
			exports.functions[i].name = malloc(function_name_size);
			if (exports.functions[i].name) {
				exports.err = LIBPE_E_ALLOCATION_FAILURE;
				return exports;
			}

			snprintf(fname_forwarded, function_name_size-1, "%s -> %s", fname, fw_entry_name);
			memcpy(exports.functions[i].name, fname_forwarded, function_name_size);
		} else {
			exports.functions[i].name = malloc(fname_size);
			if (exports.functions[i].name) {
				exports.err = LIBPE_E_ALLOCATION_FAILURE;
				return exports;
			}

			memcpy(exports.functions[i].name, fname, fname_size);
		}
	}

	return exports;
}

void pe_dealloc_exports(pe_exports_t obj) {
	for (uint32_t i=0; i < obj.functions_count; i++) {
		free(obj.functions[i].name);
	}

	free(obj.functions);
}

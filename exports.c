#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "exports.h"
#include "pe.h"
int get_exports_functions_count(pe_ctx_t *ctx) {
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL) {
		//EXIT_ERROR("export directory not found")
		return 0;
	}	
	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		//fprintf(stderr, "export directory not found\n");
		// return;
		return 0;
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	const IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	return exp->NumberOfFunctions;
}

exports *get_exports(pe_ctx_t *ctx)
{
	exports *sample;
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL) { 
		//EXIT_ERROR("export directory not found") 
		printf("Directory is null \n");
		return NULL; 
	}
	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		//fprintf(stderr, "export directory not found\n");
		printf("Virtual Address is null\n");
		return NULL;
		
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	const IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
		// TODO: Should we report something?
		//return;
		printf("cannot read export data \n");
		return NULL;
	}

	ofs = pe_rva2ofs(ctx, exp->AddressOfNames);
	const uint32_t *rva_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, rva_ptr, sizeof(uint32_t))) {
		// TODO: Should we report something?
		//return;
		printf(" Cannot read ofs"); 
		return NULL;
	}
	const uint32_t rva = *rva_ptr;

	ofs = pe_rva2ofs(ctx, rva);

	//output_open_scope("Exported functions", OUTPUT_SCOPE_TYPE_ARRAY);
	// If `NumberOfNames == 0` then all functions are exported by ordinal.
	// Otherwise `NumberOfNames` must be equal to `NumberOfFunctions`
	if (exp->NumberOfNames != 0 && exp->NumberOfNames != exp->NumberOfFunctions) {
		// fprintf(stderr, "NumberOfFunctions differs from NumberOfNames\n");
		//output_close_scope(); // Exported functions
		printf(" number of names not equals to number of sections"); // Number of functions difffer for number of names
		return NULL;
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

	sample = (exports *)malloc(exp->NumberOfFunctions*sizeof(exports *));

	//printf("Number Of Functions : %d\n", exp->NumberOfFunctions);
	for (uint32_t i=0; i < exp->NumberOfFunctions; i++) {
		uint64_t entry_ordinal_list_ptr = offset_to_AddressOfNameOrdinals + sizeof(uint16_t) * i;
		uint16_t *entry_ordinal_list = LIBPE_PTR_ADD(ctx->map_addr, entry_ordinal_list_ptr);

		uint64_t entry_va_list_ptr = offset_to_AddressOfFunctions + sizeof(uint32_t) * i;
		uint32_t *entry_va_list = LIBPE_PTR_ADD(ctx->map_addr, entry_va_list_ptr);

		uint64_t entry_name_list_ptr = offset_to_AddressOfNames + sizeof(uint32_t) * i;
		uint32_t *entry_name_list = LIBPE_PTR_ADD(ctx->map_addr, entry_name_list_ptr);

		// printf("ctx->map_addr = %p\n", ctx->map_addr);
		// printf("ctx->map_end = %p\n", ctx->map_end);
		// printf("entry_ordinal_list = %p\n", entry_ordinal_list);
		// printf("entry_va_list = %p\n", entry_va_list);
		// printf("entry_name_list = %p\n", entry_name_list);

		if (!pe_can_read(ctx, entry_ordinal_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		if (!pe_can_read(ctx, entry_va_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		if (!pe_can_read(ctx, entry_name_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
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
			// TODO: Should we report something?
			break;
		}

		//printf("ord=%d, va=%x, name=%s\n", entry_ordinal, entry_va, entry_name);

		// Declared as 11 bytes so that it can store the hexadecimal representation of the maximum
		// possible value of an uint32_t variable, 0xFFFFFFFF.
		sample[i].addr = (char *) malloc(11 *sizeof(char*));
		char addr[11] = { 0 };
		sprintf(addr, "%#x", entry_va);
		memcpy(sample[i].addr, addr, 11);
		//printf("%s \n", sample[i].addr);
		char fname[300] = { 0 };
		strncpy(fname, entry_name, sizeof(fname)-1);

		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		fname[sizeof(fname) - 1] = '\0';

		//output_open_scope("Function", OUTPUT_SCOPE_TYPE_OBJECT);

		// Check whether the exported function is forwarded.
		// It's forwarded if its RVA is inside the exports section.
		if (entry_va >= va && entry_va <= va + dir->Size)
		{
			// When a symbol is forwarded, its RVA points to a string containing
			// the name of the DLL and symbol to which it is forwarded.
			const uint64_t fw_entry_name_ofs = pe_rva2ofs(ctx, entry_va);
			const char *fw_entry_name = LIBPE_PTR_ADD(ctx->map_addr, fw_entry_name_ofs);

			// Validate whether it's ok to access at least 1 byte after fw_entry_name.
			// It might be '\0', for example.
			if (!pe_can_read(ctx, fw_entry_name, 1)) {
				// TODO: Should we report something?
				break;
			}

			sample[i].function_name = (char *)malloc( (sizeof(fname) * 2 + 4)*sizeof(char *));
			char fname_forwarded[sizeof(fname) * 2 + 4] = { 0 }; // Twice the size plus " -> ".
			snprintf(fname_forwarded, sizeof(fname_forwarded)-1, "%s -> %s", fname, fw_entry_name);

			memcpy(sample[i].function_name, fname_forwarded, sizeof(fname) * 2 + 4);
			printf(" fname_forwarded : %s ", sample[i].function_name);
		}
		else
		{
			sample[i].function_name = (char *)malloc(300*sizeof(char*));
			memcpy(sample[i].function_name, fname, 300);
		}

	}
	return sample;
}


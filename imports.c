#include<stdlib.h>
#include<string.h>
#include "imports.h"
#include "pe.h"

#define MAX_FUNCTION_NAME 512
#define MAX_DLL_NAME 256

int get_dll_count( pe_ctx_t *ctx) {
	/*const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
		printf("%"PRIu32 Print virtual address"\n ", dir->VirtualAddress);*/
	int count =0;
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

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			break;
		}
		count++;
		ofs = aux; // Restore previous ofs
	}
	return count;	
}

int get_functions_count( pe_ctx_t *ctx, uint64_t offset) {
	uint64_t ofs = offset;

	//char hint_str[16];
	//char fname[MAX_FUNCTION_NAME];
	int count =0;
	//memset(hint_str, 0, sizeof(hint_str));
	//memset(fname, 0, sizeof(fname));

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						return count;
					}

					// Type punning
					const uint32_t thunk_type = *(uint32_t *)thunk;
					if (thunk_type == 0) {
						return count;
					}

					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						return count;
					}

					ofs += sizeof(IMAGE_THUNK_DATA32);
					break;
				}
			case MAGIC_PE64:
				{
					const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
						return count;
					}

					const uint64_t thunk_type = *(uint64_t *)thunk;
					if (thunk_type == 0) {
						return count;
					}

					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
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

function_t get_imported_functions(pe_ctx_t *ctx, uint64_t offset, int functions_count, char *hint_str, size_t size_hint_str, char *fname, size_t size_fname)
{
	uint64_t ofs = offset;
	function_t sample;
	sample.count = functions_count;
	char **functions = malloc(functions_count*sizeof(char*)); // create an array of char pointers
	if (functions == NULL){
		sample.err = LIBPE_E_ALLOCATION_FAILURE;
		return sample;
	}

	// allocate space for each string.
	for (int i=0; i < functions_count; i++) {
		functions[i] = malloc(MAX_FUNCTION_NAME);
		if (functions[i] == NULL) {
			sample.err = LIBPE_E_ALLOCATION_FAILURE;
			return sample;
		}
	}
	bool is_ordinal = false;

	for (int i=0;i<functions_count; i++) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						sample.err = LIBPE_E_ALLOCATION_FAILURE;
						sample.functions = NULL;	
						return sample;
					}

					// Type punning
					const uint32_t thunk_type = *(uint32_t *)thunk;
					if (thunk_type == 0) {
						sample.err = LIBPE_E_TYPE_PUNNING_FAILED;
						sample.functions = NULL;
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
							sample.functions = NULL;
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
						sample.functions = NULL;
						return sample; // DO something so that API notifies of the error
					}

					// Type punning
					const uint64_t thunk_type = *(uint64_t *)thunk;
					if (thunk_type == 0) {
						sample.err = LIBPE_E_TYPE_PUNNING_FAILED;
						sample.functions = NULL;
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
							sample.functions = NULL;
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
			memcpy(functions[i], hint_str, 16);
		else
			memcpy(functions[i], fname, MAX_FUNCTION_NAME);

	}
	sample.err = LIBPE_E_OK;
	sample.functions = functions;
	return sample;
}

pe_import_t get_imports(pe_ctx_t *ctx) {
	pe_import_t imports;
	int dll_count = get_dll_count(ctx);
	// fix: "Call to 'malloc' has an allocation size of 0 bytes"
	if (dll_count == 0) {
		imports.dll_count = 0;
		imports.dllNames = NULL;
		return imports;
	}
	imports.dll_count = dll_count;
	imports.dllNames = malloc(dll_count *sizeof(char*));

	for ( int i=0; i<dll_count; i++)
		imports.dllNames[i] = malloc(MAX_DLL_NAME);

	imports.functions = malloc(dll_count * sizeof(function_t));

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL) {
		imports.dll_count = dll_count;
		imports.dllNames = NULL;
		return imports;
	}

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		imports.dll_count = dll_count;
		imports.dllNames = NULL;
		return imports;
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);

	for (int i=0; i<dll_count; i++) { 
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
		memcpy(imports.dllNames[i], dll_name, MAX_DLL_NAME);
		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			break;
		}

		char hint_str[16];
		char fname[MAX_FUNCTION_NAME];
		memset(hint_str, 0, sizeof(hint_str));
		memset(fname, 0, sizeof(fname));
		size_t size_hint_str = sizeof(hint_str);
		size_t size_fname = sizeof(fname);
		int functions_count = get_functions_count(ctx, ofs);

		imports.functions[i] = get_imported_functions(ctx, ofs, functions_count, hint_str,size_hint_str, fname, size_fname);
		if (imports.functions[i].err != LIBPE_E_OK) {
			imports.err = imports.functions[i].err;
			return imports;
		}
		ofs = aux; // Restore previous ofs
	}
	imports.err = LIBPE_E_OK;
	return imports;
}





void dealloc_imports(pe_import_t imports) {
	for (int i=0; i<imports.dll_count; i++) {	
		free(imports.dllNames[i]);
		for (int j=0; j<imports.functions[i].count; j++) {
			free(imports.functions[i].functions[j]);
		}
		free(imports.functions[i].functions);
	}
	free(imports.dllNames);
	free(imports.functions);
}

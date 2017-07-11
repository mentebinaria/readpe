#include<stdlib.h>
#include<string.h>
#include "imports.h"
#include "pe.h"

#define MAX_FUNCTION_NAME 512
#define MAX_DLL_NAME 256

function get_imported_functions(pe_ctx_t *ctx, uint64_t offset, int functions_count, char *hint_str, size_t size_hint_str, char *fname, size_t size_fname)
{
	uint64_t ofs = offset;
	function sample;
	sample.count = functions_count;
	char **functions = malloc(functions_count * sizeof(char *)); // create an array of char pointers

	// allocate space for each string.
	for (int i=0; i < functions_count; i++)
		functions[i] = (char *)malloc(MAX_FUNCTION_NAME *sizeof(char *));


	bool is_ordinal;

	for (int i=0;i<functions_count; i++) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						// TODO: Should we report something?
						printf("Line:746 - Cannot read thunk");
						sample.functions = NULL;	
						return sample; // do some thing so the API notifies about the error
					}

					// Type punning
					const uint32_t thunk_type = *(uint32_t *)thunk;
					if (thunk_type == 0) {
						printf(" Line:752 thunk_type == 0\n");
						sample.functions = NULL;
						return sample; // DO something so that API notifes about the error
					}

					is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

					if (is_ordinal) {
						snprintf(hint_str, size_hint_str-1, "%"PRIu32,
								thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
					} else {
						const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							//return NULL;
							printf("Line:766 - cannot read imp_name\n");
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
						// TODO: Should we report something?
						//return NULL;
						printf("Line: 785 -cannot read thunk");
						sample.functions = NULL;
						return sample; // DO something so that API notifies of the error
					}

					// Type punning
					const uint64_t thunk_type = *(uint64_t *)thunk;
					if (thunk_type == 0) {
						//return NULL;
						printf("Line 793: thunk_type == 0 \n"); // DO something so that API notfies of the error
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
							// TODO: Should we report something?
							//return NULL;
							printf("cannot read import by name\n");
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
	sample.functions = functions;
	return sample;
}

import get_imports(pe_ctx_t *ctx) {
	int dll_count = get_dll_count(ctx);
	//library *libraries = (library *)malloc( dll_count *sizeof(library));
	import imports;
	imports.dll_count = dll_count;
	imports.names = malloc(dll_count *sizeof(imports.names));

	for ( int i=0; i<dll_count; i++)
		imports.names[i] = (char *)malloc(MAX_DLL_NAME*sizeof(char *));

	imports.functions = (function *)malloc(dll_count * sizeof(function));

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL) {
		///EXIT_ERROR("import directory not found")
		// Do something which clearly tells when something get really bad.
		printf("Line: 849 - cannot read dir	\n");
		imports.dll_count = dll_count;
		imports.names = NULL;
		return imports;
	}

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "import directory not found\n");
		// return something which clearly tell the error
		imports.dll_count = dll_count;
		imports.names = NULL;
		return imports;
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);

	for (int i=0; i<dll_count; i++) { 
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			//Areturn;
			// or return an empty struct.
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs

		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		const char *dll_name_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, dll_name_ptr, 1)) {
			// TODO: Should we report something?
			break;
		}

		char dll_name[MAX_DLL_NAME];
		strncpy(dll_name, dll_name_ptr, sizeof(dll_name)-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll_name[sizeof(dll_name) - 1] = '\0';

		//	imports.names[i] = dll_name;
		memcpy(imports.names[i], dll_name, MAX_DLL_NAME* sizeof(char *));
		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			//            output_close_scope(); // Library
			break;
		}


		// Search for DLL imported functions
		char hint_str[16];
		char fname[MAX_FUNCTION_NAME];
		memset(hint_str, 0, sizeof(hint_str));
		memset(fname, 0, sizeof(fname));
		size_t size_hint_str = sizeof(hint_str);
		size_t size_fname = sizeof(fname);
		//char *imports =
		int functions_count = get_functions_count(ctx, ofs);
		//memcpy(imports.functions[i], get_imported_functions(ctx, ofs, functions_count, hint_str,size_hint_str, fname, size_fname), functions_count* sizeof(function));
		//imports.functions[i] = imp_functions; // DOUBT ==> allocating memory for double pointer. 

		imports.functions[i] = get_imported_functions(ctx, ofs, functions_count, hint_str,size_hint_str, fname, size_fname);


		//printf("imports :%s  \n", imports);
		ofs = aux; // Restore previous ofs
	}

	return imports;
}

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
	/*printf("from Get Functions count : %s", dllname);
		const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
		printf("%"PRIu32 Print virtual address"\n", dir->VirtualAddress);*/
	uint64_t ofs = offset;

	char hint_str[16];
	char fname[MAX_FUNCTION_NAME];
	int count =0;
	memset(hint_str, 0, sizeof(hint_str));
	memset(fname, 0, sizeof(fname));

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						// TODO: Should we report something?
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

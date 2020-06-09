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

#include "libpe/hashes.h"

#include "libpe/pe.h"
#include "libfuzzy/fuzzy.h"
#include "libpe/ordlookup.h"
#include "libpe/utlist.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

/* By liw. */
static char *last_strstr(char *haystack, const char *needle) {
	if (needle == NULL || *needle == '\0')
		return haystack;

	char *result = NULL;
	for (;;) {
		char *p = strstr(haystack, needle);
		if (p == NULL)
			break;
		result = p;
		haystack = p + 1;
	}

	return result;
}

static pe_err_e get_hashes(pe_hash_t *output, const char *name, const unsigned char *data, size_t data_size) {
	pe_err_e ret = LIBPE_E_OK;

	const size_t hash_maxsize = pe_hash_recommended_size();
	char *hash_value = malloc(hash_maxsize);
	if (hash_value == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}
	memset(hash_value, 0, hash_maxsize);

	output->name = strdup(name);
	if (output->name == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}

	bool hash_ok;

	hash_ok = pe_hash_raw_data(hash_value, hash_maxsize, "md5", data, data_size);
	if (!hash_ok) {
		ret = LIBPE_E_HASHING_FAILED;
		goto error;
	}
	output->md5 = strdup(hash_value);
	if (output->md5 == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}

	hash_ok = pe_hash_raw_data(hash_value, hash_maxsize, "sha1", data, data_size);
	if (!hash_ok) {
		ret = LIBPE_E_HASHING_FAILED;
		goto error;
	}
	output->sha1 = strdup(hash_value);
	if (output->sha1 == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}

	hash_ok = pe_hash_raw_data(hash_value, hash_maxsize, "sha256", data, data_size);
	if (!hash_ok) {
		ret = LIBPE_E_HASHING_FAILED;
		goto error;
	}
	output->sha256 = strdup(hash_value);
	if (output->sha256 == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}

	hash_ok = pe_hash_raw_data(hash_value, hash_maxsize, "ssdeep", data, data_size);
	if (!hash_ok) {
		ret = LIBPE_E_HASHING_FAILED;
		goto error;
	}
	output->ssdeep = strdup(hash_value);
	if (output->ssdeep == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}

error:
	free(hash_value);
	return ret;
}

static pe_err_e get_headers_dos_hash(pe_ctx_t *ctx, pe_hash_t *output) {
	const IMAGE_DOS_HEADER *sample = pe_dos(ctx);
	const unsigned char *data = (const unsigned char *)sample;
	const uint64_t data_size = sizeof(IMAGE_DOS_HEADER);
	return get_hashes(output, "IMAGE_DOS_HEADER", data, data_size);
}

static pe_err_e get_headers_coff_hash(pe_ctx_t *ctx, pe_hash_t *output) {
	const IMAGE_COFF_HEADER *sample = pe_coff(ctx);
	const unsigned char *data = (const unsigned char *)sample;
	const uint64_t data_size = sizeof(IMAGE_COFF_HEADER);
	return get_hashes(output, "IMAGE_COFF_HEADER", data, data_size);
}

static pe_err_e get_headers_optional_hash(pe_ctx_t *ctx, pe_hash_t *output) {
	const IMAGE_OPTIONAL_HEADER *sample = pe_optional(ctx);

	switch (sample->type) {
		default:
			// TODO(jweyrich): handle unknown type.
			exit(1);
		case MAGIC_PE32:
		{
			const unsigned char *data = (const unsigned char *)sample->_32;
			const uint64_t data_size = sizeof(IMAGE_OPTIONAL_HEADER_32);
			return get_hashes(output, "IMAGE_OPTIONAL_HEADER_32", data, data_size);
		}
		case MAGIC_PE64:
		{
			const unsigned char *data = (const unsigned char *)sample->_64;
			const uint64_t data_size = sizeof(IMAGE_OPTIONAL_HEADER_64);
			return get_hashes(output, "IMAGE_OPTIONAL_HEADER_64", data, data_size);
		}
	}
}

static const size_t g_openssl_hash_maxsize = EVP_MAX_MD_SIZE * 2 + 1;
static const size_t g_ssdeep_hash_maxsize = FUZZY_MAX_RESULT;

size_t pe_hash_recommended_size(void) {
	// Since standard C lacks max(), we do it manually.
	const size_t result = g_openssl_hash_maxsize > g_ssdeep_hash_maxsize
		? g_openssl_hash_maxsize
		: g_ssdeep_hash_maxsize;

	return result;
}

bool pe_hash_raw_data(char *output, size_t output_size, const char *alg_name, const unsigned char *data, size_t data_size) {
	if (strcmp("ssdeep", alg_name) == 0) {
		if (output_size < g_ssdeep_hash_maxsize) {
			// Not enough space.
			return false;
		}

		fuzzy_hash_buf(data, data_size, output);
		return true;
	}

	if (output_size < g_openssl_hash_maxsize) {
		// Not enough space.
		return false;
	}

	const EVP_MD *md = EVP_get_digestbyname(alg_name);
	if (md == NULL) {
		// Unsupported hash algorithm.
		return false;
	}

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

// See https://wiki.openssl.org/index.php/1.1_API_Changes
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX md_ctx_auto;
	EVP_MD_CTX *md_ctx = &md_ctx_auto;
#else
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
#endif

	// FIXME: Handle errors - Check return values.
	EVP_MD_CTX_init(md_ctx);
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, data, data_size);
	EVP_DigestFinal_ex(md_ctx, md_value, &md_len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_cleanup(md_ctx);
#else
	EVP_MD_CTX_free(md_ctx);
#endif

	int result = true;
	for (unsigned int i=0; i < md_len; i++) {
		int err = sprintf(&output[i * 2], "%02x", md_value[i]);
		if (err < 0) {
			result = false;
			break;
		}
	}

	return result;
}

pe_hash_headers_t *pe_get_headers_hashes(pe_ctx_t *ctx) {
	if (ctx->cached_data.hash_headers != NULL)
		return ctx->cached_data.hash_headers;

	pe_hash_headers_t *result = ctx->cached_data.hash_headers = malloc(sizeof(pe_hash_headers_t));
	if (result == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}
	memset(result, 0, sizeof(pe_hash_headers_t));

	result->err = LIBPE_E_OK;

	pe_err_e status = LIBPE_E_OK;

	result->dos = malloc(sizeof(pe_hash_t));
	if (result->dos == NULL) {
		result->err = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}
	status = get_headers_dos_hash(ctx, result->dos);
	if (status != LIBPE_E_OK) {
		result->err = status;
		goto error;
	}

	result->optional = malloc(sizeof(pe_hash_t));
	if (result->optional == NULL) {
		result->err = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}
	status = get_headers_optional_hash(ctx, result->optional);
	if (status != LIBPE_E_OK) {
		result->err = status;
		goto error;
	}

	result->coff = malloc(sizeof(pe_hash_t));
	if (result->coff == NULL) {
		status = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}
	status = get_headers_coff_hash(ctx, result->coff);
	if (status != LIBPE_E_OK) {
		result->err = status;
		goto error;
	}

error:
	return result;
}

pe_hash_sections_t *pe_get_sections_hash(pe_ctx_t *ctx) {
	if (ctx->cached_data.hash_sections != NULL)
		return ctx->cached_data.hash_sections;

	pe_hash_sections_t *result = ctx->cached_data.hash_sections = malloc(sizeof(pe_hash_sections_t));
	if (result == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}
	memset(result, 0, sizeof(pe_hash_sections_t));
	
	result->err = LIBPE_E_OK;

	const size_t num_sections = pe_sections_count(ctx);
	
	// Allocate an array of pointers once so we can store each pe_hash_t pointer in the
	// respective result->sections[i].
	const size_t sections_size = num_sections * sizeof(pe_hash_t *);
	result->sections = malloc(sections_size);
	if (result->sections == NULL) {
		result->err = LIBPE_E_ALLOCATION_FAILURE;
		return result;
	}
	memset(result->sections, 0, sections_size);

	IMAGE_SECTION_HEADER ** const sections = pe_sections(ctx);

	for (size_t i=0; i < num_sections; i++) {
		uint64_t data_size = sections[i]->SizeOfRawData;
		const unsigned char *data = LIBPE_PTR_ADD(ctx->map_addr, sections[i]->PointerToRawData);

		if (!pe_can_read(ctx, data, data_size)) {
			//fprintf(stderr, "%s\n", "unable to read sections data");
			continue;
		}

		if (data_size) {
			char *name = (char *)sections[i]->Name;

			pe_hash_t *section_hash = malloc(sizeof(pe_hash_t));
			if (section_hash == NULL) {
				result->err = LIBPE_E_ALLOCATION_FAILURE;
				break;
			}
			memset(section_hash, 0, sizeof(pe_hash_t));

			pe_err_e status = get_hashes(section_hash, name, data, data_size);
			if (status != LIBPE_E_OK) {
				// TODO: Should we skip this section and continue the loop?
				result->err = status;
				break;
			}

			result->sections[result->count] = section_hash;
			result->count++;
		}
	}

	return result;
}

pe_hash_t *pe_get_file_hash(pe_ctx_t *ctx) {
	if (ctx->cached_data.hash_file != NULL)
		return ctx->cached_data.hash_file;

	pe_hash_t *hash = ctx->cached_data.hash_file = malloc(sizeof(pe_hash_t));
	if (hash == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}
	memset(hash, 0, sizeof(pe_hash_t));

	const uint64_t data_size = pe_filesize(ctx);
	pe_err_e status = get_hashes(hash, "PEfile hash", ctx->map_addr, data_size);
	if (status != LIBPE_E_OK)
		abort();
	return hash;
} 

typedef struct element {
	char *dll_name;
	char *function_name;
	//struct element *prev; // needed for a doubly-linked list only
	struct element *next; // needed for singly- or doubly-linked lists
} element_t;

static void imphash_load_imported_functions(pe_ctx_t *ctx, uint64_t offset, char *dll_name, element_t **head, pe_imphash_flavor_e flavor) {
	if (dll_name == NULL || dll_name[0] == '\0')
		return;

	uint64_t ofs = offset;

	char hint_str[32];
	char fname[MAX_FUNCTION_NAME];
	bool is_ordinal = false;

	memset(hint_str, 0, sizeof(hint_str));
	memset(fname, 0, sizeof(fname));

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						// TODO: Should we report something?
						return;
					}

					// Type punning
					const uint32_t thunk_type = *(uint32_t *)thunk;
					if (thunk_type == 0)
						return;

					is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

					if (is_ordinal) {
						snprintf(hint_str, sizeof(hint_str)-1, "%"PRIu32,
								thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
					} else {
						const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							return;
						}

						snprintf(hint_str, sizeof(hint_str)-1, "%d", imp_name->Hint);
						strncpy(fname, (char *)imp_name->Name, sizeof(fname)-1);
						// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
						fname[sizeof(fname) - 1] = '\0';
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
						return;
					}

					// Type punning
					const uint64_t thunk_type = *(uint64_t *)thunk;
					if (thunk_type == 0)
						return;

					is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG64) != 0;

					if (is_ordinal) {
						snprintf(hint_str, sizeof(hint_str)-1, "%llu",
								thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64);
					} else {
						uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							return;
						}

						snprintf(hint_str, sizeof(hint_str)-1, "%d", imp_name->Hint);
						strncpy(fname, (char *)imp_name->Name, sizeof(fname)-1);
						// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
						fname[sizeof(fname) - 1] = '\0';
						//size_t fname_len = strlen(fname);
					}
					ofs += sizeof(IMAGE_THUNK_DATA64);
					break;
				}
		}

		// Beginning of imphash logic - that's the weirdest thing I've even seen...

		const size_t dll_name_len = strlen(dll_name);
		for (unsigned i=0; i < dll_name_len; i++)
			dll_name[i] = tolower(dll_name[i]);

		char *aux = NULL;

		//TODO use a reverse search function instead

		switch (flavor) {
			default: abort();
			case LIBPE_IMPHASH_FLAVOR_MANDIANT:
			{
				aux = last_strstr(dll_name, ".");
				break;
			}
			case LIBPE_IMPHASH_FLAVOR_PEFILE:
			{
				aux = last_strstr(dll_name, ".dll");
				if (aux)
					*aux = '\0';

				aux = last_strstr(dll_name, ".ocx");
				if (aux)
					*aux = '\0';

				aux = last_strstr(dll_name, ".sys");
				if (aux)
					*aux = '\0';
				break;
			}
		}

		if (aux)
			*aux = '\0';

		const size_t fname_len = strlen(fname);
		for (size_t i=0; i < fname_len; i++)
			fname[i] = tolower(fname[i]);

		element_t *el = malloc(sizeof(element_t));
		if (el == NULL) {
			// TODO: Handle allocation failure.
			abort();
		}
		memset(el, 0, sizeof(element_t));

		el->dll_name = strdup(dll_name);

		switch (flavor) {
			default: abort();
			case LIBPE_IMPHASH_FLAVOR_MANDIANT:
			{
				el->function_name = strdup(is_ordinal ? hint_str : fname);
				break;
			}
			case LIBPE_IMPHASH_FLAVOR_PEFILE:
			{
				int hint = strtoul(hint_str, NULL, 10);

				if (strncmp(dll_name, "oleaut32", 8) == 0 && is_ordinal) {
					for (size_t i=0; i < sizeof(oleaut32_arr) / sizeof(ord_t); i++)
						if (hint == oleaut32_arr[i].number)
							el->function_name = strdup(oleaut32_arr[i].fname);
				} else if (strncmp(dll_name, "ws2_32", 6) == 0 && is_ordinal) {
					for (size_t i=0; i < sizeof(ws2_32_arr) / sizeof(ord_t); i++)
						if (hint == ws2_32_arr[i].number)
							el->function_name = strdup(ws2_32_arr[i].fname);
				} else {
					char ord[MAX_FUNCTION_NAME];
					memset(ord, 0, MAX_FUNCTION_NAME);

					if (is_ordinal) {
						snprintf(ord, MAX_FUNCTION_NAME, "ord%s", hint_str);
						el->function_name = strdup(ord);
					} else {
						el->function_name = strdup(fname);
					}
				}

				break;
			}
		}

		const size_t function_name_len = strlen(el->function_name);
		for (size_t i=0; i < function_name_len; i++)
			el->function_name[i] = tolower(el->function_name[i]);

		LL_APPEND(*head, el);
	}
}

static void freeNodes(element_t *currentNode) {
	if (currentNode == NULL)
		return;

	element_t *temp;
	while(currentNode != NULL) {
		temp = currentNode;
		currentNode = currentNode->next;
		free(temp->function_name);
		free(temp->dll_name);
		free(temp);
	}
}

char *pe_imphash(pe_ctx_t *ctx, pe_imphash_flavor_e flavor) {
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		return NULL;

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		//fprintf(stderr, "import directory not found\n");
		return NULL;
	}

	uint64_t ofs = pe_rva2ofs(ctx, va);
	
	element_t *elt, *tmp, *head = NULL;
	int count = 0;

	while (1) {
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			return NULL;
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs

		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0 || ofs > (uint64_t) ctx->map_size)
			return NULL;

		const char *dll_name_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, dll_name_ptr, 1)) {
			// TODO: Should we report something?
			break;
		}

		char dll_name[MAX_DLL_NAME];
		strncpy(dll_name, dll_name_ptr, sizeof(dll_name)-1);
		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll_name[sizeof(dll_name) - 1] = '\0';

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			break;
		}

		imphash_load_imported_functions(ctx, ofs, dll_name, &head, flavor);
		ofs = aux; // Restore previous ofs
	}

	LL_COUNT(head, elt, count);

	// Allocate enough memory to store N times "dll_name.func_name,", plus 1 byte for the NUL terminator.
	const size_t imphash_string_size = count * (MAX_DLL_NAME + MAX_FUNCTION_NAME + 2) + 1;
	char *imphash_string = malloc(imphash_string_size);
	if (imphash_string == NULL) {
		// TODO: Handle allocation failure.
		abort();
	}
	memset(imphash_string, 0, imphash_string_size);

	LL_FOREACH_SAFE(head, elt, tmp) {
		sprintf(imphash_string + strlen(imphash_string), "%s.%s,", elt->dll_name, elt->function_name);
		LL_DELETE(head, elt);
	}

	assert(!elt);
	freeNodes(head);

	size_t imphash_string_len = strlen(imphash_string);
	if (imphash_string_len == 0) {
		free(imphash_string);
		//ret = LIBPE_E_ALLOCATION_FAILURE;
		return NULL;
	}

	// Remove the last comma sign and decrement the string length by 1.
	imphash_string[imphash_string_len-1] = '\0';
	imphash_string_len--;

	const unsigned char *data = (const unsigned char *)imphash_string;
	const size_t data_size = imphash_string_len;

	const size_t hash_maxsize = pe_hash_recommended_size();
	char *hash_value = malloc(hash_maxsize);
	if (hash_value == NULL) {
		free(imphash_string);
		//ret = LIBPE_E_ALLOCATION_FAILURE;
		return NULL;
	}
	memset(hash_value, 0, hash_maxsize);

	const bool hash_ok = pe_hash_raw_data(hash_value, hash_maxsize, "md5", data, data_size);

	free(imphash_string);

	//printf("### DEBUG imphash_string [%zu] = %s\n", imphash_string_len, imphash_string);
	return hash_ok ? hash_value : NULL;
}

void pe_hash_headers_dealloc(pe_hash_headers_t *obj) {
	if (obj == NULL)
		return;

	pe_hash_dealloc(obj->dos);
	pe_hash_dealloc(obj->coff);
	pe_hash_dealloc(obj->optional);
	free(obj);
}

void pe_hash_sections_dealloc(pe_hash_sections_t *obj) {
	if (obj == NULL)
		return;

	for (uint32_t i=0; i < obj->count; i++) {
		pe_hash_dealloc(obj->sections[i]);
	}

	free(obj->sections);
	free(obj);
}

void pe_hash_dealloc(pe_hash_t *obj) {
	if (obj == NULL)
		return;

	free(obj->name);
	free(obj->md5);
	free(obj->sha1);
	free(obj->sha256);
	free(obj->ssdeep);
	free(obj);
}

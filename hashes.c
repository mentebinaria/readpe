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
#include <errno.h>

// add utility
#define PEV_ABORT_IF(cond) \
	do { (cond) ? abort() : (void)0; } while (0)

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
	char *hash_value = calloc(1, hash_maxsize);
	if (hash_value == NULL) {
		ret = LIBPE_E_ALLOCATION_FAILURE;
		goto error;
	}

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

// FIX: Don't need to allocate space for these constants!
#define G_OPENSSL_HASH_MAXSIZE (EVP_MAX_MD_SIZE * 2 + 1)
#define G_SSDEEP_HASH_MAXSIZE (FUZZY_MAX_RESULT)

size_t pe_hash_recommended_size(void) {
	// Since standard C lacks max(), we do it manually.
	const size_t result = G_OPENSSL_HASH_MAXSIZE > G_SSDEEP_HASH_MAXSIZE
		? G_OPENSSL_HASH_MAXSIZE
		: G_SSDEEP_HASH_MAXSIZE;

	return result;
}

// add function to tranforms set of bytes in hex equivalente into output string
static void to_hex_str(const uint8_t* input, char* output, size_t n)
{
	for (const uint8_t* input_ptr = input; n; --n, ++input_ptr)
	{
		unsigned b = (*input_ptr);
		*output++ = "0123456789abcdef"[b >> 4];
		*output++ = "0123456789abcdef"[b & 0xf];
	}
}

bool pe_hash_raw_data(char *output, size_t output_size, const char *alg_name, const unsigned char *data, size_t data_size) {
	if (strcmp("ssdeep", alg_name) == 0) {
		if (output_size < G_SSDEEP_HASH_MAXSIZE) {
			// Not enough space.
			return false;
		}

		fuzzy_hash_buf(data, data_size, output);
		return true;
	}

	if (output_size < G_OPENSSL_HASH_MAXSIZE) {
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

	// FIX: Better than going through all the input calculating the byte2hex of each byte.
	to_hex_str(md_value, output, md_len);
	return true;
}

pe_hash_headers_t *pe_get_headers_hashes(pe_ctx_t *ctx) {
	if (ctx->cached_data.hash_headers != NULL)
		return ctx->cached_data.hash_headers;

	pe_hash_headers_t *result = ctx->cached_data.hash_headers = calloc(1, sizeof(pe_hash_headers_t));
	if (result == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}

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
		result->err = status;
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

	pe_hash_sections_t *result = ctx->cached_data.hash_sections = calloc(1, sizeof(pe_hash_sections_t));
	if (result == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}
	
	result->err = LIBPE_E_OK;

	const size_t num_sections = pe_sections_count(ctx);
	
	// Allocate an array of pointers once so we can store each pe_hash_t pointer in the
	// respective result->sections[i].
	result->sections = calloc(num_sections, sizeof(pe_hash_t *));
	if (result->sections == NULL) {
		result->err = LIBPE_E_ALLOCATION_FAILURE;
		return result;
	}

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

			pe_hash_t *section_hash = calloc(1, sizeof(pe_hash_t));
			if (section_hash == NULL) {
				result->err = LIBPE_E_ALLOCATION_FAILURE;
				break;
			}

			pe_err_e status = get_hashes(section_hash, name, data, data_size);
			if (status != LIBPE_E_OK) {
				// TODO: Should we skip this section and continue the loop?
				result->err = status;
				free(section_hash);
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

	pe_hash_t *hash = ctx->cached_data.hash_file = calloc(1, sizeof(pe_hash_t));
	if (hash == NULL) {
		// TODO(jweyrich): Should we report an error? If yes, we need a redesign.
		return NULL;
	}

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

// strlwr - string lowercase
static void pe_transform_to_lowercase_str(char* str)
{
	if (str == NULL)
		// TODO: Should we warn here?
		return;

	for (char* p = str; *p; ++p)
		*p = tolower((unsigned char)*p);
}

static void pe_get_all_ord_lkp_func_name_with_hint(element_t* elem_ptr, ord_t* ord_ptr, int hint)
{
	for (ord_t* p = ord_ptr; p->number; ++p)
	{
		if (hint == p->number)
		{
			errno = 0;
			elem_ptr->function_name = strdup(p->fname);
			PEV_ABORT_IF(!elem_ptr->function_name || errno == ENOMEM);
			break;
		}
	}
}

static void imphash_load_imported_functions(pe_ctx_t *ctx, uint64_t offset, char *dll_name, element_t **head, pe_imphash_flavor_e flavor) {
	if (dll_name == NULL || dll_name[0] == '\0')
		return;

	uint64_t ofs = offset;

	char* hint_str = NULL;
	char* fname = NULL;

	bool is_ordinal = false;
	int errcode = 0; // for asprintf return code

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
						errcode = asprintf(&hint_str, "%"PRIu32, 
										   thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
						
						// FIX-ME: devemos abortar a execucao?
						PEV_ABORT_IF(errcode == -1);
						
					} else {
						const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							return;
						}

						errcode = asprintf(&hint_str, "%"PRIu16, imp_name->Hint);
						PEV_ABORT_IF(errcode == -1);

						errno = 0;

						// if the character '\0' comes before MAX_FUNCTION_NAME - 1
						// we duplicate the string and put it in fname
						// if you can't find '\ 0' copy up to the maximum
						// MAX_FUNCTION_NAME - 1 characters
						fname = strndup((char*)imp_name->Name, MAX_FUNCTION_NAME - 1);
						PEV_ABORT_IF(!fname || errno == ENOMEM);
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
						errcode = asprintf(&hint_str, "%"PRIu64,
										   (uint64_t)(thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64));
						
						PEV_ABORT_IF(errcode == -1);

					} else {
						uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							return;
						}

						errcode = asprintf(&hint_str, "%"PRIu16, imp_name->Hint);
						PEV_ABORT_IF(errcode == -1);


						errno = 0;
						fname = strndup((char*)imp_name->Name, MAX_FUNCTION_NAME - 1);
						PEV_ABORT_IF(!fname || errno == ENOMEM);
					}
					ofs += sizeof(IMAGE_THUNK_DATA64);
					break;
				}
			default:
				return;
		}

		// Beginning of imphash logic - that's the weirdest thing I've even seen...
		pe_transform_to_lowercase_str(dll_name);
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

		pe_transform_to_lowercase_str(fname);

		element_t *el = calloc(1, sizeof(element_t));
		if (el == NULL) {
			// TODO: Handle allocation failure.
			abort();
		}

		errno = 0;
		el->dll_name = strdup(dll_name);

		// add verification of allocation error
		PEV_ABORT_IF(!el->dll_name || errno == ENOMEM);

		switch (flavor) {
			default: abort();
			case LIBPE_IMPHASH_FLAVOR_MANDIANT:
			{
				el->function_name = is_ordinal ? hint_str : fname;
				break;
			}
			case LIBPE_IMPHASH_FLAVOR_PEFILE:
			{
				errno = 0;

				char* rest = NULL;
				int hint = (int) strtol(hint_str, &rest, 10);

				// should we treat the error or abort?
				PEV_ABORT_IF(hint_str == rest || errno == ERANGE);

				if (strncmp(dll_name, "oleaut32", 8) == 0 && is_ordinal) {
					pe_get_all_ord_lkp_func_name_with_hint(el, oleaut32_arr, hint);
				} else if (strncmp(dll_name, "ws2_32", 6) == 0 && is_ordinal) {
					pe_get_all_ord_lkp_func_name_with_hint(el, ws2_32_arr, hint);
				} 
				else 
				{
					if (is_ordinal) {
						char* ord_str = NULL;

						errcode = asprintf(&ord_str, "ord%s", hint_str);
						PEV_ABORT_IF(errcode == -1);

						el->function_name = ord_str;
					} else {
						el->function_name = fname;
					}
				}

				break;
			}
		}

		pe_transform_to_lowercase_str(el->function_name);
		LL_APPEND(*head, el);
	}
}

static void freeNodes(element_t *currentNode) {
	if (currentNode == NULL)
		return;

	while(currentNode != NULL) {
		element_t *temp = currentNode;
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

		char* dll_name = NULL;
		errno = 0;

		// if the character '\0' comes before MAX_DLL_NAME - 1
		// we duplicate the string and put it in fname
		// if you can't find '\ 0' copy up to the maximum
		// MAX_DLL_NAME - 1 characters
		dll_name = strndup(dll_name_ptr, MAX_DLL_NAME - 1);
		PEV_ABORT_IF(!dll_name || errno == ENOMEM);

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			free(dll_name);
			break;
		}

		imphash_load_imported_functions(ctx, ofs, dll_name, &head, flavor);

		// release dll_name from memory
		free(dll_name);

		// Restore previous ofs
		ofs = aux; 
	}

	LL_COUNT(head, elt, count);

	// Allocate enough memory to store N times "dll_name.func_name,", plus 1 byte for the NUL terminator.
	const size_t imphash_string_size = count * (MAX_DLL_NAME + MAX_FUNCTION_NAME + 2) + 1;
	char *imphash_string = calloc(1, imphash_string_size);

	if (imphash_string == NULL) {
		// TODO: Handle allocation failure.
		abort();
	}

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
	char *hash_value = calloc(1, hash_maxsize);
	if (hash_value == NULL) {
		free(imphash_string);
		//ret = LIBPE_E_ALLOCATION_FAILURE;
		return NULL;
	}

	const bool hash_ok = pe_hash_raw_data(hash_value, hash_maxsize, "md5", data, data_size);

	free(imphash_string);

	//printf("### DEBUG imphash_string [%zu] = %s\n", imphash_string_len, imphash_string);

	if (!hash_ok) {
		free(hash_value);
		return NULL;
	}

	return hash_value;
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

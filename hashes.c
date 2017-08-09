#include "hashes.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include "fuzzy.h"
#include "ordlookup.h"
#include "utlist.h"

#define IMPHASH_FLAVOR_MANDIANT 1
#define IMPHASH_FLAVOR_PEFILE 2

// Used for Imphash calulation 
static char *last_strstr(char *haystack, const char *needle)
{
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

char *calc_hash(const char *alg_name, const unsigned char *data, size_t size, char *output)
{
	OpenSSL_add_all_digests();
	if (strcmp("ssdeep", alg_name) == 0) {
		fuzzy_hash_buf(data, size, output);
		return output;
	}
	const EVP_MD *md = EVP_get_digestbyname(alg_name);
	//assert(md != NULL); // We already checked this in parse_hash_algorithm()
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
	EVP_DigestUpdate(md_ctx, data, size);
	EVP_DigestFinal_ex(md_ctx, md_value, &md_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_cleanup(md_ctx);  // removing this to fix :"Error: free(): invalid next size (fast):" this is happening only with imphash
#else
	//EVP_MD_CTX_free(md_ctx); // same here
#endif
	int err;
	for (unsigned int i=0; i < md_len; i++) {
		err = sprintf(&output[i * 2], "%02x", md_value[i]);
		if(err<0){
			output = NULL;
			break;
		}
	}
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();

	return output;
}

pe_hash_t get_hashes(const char *name,const unsigned char *data, size_t data_size) {
	pe_hash_t sample;

	const size_t openssl_hash_maxsize = EVP_MAX_MD_SIZE * 2 + 1;
	const size_t ssdeep_hash_maxsize = FUZZY_MAX_RESULT;
	// Since standard C lacks max(), we do it manually.
	const size_t hash_maxsize = openssl_hash_maxsize > ssdeep_hash_maxsize
		? openssl_hash_maxsize
		: ssdeep_hash_maxsize;
	char *hash_value = malloc(hash_maxsize);
	if (hash_value == NULL) {
		sample.err = LIBPE_E_ALLOCATION_FAILURE;
		return sample;
	}

	sample.name = strdup(name);
	sample.md5 = malloc(hash_maxsize); 
	sample.sha1 = malloc(hash_maxsize);
	sample.sha256 = malloc(hash_maxsize);
	sample.ssdeep = malloc(hash_maxsize);
	// Currently we can show only one error. But what if there is a problem in both md5 and sha1?
	char *md5 = calc_hash("md5", data, data_size, hash_value);
	if (md5 == NULL){
		sample.err = LIBPE_E_HASHES_MD5;
		sample.md5 = NULL;
		return sample;
	} 
	else {
		memcpy(sample.md5,md5 , hash_maxsize); // TODO: what if something ??!!
	}

	char *sha1 = calc_hash("sha1", data, data_size, hash_value);
	if (sha1 == NULL){
		sample.err = LIBPE_E_HASHES_SHA1;
		sample.sha1 = NULL;
		return sample;
	}
	else {
		memcpy(sample.sha1,sha1 , hash_maxsize);
	}

	char *sha256 = calc_hash("sha256", data, data_size, hash_value);
	if (sha256 == NULL) {
		sample.err = LIBPE_E_HASHES_SHA256;
		sample.sha256 = NULL;
		return sample;
	}
	else {
		memcpy(sample.sha256,sha256, hash_maxsize);
	}

	char *ssdeep = calc_hash("ssdeep", data, data_size, hash_value);
	if (ssdeep == NULL) {
		sample.err = LIBPE_E_HASHES_SSDEEP;
		sample.ssdeep = NULL;
		return sample;
	}
	else {
		memcpy(sample.ssdeep,ssdeep, hash_maxsize);
	}

	free(hash_value);
	sample.err = LIBPE_E_OK;
	return sample;
}

pe_hash_t get_headers_dos_hash(pe_ctx_t *ctx) {
	pe_hash_t dos;
	const IMAGE_DOS_HEADER *dos_sample = pe_dos(ctx);
	const unsigned char *data = (const unsigned char *)dos_sample;
	uint64_t data_size = sizeof(IMAGE_DOS_HEADER);
	dos = get_hashes("IMAGE_DOS_HEADER", data, data_size);	// TODO: what if something goes wrong?
	return dos;
}

pe_hash_t get_headers_coff_hash(pe_ctx_t *ctx) {
	pe_hash_t coff;
	const IMAGE_COFF_HEADER *coff_sample = pe_coff(ctx);
	const unsigned char *data = (const unsigned char *)coff_sample;
	uint64_t data_size = sizeof(IMAGE_COFF_HEADER);
	coff = get_hashes("IMAGE_COFF_HEADER", data, data_size);	// TODO: what if something goes wrong!!??
	return coff;
}

pe_hash_t get_headers_optional_hash(pe_ctx_t *ctx) {
	pe_hash_t optional; const IMAGE_OPTIONAL_HEADER *optional_sample = pe_optional(ctx);
	const unsigned char *data;
	uint64_t data_size;
	switch(optional_sample->type) {
		default:
			// TODO(jweyrich): handle unknown type.
			exit(1);
		case MAGIC_PE32:
			data = (const unsigned char *)optional_sample->_32;
			data_size = sizeof(IMAGE_OPTIONAL_HEADER_32);
			optional = get_hashes("IMAGE_OPTIONAL_HEADER_32", data, data_size);
			return optional;

		case MAGIC_PE64:
			data = (const unsigned char *)optional_sample->_64;
			data_size = sizeof(IMAGE_OPTIONAL_HEADER_64);	
			optional = get_hashes("IMAGE_OPTIONAL_HEADER_64", data, data_size);
			return optional;
	}
}

pe_hdr_t get_headers_hash(pe_ctx_t *ctx) {

	pe_hash_t dos = get_headers_dos_hash(ctx); // TODO:what if something goes wrong??
	pe_hash_t optional = get_headers_optional_hash(ctx);
	pe_hash_t coff = get_headers_coff_hash(ctx);

	pe_hdr_t sample_hdr;
	sample_hdr.err = dos.err;

	if (dos.err == LIBPE_E_OK) {
		sample_hdr.dos = dos;
	}
	else {
		sample_hdr.err = dos.err;
		return sample_hdr;
	}

	if (optional.err == LIBPE_E_OK) {
		sample_hdr.optional = optional;
	}
	else {
		sample_hdr.err = optional.err;
		return sample_hdr;
	}

	if (coff.err == LIBPE_E_OK) {
		sample_hdr.coff = coff;
	}
	else {
		sample_hdr.err = coff.err;
		return sample_hdr;
	}

	return sample_hdr; 
}

pe_hash_section_t get_sections_hash(pe_ctx_t *ctx) {
	pe_hash_section_t final_sample;
	int c = pe_sections_count(ctx); // Total number of sections
	pe_hash_t *sample = (pe_hash_t *)malloc(c *sizeof(pe_hash_t));  //local hash sample which will later be assigned to finalsample.sections
	const unsigned char *data = NULL;
	uint64_t data_size = 0;
	char *name; // to savename of section
	IMAGE_SECTION_HEADER ** const sections = pe_sections(ctx);
	int count = 0; // to count number of sections which has hashes
	for (int i=0; i<c; i++) {
		data_size = sections[i]->SizeOfRawData;
		data = LIBPE_PTR_ADD(ctx->map_addr, sections[i]->PointerToRawData);

		if (!pe_can_read(ctx, data, data_size)) {
			//EXIT_ERROR("Unable to read section data");
			//fprintf(stderr, "%s\n", "unable to read sections data");
			final_sample.count = 0;
			final_sample.sections = NULL;
			return final_sample;
		}
		if (data_size) {
			name = (char *)sections[i]->Name;
			pe_hash_t sec_hash = get_hashes(name, data, data_size);
			if (sec_hash.err != LIBPE_E_OK) {
				final_sample.err = sec_hash.err;
				return final_sample;
			}
			else {
				sample[count] = sec_hash;
				count++;
			}
		}
	}

	final_sample.err = LIBPE_E_OK;
	final_sample.count = count;
	final_sample.sections = sample;
	return final_sample;
}

pe_hash_t get_file_hash(pe_ctx_t *ctx) {
	const unsigned char *data = ctx->map_addr;
	uint64_t data_size = pe_filesize(ctx);
	pe_hash_t sample;
	const char *name = "PEfile hash";
	sample = get_hashes(name, data, data_size);
	return sample;
} 

typedef struct element {
	char *dll_name;
	char *function_name;
	//struct element *prev; /* needed for a doubly-linked list only */
	struct element *next; /* needed for singly- or doubly-linked lists */
} element;

static void imphash_load_imported_functions(pe_ctx_t *ctx, uint64_t offset, char *dll_name, struct element **head, int flavor)
{
	uint64_t ofs = offset;

	char hint_str[16];
	char fname[MAX_FUNCTION_NAME];
	bool is_ordinal = false; // Initalize variable

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

		if (!dll_name)
			continue;

		// Beginning of imphash logic - that's the weirdest thing I've even seen...

		for (unsigned i=0; i < strlen(dll_name); i++)
			dll_name[i] = tolower(dll_name[i]);

		char *aux = NULL;

		//TODO use a reverse search function instead

		if (flavor == IMPHASH_FLAVOR_MANDIANT)
			aux = last_strstr(dll_name, ".");
		else if (flavor == IMPHASH_FLAVOR_PEFILE) {
			aux = last_strstr(dll_name, ".dll");
			if (aux)
				*aux = '\0';

			aux = last_strstr(dll_name, ".ocx");
			if (aux)
				*aux = '\0';

			aux = last_strstr(dll_name, ".sys");
			if (aux)
				*aux = '\0';
		}

		if (aux)
			*aux = '\0';

		for (unsigned i=0; i < strlen(fname); i++)
			fname[i] = tolower(fname[i]);

		struct element *el = malloc(sizeof(struct element));
		if (el == NULL) {
			// TODO: Handle allocation failure.
			abort();
		}

		el->dll_name = strdup(dll_name);

		if (flavor == IMPHASH_FLAVOR_MANDIANT) {
			el->function_name = strdup(is_ordinal ? hint_str : fname);
		}
		else if (flavor == IMPHASH_FLAVOR_PEFILE) { 

			int hint = strtoul(hint_str, NULL, 10);

			if ( strncmp(dll_name, "oleaut32", 8) == 0 && is_ordinal) {
				for (unsigned i=0; i < sizeof(oleaut32_arr) / sizeof(ord_t); i++)
					if (hint == oleaut32_arr[i].number)
						el->function_name = strdup(oleaut32_arr[i].fname);
			}
			else if ( strncmp(dll_name, "ws2_32", 6) == 0 && is_ordinal) {
				for (unsigned i=0; i < sizeof(ws2_32_arr) / sizeof(ord_t); i++)
					if (hint == ws2_32_arr[i].number)
						el->function_name = strdup(ws2_32_arr[i].fname);
			}
			else {
				char ord[MAX_FUNCTION_NAME];
				memset(ord, 0, MAX_FUNCTION_NAME);

				if (is_ordinal) {
					snprintf(ord, MAX_FUNCTION_NAME, "ord%s", hint_str);
					el->function_name = strdup(ord);
				} else {
					el->function_name = strdup(fname);
				}
			}
		}

		for (unsigned i=0; i < strlen(el->function_name); i++)
			el->function_name[i] = tolower(el->function_name[i]);

		LL_APPEND(*head, el);
	}
}

char *imphash(pe_ctx_t *ctx, int flavor)
{
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		return NULL;

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		//fprintf(stderr, "import directory not found\n");
		return NULL;
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);
	element *elt, *tmp, *head = NULL;
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

		//output_open_scope("Library", OUTPUT_SCOPE_TYPE_OBJECT);
		//output("Name", dll_name);

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			break;
		}

		imphash_load_imported_functions(ctx, ofs, dll_name, &head, flavor);
		ofs = aux; // Restore previous ofs
	}

	LL_COUNT(head, elt, count);
	//printf("%d number of elements in list outside\n", count);

	size_t imphash_string_size = sizeof(char) * count * (MAX_DLL_NAME + MAX_FUNCTION_NAME) + 1;

	char *imphash_string = malloc(imphash_string_size);
	if (imphash_string == NULL) {
		// TODO: Handle allocation failure.
		abort();
	}

	memset(imphash_string, 0, imphash_string_size);

	LL_FOREACH_SAFE(head, elt, tmp) \
		sprintf(imphash_string + strlen(imphash_string), "%s.%s,", elt->dll_name, elt->function_name); \
		LL_DELETE(head, elt);

	free(elt);

	imphash_string_size = strlen(imphash_string);
	if (imphash_string_size)
		imphash_string[imphash_string_size-1] = '\0'; // remove the last comma sign

	//puts(imphash_string); // DEBUG

	char imphash[33];
	char *output = malloc(sizeof(imphash));
	char *md5 = calc_hash("md5", imphash_string, sizeof(imphash_string), imphash);
	memcpy(output, md5, sizeof(imphash));
	free(md5);

	free(imphash_string);

	return output;
}

void dealloc_hdr_hashes(pe_hdr_t obj) {
	free(obj.dos.md5);
	free(obj.dos.sha1);
	free(obj.dos.sha256);
	free(obj.dos.ssdeep);
	free(obj.coff.md5);
	free(obj.coff.sha1);
	free(obj.coff.sha256);
	free(obj.coff.ssdeep);
	free(obj.optional.md5);
	free(obj.optional.sha1);
	free(obj.optional.sha256);
	free(obj.optional.ssdeep); 
}

void dealloc_sections_hashes(pe_hash_section_t obj) {
	int count = obj.count;
	for (int i=0;i<count;i++){
		free(obj.sections[i].md5);
		free(obj.sections[i].sha1);
		free(obj.sections[i].sha256);
		free(obj.sections[i].ssdeep);
	}
	free(obj.sections);
}

void dealloc_filehash(pe_hash_t obj) {
	free(obj.name);
	free(obj.md5);
	free(obj.sha1);
	free(obj.sha256);
	free(obj.ssdeep);
}

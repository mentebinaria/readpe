#ifndef LIBPE_HASHES
#define LIBPE_HASHES

#ifdef __cplusplus
extern "C" {
#endif

#include "pe.h"
#include "error.h"

	typedef struct {
		pe_err_e err;
		const char *name;
		char *md5;	// const is not use because memcpy will change these value.
		char *ssdeep;
		char *sha1;
		char *sha256;
	}hash_t;

	typedef struct {
		pe_err_e err;
		hash_t dos;
		hash_t coff;
		hash_t optional;
	}pe_hdr_t;

	typedef struct {
		pe_err_e err;
		int count;
		hash_t *sections;
	}pe_hash_section_t;

	pe_hdr_t get_headers_hash(pe_ctx_t *ctx);
	pe_hash_section_t get_sections_hash(pe_ctx_t *ctx);
	hash_t get_file_hash(pe_ctx_t *ctx);
	char *imphash(pe_ctx_t *ctx, int flavor);

	// Dellocation Functions
	void dealloc_hdr_hashes(pe_hdr_t header_hashes);
	void dealloc_sections_hashes(pe_hash_section_t sections_hash);
	void dealloc_filehash(hash_t filehash);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

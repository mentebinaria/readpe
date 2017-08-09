#ifndef LIBPE_HASHES
#define LIBPE_HASHES

#ifdef __cplusplus
extern "C" {
#endif

#include "pe.h"
#include "error.h"

typedef struct {
	pe_err_e err;
	char *name;
	char *md5;
	char *ssdeep;
	char *sha1;
	char *sha256;
}pe_hash_t;

typedef struct {
	pe_err_e err;
	pe_hash_t dos;
	pe_hash_t coff;
	pe_hash_t optional;
}pe_hdr_t;

typedef struct {
	pe_err_e err;
	int count;
	pe_hash_t *sections;
}pe_hash_section_t;

pe_hdr_t get_headers_hash(pe_ctx_t *ctx);
pe_hash_section_t get_sections_hash(pe_ctx_t *ctx);
pe_hash_t get_file_hash(pe_ctx_t *ctx);
char *imphash(pe_ctx_t *ctx, int flavor);

// Dellocation Functions
void dealloc_hdr_hashes(pe_hdr_t obj);
void dealloc_sections_hashes(pe_hash_section_t obj);
void dealloc_filehash(pe_hash_t obj);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

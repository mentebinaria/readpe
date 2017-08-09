#ifndef LIBPE_HASHES
#define LIBPE_HASHES

#include "pe.h"
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBPE_IMPHASH_FLAVOR_MANDIANT = 1,
	LIBPE_IMPHASH_FLAVOR_PEFILE = 2,
} pe_imphash_flavor_e;

typedef struct {
	pe_err_e err;
	char *name;
	char *md5;
	char *ssdeep;
	char *sha1;
	char *sha256;
} pe_hash_t;

typedef struct {
	pe_err_e err;
	pe_hash_t dos;
	pe_hash_t coff;
	pe_hash_t optional;
} pe_hdr_t;

typedef struct {
	pe_err_e err;
	uint32_t count;
	pe_hash_t *sections;
} pe_hash_section_t;

pe_hdr_t get_headers_hash(pe_ctx_t *ctx);
pe_hash_section_t get_sections_hash(pe_ctx_t *ctx);
pe_hash_t get_file_hash(pe_ctx_t *ctx);
char *pe_imphash(pe_ctx_t *ctx, pe_imphash_flavor_e flavor);

void pe_dealloc_hdr_hashes(pe_hdr_t obj);
void pe_dealloc_sections_hashes(pe_hash_section_t obj);
void pe_dealloc_filehash(pe_hash_t obj);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

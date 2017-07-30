#include "pe.h"
#include "error.h"

typedef struct {
	pe_err_e err;
	const char *name;
	char *md5;  // const is not use because memcpy will change these value.
	char *ssdeep;
	char *sha1;
	char *sha256;
}hash_t;

typedef struct {
	pe_err_e err;
	hash_t dos;
	hash_t coff;
	hash_t optional;
}hdr_t;

typedef struct {
	pe_err_e err;
int count;
	hash_t *sections;
}hash_section_t;

// General functions
char *calc_hash(const char *alg_name, const unsigned char *data, size_t size, char *output);

// Functions to get hash of headers
hash_t get_hashes(const char *name,const unsigned char *data, size_t size);
hash_t get_headers_dos_hash(pe_ctx_t *ctx);
hash_t get_headers_coff_hash(pe_ctx_t *ctx);
hash_t get_headers_optional_hash(pe_ctx_t *ctx);
hdr_t get_headers_hash(pe_ctx_t *ctx);

// Functions to get hash of sections
hash_section_t get_sections_hash(pe_ctx_t *ctx);

	// Functions to get Hash of entire file
hash_t get_file_hash(pe_ctx_t *ctx);

// Functions to get imphash
char *imphash(pe_ctx_t *ctx, int flavor);
void dealloc_hdr_hashes(hdr_t header_hashes);
void dealloc_sections_hashes(hash_section_t sections_hash);
void dealloc_filehash(hash_t filehash);

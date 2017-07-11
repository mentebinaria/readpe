#include <stdint.h>
#include <stdio.h>
#include "pe.h"
#include "libfuzzy/fuzzy.h"

typedef struct {
	char *name;  // IMAGE_DOS_HEADER
	char *md5;
	char *ssdeep;
	char *sha1;
	char *sha256;
}hash_;

typedef struct {
	hash_ dos;
	hash_ coff;
	hash_ optional;
}hdr_;

typedef struct {
int count;
	hash_ *sections;
}hash_section;

// General functions
char *calc_hash(const char *alg_name, const unsigned char *data, size_t size, char *output);

// Functions to get hash of headers
hash_ get_hashes(char *name,const unsigned char *data, size_t size);
hash_ get_headers_dos_hash(pe_ctx_t *ctx);
hash_ get_headers_coff_hash(pe_ctx_t *ctx);
hash_ get_headers_optional_hash(pe_ctx_t *ctx);
hdr_ get_headers_hash(pe_ctx_t *ctx);

// Functions to get hash of sections
hash_section get_sections_hash(pe_ctx_t *ctx);

	// Functions to get Hash of entire file
hash_ get_file_hash(pe_ctx_t *ctx);


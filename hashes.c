#include "pe.h"
#include "hashes.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "fuzzy.h"

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
	EVP_MD_CTX_cleanup(md_ctx);
#else
	EVP_MD_CTX_free(md_ctx);
#endif
	for (unsigned int i=0; i < md_len; i++)
		sprintf(&output[i * 2], "%02x", md_value[i]);
	EVP_cleanup();

	return output;
}

hash_ get_hashes(char *name,const unsigned char *data, size_t data_size) {
	hash_ sample;

	int MD_SIZE = EVP_MAX_MD_SIZE * 2 + 1;
	char hash_value[MD_SIZE];
	sample.name  = name;                             // TODO : allow memory dynamically.
	//sample.name = (char *)malloc(
	sample.md5 = (char *)malloc(MD_SIZE*sizeof(char *));
	sample.sha1 = (char *)malloc(MD_SIZE*sizeof(char *));
	sample.sha256 = (char *)malloc(MD_SIZE*sizeof(char *));
	sample.ssdeep = (char *)malloc(MD_SIZE*sizeof(char *));

	memcpy(sample.md5, calc_hash("md5", data, data_size, hash_value), MD_SIZE * sizeof(char *));
	memcpy(sample.sha1, calc_hash("sha1", data, data_size, hash_value), MD_SIZE * sizeof(char *));
	memcpy(sample.sha256, calc_hash("sha256", data, data_size, hash_value), MD_SIZE * sizeof(char *));
	memcpy(sample.ssdeep, calc_hash("ssdeep", data, data_size, hash_value), MD_SIZE * sizeof(char *));

	return sample;

}

hash_ get_headers_dos_hash(pe_ctx_t *ctx) {
	hash_ dos;
	const IMAGE_DOS_HEADER *dos_sample = pe_dos(ctx);
	const unsigned char *data = (const unsigned char *)dos_sample;
	uint64_t data_size = sizeof(IMAGE_DOS_HEADER);
	dos = get_hashes("IMAGE_DOS_HEADER", data, data_size);
	return dos;
}

hash_ get_headers_coff_hash(pe_ctx_t *ctx) {
	hash_ coff;
	const IMAGE_COFF_HEADER *coff_sample = pe_coff(ctx);
	const unsigned char *data = (const unsigned char *)coff_sample;
	uint64_t data_size = sizeof(IMAGE_COFF_HEADER);
	coff = get_hashes("IMAGE_COFF_HEADER", data, data_size); 
	return coff;
}

hash_ get_headers_optional_hash(pe_ctx_t *ctx) {
	hash_ optional;
	const IMAGE_OPTIONAL_HEADER *optional_sample = pe_optional(ctx);
	const unsigned char *data;
	uint64_t data_size;
	switch(optional_sample->type) {
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
	return optional;	
}

hdr_ get_headers_hash(pe_ctx_t *ctx) {

	hash_ dos = get_headers_dos_hash(ctx);
	hash_ optional = get_headers_optional_hash(ctx);
	hash_ coff = get_headers_coff_hash(ctx);

	hdr_ sample_hdr;
	sample_hdr.dos = dos;
	sample_hdr.coff = coff;
	sample_hdr.optional = optional;

	return sample_hdr;
}

hash_section get_sections_hash(pe_ctx_t *ctx) {
	hash_section final_sample;
	int c = pe_sections_count(ctx); // Total number of sections
	hash_ *sample = (hash_ *)malloc(c *sizeof(hash_));  //local hash sample which will later be assigned to finalsample.sections
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
			fprintf(stderr, "%s\n", "unable to read sections data");
			final_sample.count = 0;
			final_sample.sections = NULL;
			return final_sample;
		}
		if (data_size) {
			name = (char *)sections[i]->Name;
			sample[count] =  get_hashes(name, data, data_size);
			printf("%d \n",count);
			count++;
		}
	}
	//section_ sample_sect;
	//sample_sect.sections = (hash_ *)malloc( c * sizeof(hash_));
	//sample_sect.sections = sample;
	//sample_sect.count = c;
	for (int i=0;i<count; i++) {
			printf("%s\n",sample[i].name);
	}
	final_sample.count = count;
	final_sample.sections = sample;
	return final_sample;

}

hash_ get_file_hash(pe_ctx_t *ctx) {
	const unsigned char *data = ctx->map_addr;
	uint64_t data_size = pe_filesize(ctx);
	hash_ sample;
	char *name = "PEfile hash";
	sample = get_hashes(name, data, data_size);
	return sample;
} 



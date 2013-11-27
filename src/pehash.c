/*
	pev - the PE file analyzer toolkit

	pehash.c - calculate hashes of PE pieces

	Copyright (C) 2012 - 2013 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "../lib/libfuzzy/fuzzy.h"

#define PROGRAM "pehash"

typedef struct {
	struct {
		bool all;
		bool md5;
		bool sha1;
		bool sha256;
		bool ssdeep;
	} algorithms;
	struct {
		bool all;
		bool dos;
		bool coff;
		bool optional;
	} headers;
	struct {
		char *name;
		uint16_t index;
	} sections;
} options_t;

static void usage(void)
{
	printf("Usage: %s OPTIONS FILE\n"
		"Calculate hashes of PE pieces\n"
		"\nExample: %s -s '.text' winzip.exe\n"
		"\nOptions:\n"
		" -f, --format <text|csv|xml|html>           change output format (default: text)\n"
		" -a, --algorithm <md5|sha1|sha256|ssdeep>   hash using only the specified algorithm\n"
		" -h, --header <dos|coff|optional>           hash only the header with the specified name\n"
		" -s, --section <section_name>               hash only the section with the specified name\n"
		" --section-index <section_index>            hash only the section at the specified index (1..n)\n"
		" -v, --version                              show version and exit\n"
		" --help                                     show this help and exit\n",
		PROGRAM, PROGRAM);

}

static void parse_hash_algorithm(options_t *options, const char *optarg)
{
	if (strcmp(optarg, "md5") == 0)
		options->algorithms.md5 = true;
	else if (strcmp(optarg, "sha1") == 0)
		options->algorithms.sha1 = true;
	else if (strcmp(optarg, "sha256") == 0)
		options->algorithms.sha256 = true;
	else if (strcmp(optarg, "ssdeep") == 0)
		options->algorithms.ssdeep = true;
	else
		EXIT_ERROR("invalid hashing algorithm option");
}

static void parse_header_name(options_t *options, const char *optarg)
{
	if (strcmp(optarg, "dos") == 0)
		options->headers.dos = true;
	else if (strcmp(optarg, "coff") == 0)
		options->headers.coff = true;
	else if (strcmp(optarg, "optional") == 0)
		options->headers.optional = true;
	else
		EXIT_ERROR("invalid header name option");
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	if (options->sections.name != NULL)
		free(options->sections.name);

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	// parameters for getopt_long() function 
	static const char short_options[] = "f:Aa:h:s:v";

	static const struct option long_options[] = {
		{ "help",			no_argument,			NULL,  1  },
		{ "format",			required_argument,	NULL, 'f' },
		{ "algorithm",		required_argument,	NULL, 'a' },
		{ "header",			required_argument,	NULL, 'h' },
		{ "section-name",	required_argument,	NULL, 's' },
		{ "section-index",required_argument,	NULL,  2  },
		{ "version",		no_argument,			NULL, 'v' },
		{  NULL,				0,							NULL,  0  }
	};

	// Default options.
	options->algorithms.all = true;
	options->headers.all = true;

	int c, ind;
	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:     // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				parse_format(optarg);
				break;
			case 'a':
				options->algorithms.all = false;
				parse_hash_algorithm(options, optarg);
				break;
			case 's':
				options->headers.all = false;
				// TODO: How do we need to handle non-ascii names?
				options->sections.name = strdup(optarg);
				break;
			case 2:
				options->headers.all = false;
				options->sections.index = strtol(optarg, NULL, 10);
				if (options->sections.index < 1 || options->sections.index > MAX_SECTIONS) {
					EXIT_ERROR("Bad argument for section-index,");
				}
				break;
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 'h':
				options->headers.all = false;
				parse_header_name(options, optarg);
				break;
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	// TODO: Warn about simultaneous usage of -h, -s, and --section-index.

	return options;
}

static void calc_sha1(const unsigned char *data, size_t size, char *sha1sum)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA_CTX mdContext;

	SHA1_Init(&mdContext);
	SHA1_Update(&mdContext, data, size);
	SHA1_Final(hash, &mdContext);

	for (unsigned i=0; i < SHA_DIGEST_LENGTH; i++)
		snprintf(&sha1sum[i*2], MAX_MSG, "%02x", hash[i]);
}

static void calc_sha256(const unsigned char *data, size_t size, char *sha256sum)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX mdContext;

	SHA256_Init(&mdContext);
	SHA256_Update(&mdContext, data, size);
	SHA256_Final(hash, &mdContext);

	for (unsigned i=0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&sha256sum[i*2], "%02x", hash[i]);
}

static void calc_md5(const unsigned char *data, size_t size, char *md5sum)
{
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX mdContext;

	MD5_Init(&mdContext);
	MD5_Update(&mdContext, data, size);
	MD5_Final(hash, &mdContext);

	for (unsigned i=0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(&md5sum[i*2], "%02x", hash[i]);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		return EXIT_FAILURE;
	}

	options_t *options = parse_options(argc, argv);

	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, argv[argc-1]);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx))
		EXIT_ERROR("not a valid PE file");

	const IMAGE_SECTION_HEADER *section_ptr = NULL;
	const unsigned char *data = NULL;
	uint64_t data_size = 0;

	if (options->headers.all) {
		const uint64_t pe_size = pe_filesize(&ctx);
		data = ctx.map_addr;
		data_size = pe_size;
	} else if (options->headers.dos) {
		const IMAGE_DOS_HEADER *dos_hdr = pe_dos(&ctx);
		data = (const unsigned char *)dos_hdr;
		data_size = sizeof(IMAGE_DOS_HEADER);
	} else if (options->headers.coff) {
		const IMAGE_COFF_HEADER *coff_hdr = pe_coff(&ctx);
		data = (const unsigned char *)coff_hdr;
		data_size = sizeof(IMAGE_COFF_HEADER);
	} else if (options->headers.optional) {
		const IMAGE_OPTIONAL_HEADER *opt_hdr = pe_optional(&ctx);
		switch (opt_hdr->type) {
			case MAGIC_ROM:
				// Oh boy! We do not support ROM. Abort!
				fprintf(stderr, "ROM image is not supported\n");
				break;
			case MAGIC_PE32:
				if (LIBPE_IS_PAST_THE_END(&ctx, opt_hdr->_32, sizeof(IMAGE_OPTIONAL_HEADER_32))) {
					// TODO: Should we report something?
					break;
				}
				data = (const unsigned char *)opt_hdr->_32;
				data_size = sizeof(IMAGE_OPTIONAL_HEADER_32);
				break;
			case MAGIC_PE64:
				if (LIBPE_IS_PAST_THE_END(&ctx, opt_hdr->_64, sizeof(IMAGE_OPTIONAL_HEADER_64))) {
					// TODO: Should we report something?
					break;
				}
				data = (const unsigned char *)opt_hdr->_64;
				data_size = sizeof(IMAGE_OPTIONAL_HEADER_64);
				break;

		}
	} else if (options->sections.name != NULL) {
		const IMAGE_SECTION_HEADER *section = pe_section_by_name(&ctx, options->sections.name);
		if (section == NULL) {
			EXIT_ERROR("The requested section could not be found on this binary");
		}
		section_ptr = section;
	} else if (options->sections.index > 0) {
		const uint16_t num_sections = pe_sections_count(&ctx);
		if (num_sections == 0 || options->sections.index > num_sections) {
			EXIT_ERROR("The requested section could not be found on this binary");
		}
		IMAGE_SECTION_HEADER ** const sections = pe_sections(&ctx);
		const IMAGE_SECTION_HEADER *section = sections[options->sections.index - 1];
		section_ptr = section;
	}

	if (section_ptr != NULL) {
		if (section_ptr->SizeOfRawData > 0) {
			const uint8_t *section_data_ptr = LIBPE_PTR_ADD(ctx.map_addr, section_ptr->PointerToRawData);
			// printf("map_addr = %p\n", ctx.map_addr);
			// printf("section_data_ptr = %p\n", section_data_ptr);
			// printf("SizeOfRawData = %u\n", section_ptr->SizeOfRawData);
			if (LIBPE_IS_PAST_THE_END(&ctx, section_data_ptr, section_ptr->SizeOfRawData)) {
				EXIT_ERROR("The requested section has an invalid size");
			}
			data = (const unsigned char *)section_data_ptr;
			data_size = section_ptr->SizeOfRawData;
		} else {
			data = (const unsigned char *)"";
			data_size = 0;
		}
	}

	if (data != NULL) {
		if (options->algorithms.md5 || options->algorithms.all) {
			char md5_sum[(MD5_DIGEST_LENGTH*2) + 1];
			calc_md5(data, data_size, md5_sum);
			output("md5", md5_sum);
		}

		if (options->algorithms.sha1 || options->algorithms.all) {
			char sha1_sum[((SHA_DIGEST_LENGTH*2)+1)];
			calc_sha1(data, data_size, sha1_sum);
			output("sha-1", sha1_sum);
		}

		if (options->algorithms.sha256 || options->algorithms.all) {
			char sha256_sum[((SHA256_DIGEST_LENGTH*2)+1)];
			calc_sha256(data, data_size, sha256_sum);
			output("sha-256", sha256_sum);
		}

		if (options->algorithms.ssdeep || options->algorithms.all) {
			char ssdeep[FUZZY_MAX_RESULT + 1];
			fuzzy_hash_buf(data, data_size, ssdeep);
			output("sssdeep", ssdeep);
		}
	}

	// free
	free_options(options);
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

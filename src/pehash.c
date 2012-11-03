/*
	pev - the PE file analyzer toolkit

	pehash.c - calculate PE file cryptographic signatures
	
	Copyright (C) 2012 pev authors
	
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
	
#include "pehash.h"

struct options config;
static int ind;

static void usage() 
{
	printf("Usage: %s OPTIONS FILE\n"
	"Show PE file cryptographic signatures\n"
	"\nExample: %s --hash md5 winzip.exe\n"
	"\nOptions:\n"
	" -A, --all                              full output (all available hashes) (default)\n"
	" -f, --format <text|csv|xml|html>       change output format (default text)\n"
	" -h, --hash <md5|sha1|sha256>           hashing algorithm\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
PROGRAM, PROGRAM);

}

static void parse_hash_algorithm(const char *optarg)
{
	if (! strcmp(optarg, "md5"))
		config.md5 = true;
	else if (! strcmp(optarg, "sha1"))
		config.sha1 = true;
	else if (! strcmp(optarg, "sha256"))
		config.sha256 = true;
	else
		EXIT_ERROR("invalid hashing algorithm option");
}

void parse_options(int argc, char *argv[])
{
	int c;

	// parameters for getopt_long() function 
	static const char short_options[] = "AHSh:dif:v";

	static const struct option long_options[] = {
	{"help",             no_argument,       NULL,  1 },
	{"all",              no_argument,       NULL, 'A'},
	{"hash",             required_argument, NULL, 'h'},
	{"format",           required_argument, NULL, 'f'},
	{"version",          no_argument,       NULL, 'v'},
	{ NULL,              0,                 NULL,  0 }
	};

	// setting all fields to false
	memset(&config, false, sizeof(config));

	config.all = true;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:     // --help option
				usage();
				exit(EXIT_SUCCESS);

			case 'A':
				config.all = true; break;

				case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

				case 'h':
				config.all = false;
				parse_hash_algorithm(optarg); break;

				case 'f':
				parse_format(optarg); break;

				default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

static void calc_sha1(unsigned char *data, size_t size, char *sha1sum)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA_CTX mdContext;

	SHA1_Init(&mdContext);
	SHA1_Update(&mdContext, data, size);
	SHA1_Final(hash, &mdContext);

	for(unsigned i=0; i < SHA_DIGEST_LENGTH; i++)
		snprintf(&sha1sum[i*2], MAX_MSG, "%02x", hash[i]);
}

static void calc_sha256(unsigned char *data, size_t size, char *sha256sum)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX mdContext;

	SHA256_Init(&mdContext);
	SHA256_Update (&mdContext, data, size);
	SHA256_Final(hash, &mdContext);

	for(unsigned i=0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&sha256sum[i*2], "%02x", hash[i]);
}

static void calc_md5(unsigned char *data, size_t size, char *md5sum)
{
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX mdContext;

	MD5_Init(&mdContext);
	MD5_Update(&mdContext, data, size);
	MD5_Final(hash, &mdContext);

	for(unsigned i=0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(&md5sum[i*2], "%02x", hash[i]);
}

int main(int argc, char *argv[])
{
	FILE *fp;
	PE_FILE pe;
	unsigned char *data;
	size_t pesize = 0;

	if (argc < 2)
	{
		usage();
		exit(1);
	}

	parse_options(argc, argv);

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp);
	fseek(pe.handle, 0, SEEK_END);
	pesize = ftell(pe.handle);
	rewind(pe.handle);
	data = (unsigned char *) xmalloc(pesize + 1);
	fread(data, pesize, 1, pe.handle);

	if (config.md5 || config.all)
	{
		char md5_sum[(MD5_DIGEST_LENGTH*2) + 1];

		calc_md5(data, pesize, md5_sum);
		output("md5", md5_sum);
	}

	if (config.sha1 || config.all)
	{
		char sha1_sum[((SHA_DIGEST_LENGTH*2)+1)];

		calc_sha1(data, pesize, sha1_sum);
		output("sha-1", sha1_sum);
	}


	if (config.sha256 || config.all)
	{
		char sha256_sum[((SHA256_DIGEST_LENGTH*2)+1)];

		calc_sha256(data, pesize, sha256_sum);
		output("sha-256", sha256_sum);
	}

	pe_deinit(&pe);
	free(data);
	return 0;
}

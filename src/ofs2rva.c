/*
	pev - the PE file analyzer toolkit

	ofs2rva.c - converts raw file offset to RVA

	Copyright (C) 2012 - 2015 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"

#define PROGRAM "ofs2rva"

static void usage(void)
{
	printf("Usage: %s <offset> FILE\n"
		"Convert raw file offset to RVA\n"
		"\nExample: %s 0x1b9b8 calc.exe\n"
		"\nOptions:\n"
		" -v, --version                          show version and exit\n"
		" --help                                 show this help and exit\n",
		PROGRAM, PROGRAM);
}

static void parse_options(int argc, char *argv[])
{
	/* Parameters for getopt_long() function */
	static const char short_options[] = "v";

	static const struct option long_options[] = {
		{ "help",		no_argument,	NULL,  1  },
		{ "version",	no_argument,	NULL, 'v' },
		{  NULL,		0,				NULL,  0  }
	};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1: // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	//PEV_INITIALIZE();

	if (argc != 3) {
		usage();
		return EXIT_FAILURE;
	}

	parse_options(argc, argv); // opcoes

	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, argv[2]);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	uint64_t ofs = (uint64_t)strtoll(argv[1], NULL, 0);

	if (!ofs)
		EXIT_ERROR("invalid offset");

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx))
		EXIT_ERROR("not a valid PE file");

	printf("%#llx\n", pe_ofs2rva(&ctx, ofs));

	// libera a memoria
	pe_unload(&ctx);

	//PEV_FINALIZE();

	return EXIT_SUCCESS;
}

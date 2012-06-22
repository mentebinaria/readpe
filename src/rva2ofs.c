/*
	pev - the PE file analyzer toolkit
	
	rva2ofs.c - convert RVA to raw file offset

	Copyright (C) 2012 Fernando Mercês

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

#include "rva2ofs.h"

static int ind;

void usage()
{
	printf("Usage: %s <rva> FILE\n"
	"Convert RVA to raw file offset\n"
	"\nExample: %s 0x12db cards.dll\n"
	"\nOptions:\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "v";

	static const struct option long_options[] = {
		{"help",             no_argument,       NULL,  1 },
		{"version",          no_argument,       NULL, 'v'},
		{ NULL,              0,                 NULL,  0 }
	};

	while ((c = getopt_long(argc, argv, short_options,
			long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:		// --help option
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
	PE_FILE pe;
	FILE *fp = NULL;
	unsigned long rva = 0;

	parse_options(argc, argv); // opcoes

	if (argc != 3)
	{
		usage();
		exit(1);
	}

	if ((fp = fopen(argv[2], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	rva = (unsigned long) strtol(argv[1], NULL, 0);

	if (!rva)
		EXIT_ERROR("invalid RVA");


	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");
		
	printf("%#"PRIx64"\n", rva2ofs(&pe, rva));
	// libera a memoria
	pe_deinit(&pe);
	
	return 1;
}

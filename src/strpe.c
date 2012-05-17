/*
	pev - the PE file analyzer toolkit
	
	strpe.c - search for encrypted strings in PE files

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

#include "strpe.h"

static int ind;

void usage()
{
	printf("Usage: %s FILE\n"
	"Search for encrypted strings in PE files\n"
	"\nExample: %s acrobat.exe\n"
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

#define BUFSIZE 1024
#define STRSIZE 4

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	char *format = "%#x %s\n";
	unsigned char buff[BUFSIZE];

	parse_options(argc, argv); // opcoes

	if (argc == 1 || (fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	if (argc == 3)
		format = argv[1];

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	rewind(pe.handle);

	for (unsigned int i=0; fread(&buff, sizeof(buff), 1, pe.handle); i++)
	{
		unsigned c=0;

		for (unsigned int j=0; j<BUFSIZE; j++)
		{
			if (isprint(buff[j]))
			{
				if (j == BUFSIZE-1)
				{
					for (unsigned k=j-c; k<=j; k++)
						printf("%c", buff[k]);
					printf("\n");
				}

				c++;
				continue;
			}
			else
			{
				if (c >= STRSIZE)
				{
					for (unsigned k=j-c; k<j; k++)
						printf("%c", buff[k]);
					
					printf("\n");
				}
				c=0;
			}
		}
	}
	
		
	// libera a memoria
	pe_deinit(&pe);
	
	return 0;
}

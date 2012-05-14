/*
	pesec - search for security features in PE files

	Copyright (C) 2010 - 2012 Fernando Mercês

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

#include "pesec.h"

static int ind;

void usage()
{
	printf("Usage: %s OPTIONS FILE\n\n", PROGRAM);
	
	printf(
	"-f, --format <format>                  set output format\n"
	"-v, --version                          show version and exit\n"
	"--help                                 show this help and exit\n"
	);

}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "f:v";

	static const struct option long_options[] = {
		{"format",           required_argument, NULL, 'f'},
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

			case 'f':
				parse_format(optarg); break;
				
			case 'v':
				printf("%s %s\n", PROGRAM, VERSION);
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
	WORD dllchar = 0;
	char field[MAX_MSG];

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	if (!pe_get_optional(&pe))
		return 1;

	if (pe.architecture == PE32)
		dllchar = pe.optional_ptr->_32->DllCharacteristics;
	else if (pe.architecture == PE64)
		dllchar = pe.optional_ptr->_64->DllCharacteristics;
	else
		return 1;

	snprintf(field, MAX_MSG, "ASLR");	
	output(field, (dllchar & 0x40) ? "found" : "not found");

	snprintf(field, MAX_MSG, "DEP/NX");	
	output(field, (dllchar & 0x100) ? "found" : "not found");

	snprintf(field, MAX_MSG, "SEH");	
	output(field, !(dllchar & 0x400) ? "found" : "not found");

	// libera a memoria
	pe_deinit(&pe);
	
	return 1;
}

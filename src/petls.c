/*
	petls - find TLS callbacks in PE files

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

#include "petls.h"

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

int pe_get_tls_directory(PE_FILE *pe)
{
	if (!pe_get_directories(pe))
		return false;

	if (pe->num_directories > 32)
		{printf("%d\n", pe->num_directories);puts("aqui");
		return false;}


	for (unsigned int i=0; (i < pe->num_directories) && (pe->directories_ptr[i]); i++)
	{
		// 9 is a tls directory
		if (i == 9 && pe->directories_ptr[i]->Size > 0)
			return pe->directories_ptr[i]->VirtualAddress;}
	return 0;
}

bool pe_get_tls_callbacks(PE_FILE *pe)
{
	QWORD tls_addr = 0;
	
	if (!pe)
		return false;

	tls_addr = pe_get_tls_directory(pe);
		
	if (!tls_addr || !pe_get_sections(pe))
		return false;


	// search for tls in all sections
	for (unsigned int i=0, j=0; i < pe->num_sections; i++)
	{
		if (tls_addr >= pe->sections_ptr[i]->VirtualAddress &&
		tls_addr < (pe->sections_ptr[i]->VirtualAddress + pe->sections_ptr[i]->SizeOfRawData))
		{
			unsigned int funcaddr = 0;
			if (fseek(pe->handle, tls_addr - pe->sections_ptr[i]->VirtualAddress
			+ pe->sections_ptr[i]->PointerToRawData, SEEK_SET))
			 	return false;

			if (pe->architecture == PE32)
			{
				IMAGE_TLS_DIRECTORY32 tlsdir32;

				if (!fread(&tlsdir32, sizeof(tlsdir32), 1, pe->handle))
					return false;	

				fseek(pe->handle, tlsdir32.AddressOfCallBacks - 0x400000 -
					pe->sections_ptr[i]->VirtualAddress + pe->sections_ptr[i]->PointerToRawData, SEEK_SET);
			}
			else if (pe->architecture == PE64)
			{
				IMAGE_TLS_DIRECTORY64 tlsdir64;

				if (!fread(&tlsdir64, sizeof(tlsdir64), 1, pe->handle))
					return false;	

				fseek(pe->handle, tlsdir64.AddressOfCallBacks - 0x400000 * 2 -
					pe->sections_ptr[i]->VirtualAddress + pe->sections_ptr[i]->PointerToRawData, SEEK_SET);
			}
			else
				return false;

			do
			{ 
				fread(&funcaddr, sizeof(int), 1, pe->handle);
				if (funcaddr)
				{
					char field[MAX_MSG];
					char value[MAX_MSG];

					snprintf(field, MAX_MSG, "Function %d", ++j);
					snprintf(value, MAX_MSG, "%#x", funcaddr);
					output(field, value);
				}

			} while (funcaddr);

			return true;
		}
	}
	return false;
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	if (pe_get_tls_callbacks(&pe))
		return 0;
		
	// libera a memoria
	pe_deinit(&pe);
	
	return 1;
}

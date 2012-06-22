/*
	pev - the PE file analyzer toolkit
	
	petls.c - find TLS callbacks in PE files

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

#include "petls.h"

static int ind;

void usage()
{
	printf("Usage: %s [OPTIONS] FILE\n"
	"Find TLS callbacks in PE files\n"
	"\nExample: %s winzip.exe\n"
	"\nOptions:\n"
	" -f, --format <text|csv|xml|html>       change output format (default text)\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
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
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

DWORD pe_get_tls_directory(PE_FILE *pe)
{
	if (!pe_get_directories(pe))
		return 0;

	if (pe->num_directories > 32)
		return 0;

	for (unsigned int i=0; (i < pe->num_directories && pe->directories_ptr[i]); i++)
	{
		if ((i == IMAGE_DIRECTORY_ENTRY_TLS) && pe->directories_ptr[i]->Size > 0)
			return pe->directories_ptr[i]->VirtualAddress;
	}
	return 0;
}

/* 0 - no tls section
   1 - tls callbacks functions found
   2 - fake tls callbacks detected
*/
int pe_get_tls_callbacks(PE_FILE *pe)
{
	QWORD tls_addr = 0;
	int ret = 0;
	
	if (!pe)
		return 0;

	tls_addr = pe_get_tls_directory(pe);
		
	if (!tls_addr || !pe_get_sections(pe))
		return 0;


	// search for tls in all sections
	for (unsigned int i=0, j=0; i < pe->num_sections; i++)
	{
		if (tls_addr >= pe->sections_ptr[i]->VirtualAddress &&
		tls_addr < (pe->sections_ptr[i]->VirtualAddress + pe->sections_ptr[i]->SizeOfRawData))
		{
			unsigned int funcaddr = 0;

			if (fseek(pe->handle, tls_addr - pe->sections_ptr[i]->VirtualAddress
			+ pe->sections_ptr[i]->PointerToRawData, SEEK_SET))
			 	return 0;

			if (pe->architecture == PE32)
			{
				IMAGE_TLS_DIRECTORY32 tlsdir32;

				if (!fread(&tlsdir32, sizeof(tlsdir32), 1, pe->handle))
					return 0;	

				if (! (tlsdir32.AddressOfCallBacks & pe->optional_ptr->_32->ImageBase))
					break;

				if (fseek(pe->handle,
						rva2ofs(pe, tlsdir32.AddressOfCallBacks - pe->optional_ptr->_32->ImageBase), SEEK_SET))
					return 0;
			}
			else if (pe->architecture == PE64)
			{
				IMAGE_TLS_DIRECTORY64 tlsdir64;

				if (!fread(&tlsdir64, sizeof(tlsdir64), 1, pe->handle))
					return 0;	

				if (! (tlsdir64.AddressOfCallBacks & pe->optional_ptr->_64->ImageBase))
					break;

				if (fseek(pe->handle,
				 rva2ofs(pe, tlsdir64.AddressOfCallBacks - pe->optional_ptr->_64->ImageBase), SEEK_SET))
					return 0;
			}
			else
				return 0;

			ret = 2; // tls directory and section exists
			do
			{ 
				fread(&funcaddr, sizeof(int), 1, pe->handle);
				if (funcaddr)
				{
					char field[MAX_MSG];
					char value[MAX_MSG];

					ret = 1; // function found
					snprintf(field, MAX_MSG, "Function %d", ++j);
					snprintf(value, MAX_MSG, "%#x", funcaddr);
					output(field, value);
				}
			} while (funcaddr);

			return ret;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	char field[MAX_MSG], value[MAX_MSG];
	
	if (argc < 2)
	{
		usage();
		exit(1);
	}

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	snprintf(field, MAX_MSG, "TLS directory");

	switch (pe_get_tls_callbacks(&pe))
	{
		case 0:
			snprintf(value, MAX_MSG, "not found");
			break;

		case 1:
			snprintf(value, MAX_MSG, "found, with functions");
			break;

		case 2:
			snprintf(value, MAX_MSG, "found, no functions");
			break;

		default:
			break;
	}
	output(field, value);

	// libera a memoria
	pe_deinit(&pe);
	
	return 0;
}

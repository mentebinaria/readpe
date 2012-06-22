/*
	pev - the PE file analyzer toolkit
	
	pepack.c - search for genereic packers in PE files

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

#include "pepack.h"

static int ind;

void usage()
{
	printf("Usage: %s <rva> FILE\n"
	"Search for genereic packers in PE files\n"
	"\nExample: %s putty.exe\n"
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

/* MEW Packer basically stores the entrypoint
   in a section marked only as readable (without
   executable and/or writable flags)
   Windows Loader still executes the binary
*/
bool pe_mew_packer(PE_FILE *pe, DWORD *ep)
{
   unsigned char mew_packer = '0';
	IMAGE_SECTION_HEADER *sec = pe_rva2section(pe, *ep);

   // we count the flags for the section and if there is more than
   // 2 it means we don't have the mew_packer
   unsigned int invalid_flags[] =
	{0x20000000, 0x40000000, 0x80000000};

	if (!sec)
		return false;

	// MEW never leave EP in .text section
	if (memcmp(sec->Name, ".text", 5) == 0)
		return false;

	for (unsigned int j=0; j < sizeof(invalid_flags) / sizeof(unsigned int); j++)
	{
		if (sec->Characteristics & invalid_flags[j])
			mew_packer++;
	}

   return (mew_packer < '3');
}

IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(PE_FILE *pe, DWORD *ep)
{
	IMAGE_SECTION_HEADER *epsec = NULL;

	if (!pe->optional_ptr)
		pe_get_optional(pe);

	if (!pe->num_sections || !pe->sections_ptr)
		pe_get_sections(pe);

	if (!pe->num_sections)
		return NULL;

	epsec = pe_rva2section(pe, *ep);

	if (!epsec)
		return NULL;

	if (!(epsec->Characteristics & 0x20))
		return epsec;

   return NULL;
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	DWORD ep;
	int ret = 0;
	char value[MAX_MSG];

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

	if (!pe_get_optional(&pe))
		return 1;

   ep = (pe.optional_ptr->_32 ? pe.optional_ptr->_32->AddressOfEntryPoint :
	(pe.optional_ptr->_64 ? pe.optional_ptr->_64->AddressOfEntryPoint : 0));

	if (!ep)
		return 1;

	if (pe_check_fake_entrypoint(&pe, &ep))
	{
		snprintf(value, MAX_MSG, "yes, %#x", ep);
		ret = 1;
	}
	else
		snprintf(value, MAX_MSG, "no");
		
	output("fake entrypoint", value);
	
	if (pe_mew_packer(&pe, &ep))
	{
		snprintf(value, MAX_MSG, "MEW");
		ret = 1;
	}
	else
		snprintf(value, MAX_MSG, "none");

	output("packer", value);

	// libera a memoria
	pe_deinit(&pe);
	
	return ret;
}

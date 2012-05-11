/*
	fakeoep - check for fake entry point in PE files

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

#include "fakeoep.h"

static int ind;

void usage()
{
	printf("Usage: %s OPTIONS FILE\n\n", PROGRAM);
	
	printf(
	"-v, --version                          show version and exit\n"
	"--help                                 show this help and exit\n"
	);

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
				printf("%s %s\n", PROGRAM, VERSION);
				exit(EXIT_SUCCESS);

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(PE_FILE *pe, DWORD *ep)
{
	if (!pe->optional_ptr)
		pe_get_optional(pe);

	if (!pe->num_sections || !pe->sections_ptr)
		pe_get_sections(pe);

   if (((pe->optional_ptr->_32 && pe->optional_ptr->_32->AddressOfEntryPoint) ||
	(pe->optional_ptr->_64 && pe->optional_ptr->_64->AddressOfEntryPoint)) && pe->num_sections)
   {
      *ep = (pe->optional_ptr->_32 ? pe->optional_ptr->_32->AddressOfEntryPoint :
		(pe->optional_ptr->_64 ? pe->optional_ptr->_64->AddressOfEntryPoint : 0));
      unsigned int i = 0;

      while (i < pe->num_sections &&
      (*ep < pe->sections_ptr[i]->VirtualAddress || *ep >= pe->sections_ptr[i]->VirtualAddress
		+ pe->sections_ptr[i]->Misc.VirtualSize))
         i++;

      if (i < pe->num_sections && !(pe->sections_ptr[i]->Characteristics & 0x00000020))
		   return pe->sections_ptr[i];
   }

   return NULL;
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	IMAGE_SECTION_HEADER *sec_fake_ep;
	DWORD ep;

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");
		
	sec_fake_ep = pe_check_fake_entrypoint(&pe, &ep);
	
	// libera a memoria
	pe_deinit(&pe);
	
	if (sec_fake_ep)
	{
		printf("Fake EP outside code section: %#x\n", ep);
		return 0;
	}
	
	puts("nothing found");
	return 1;
}

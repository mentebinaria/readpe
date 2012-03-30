/*
	pev - the PE file analyzer

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

#include "include/libpe.h"

bool pe_init(PE_FILE *pe, FILE *handle)
{
	if (!pe || !handle)
		return false;

	pe->handle = handle;

	pe->e_lfanew = 0;
	pe->architecture = 0;

	pe->num_sections = 0;
	pe->num_directories = 0;
	pe->num_rsrc_entries = 0;

	pe->addr_sections = 0;
	pe->addr_directories = 0;
	pe->addr_dos = 0;
	pe->addr_optional = 0;
	pe->addr_coff = 0;
	pe->addr_rsrc_dir = 0;

	// pointers (will be freed if needed)
	pe->optional_ptr = NULL;
	pe->sections_ptr = NULL;
	pe->directories_ptr = NULL;
	pe->tls_ptr = NULL;

	return true;
}

int pe_get_section(PE_FILE *pe, const char *section_name)
{
	if (!pe->addr_sections || !pe->num_sections)
		pe_get_sections(pe);

	for (int i=0; i < pe->num_sections; i++)
	{
		if (memcmp(pe->sections_ptr[i]->Name, section_name, strlen(section_name)) == 0)
			return pe->sections_ptr[i]->PointerToRawData;
	}
	return 0;
}

bool pe_get_resource_directory(PE_FILE *pe, IMAGE_RESOURCE_DIRECTORY *dir)
{
	int i;

	if (!pe->addr_rsrc_dir)
		pe->addr_rsrc_dir = pe_get_section(pe, ".rsrc");

	printf("%d\n", pe->addr_rsrc_dir); return true;

	pe_get_sections(pe);
	for (i=0; i < pe->num_sections; i++)
	{
		if (memcmp(pe->sections_ptr[i]->Name, ".rsrc", 5) == 0)
		{
			fseek(pe->handle, pe->sections_ptr[i]->PointerToRawData, SEEK_SET);
			fread(dir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
			return true;
		}
	}
	return false;
}

/*
bool pe_get_tls_callbacks(PE_FILE *pe)
{
	IMAGE_TLS_DIRECTORY32 *tlsdir;
	int i;
	unsigned tls_addr = 0;

	pe_get_directories(pe);
	for (i=0; i < pe->num_directories; i++)
	{
		if (pe->directories_ptr[i].Size > 0)
		{
		    if (i==9) // 9 is TLS directory
		    	tls_addr = pe->directories_ptr[i].VirtualAddress;
		}
	}
	//printf("tls_addr: %#x\n", tls_addr);

	pe_get_sections(pe);
	for (i=0; i < pe->num_sections; i++)
	{
		if (tls_addr > pe->sections_ptr[i].VirtualAddress &&
		    tls_addr < (pe->sections_ptr[i].VirtualAddress + pe->sections_ptr[i].SizeOfRawData))
		{
			tlsdir = (IMAGE_TLS_DIRECTORY32 *) malloc(sizeof(tlsdir));

			fseek(pe->handle, tls_addr - pe->sections_ptr[i].VirtualAddress
			+ pe->sections_ptr[i].PointerToRawData, SEEK_SET);

			fread(tlsdir, sizeof(tlsdir), 1, pe->handle);

			pe->tls_ptr = tlsdir;

			return true;
		}
	}

	return false;
}
*/

bool pe_get_sections(PE_FILE *pe)
{
	IMAGE_SECTION_HEADER **sections;
	int i;

	if (pe->sections_ptr)
		return true;

	if (!pe->addr_sections || !pe->num_sections)
		pe_get_directories(pe);

	fseek(pe->handle, pe->addr_sections, SEEK_SET);

	sections = (IMAGE_SECTION_HEADER **) malloc(sizeof(IMAGE_SECTION_HEADER *) * pe->num_sections);

	for (i=0; i < pe->num_sections; i++)
	{
		sections[i] = (IMAGE_SECTION_HEADER *) malloc(sizeof(IMAGE_SECTION_HEADER));
		fread(sections[i], sizeof(IMAGE_SECTION_HEADER), 1, pe->handle);
	}

	pe->sections_ptr = sections;

	return true;
}

bool pe_get_directories(PE_FILE *pe)
{
	IMAGE_DATA_DIRECTORY **dirs;
	int i;

	if (pe->directories_ptr)
	{
		dirs = pe->directories_ptr;
		return true;
	}

	if (!pe->addr_directories)
	{
		pe_get_optional(pe);
	}

	fseek(pe->handle, pe->addr_directories, SEEK_SET);

	dirs = (IMAGE_DATA_DIRECTORY **) malloc(sizeof(IMAGE_DATA_DIRECTORY *) * pe->num_directories);

	for (i=0; i < pe->num_directories; i++)
	{
		dirs[i] = (IMAGE_DATA_DIRECTORY *) malloc(sizeof(IMAGE_DATA_DIRECTORY));
		fread(dirs[i], sizeof(IMAGE_DATA_DIRECTORY), 1, pe->handle);
	}

	pe->addr_sections = ftell(pe->handle);
	pe->directories_ptr = dirs;

	return true;
}

bool pe_get_optional(PE_FILE *pe)
{
	IMAGE_OPTIONAL_HEADER *header;

	if (!pe)
		return false;

	if (pe->optional_ptr)
		return true;

	if (!pe->addr_optional)
	{
		IMAGE_COFF_HEADER coff;

		pe_get_coff(pe, &coff);
	}

	fseek(pe->handle, pe->addr_optional, SEEK_SET);

	header = (IMAGE_OPTIONAL_HEADER *) malloc(sizeof(IMAGE_OPTIONAL_HEADER));

	switch (pe->architecture)
	{
		case PE32:
			header->_32 = (IMAGE_OPTIONAL_HEADER_32 *) malloc(sizeof (IMAGE_OPTIONAL_HEADER_32));
			fread(header->_32, sizeof(IMAGE_OPTIONAL_HEADER_32), 1, pe->handle);
			pe->num_directories = header->_32->NumberOfRvaAndSizes;
			pe->entrypoint = header->_32->AddressOfEntryPoint;
			header->_64 = NULL;
			break;

		case PE64:
			header->_64 = (IMAGE_OPTIONAL_HEADER_64 *) malloc(sizeof (IMAGE_OPTIONAL_HEADER_64));
			fread(header->_64, sizeof(IMAGE_OPTIONAL_HEADER_64), 1, pe->handle);
			pe->num_directories = header->_64->NumberOfRvaAndSizes;
			pe->entrypoint = header->_64->AddressOfEntryPoint;
			header->_32 = NULL;
			break;

		default:
			return false;
	}

	pe->optional_ptr = header;
	pe->addr_directories = ftell(pe->handle);

	return true;
}

bool pe_get_coff(PE_FILE *pe, IMAGE_COFF_HEADER *header)
{
	int read;

	if (!pe->addr_coff)
	{
		IMAGE_DOS_HEADER dos;

		pe_get_dos(pe, &dos);
	}

	fseek(pe->handle, pe->addr_coff, SEEK_SET);
	read = fread(header, sizeof(IMAGE_COFF_HEADER), 1, pe->handle);

	pe->num_sections = header->NumberOfSections;
	pe->addr_optional = ftell(pe->handle);

	fread(&pe->architecture, sizeof(WORD), 1, pe->handle);

	return read;
}

bool pe_get_dos(PE_FILE *pe, IMAGE_DOS_HEADER *header)
{
	int read;

	rewind(pe->handle);
	read = fread(header, sizeof(IMAGE_DOS_HEADER), 1, pe->handle);
	pe->addr_coff = header->e_lfanew + 4; // PE\0\0

	return read;
}

bool ispe(PE_FILE *pe)
{
	WORD header;

	if (pe->handle == NULL)
		return false;

	rewind(pe->handle);
	fread(&header, sizeof(WORD), 1, pe->handle);

	if (header == MZ)
		return true;

	return false;
}

IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(PE_FILE *pe)
{
   // Wagner Barongello <wagner@barongello.com.br>
   // 2012-03-29

	if (!pe->optional_ptr->_32 && !pe->optional_ptr->_64)
		pe_get_optional(pe);

	if (!pe->num_sections || !pe->sections_ptr)
		pe_get_sections(pe);

   if (((pe->optional_ptr->_32 && pe->optional_ptr->_32->AddressOfEntryPoint) || (pe->optional_ptr->_64 && pe->optional_ptr->_64->AddressOfEntryPoint)) && pe->num_sections)
   {
      long ep = (pe->optional_ptr->_32 ? pe->optional_ptr->_32->AddressOfEntryPoint : (pe->optional_ptr->_64 ? pe->optional_ptr->_64->AddressOfEntryPoint : -1));
      int i = 0;

      while (i < pe->num_sections &&
      (ep < pe->sections_ptr[i]->VirtualAddress || ep >= pe->sections_ptr[i]->VirtualAddress + pe->sections_ptr[i]->Misc.VirtualSize))
         i++;

      if (i < pe->num_sections && !(pe->sections_ptr[i]->Characteristics & 0x00000020))
		   return pe->sections_ptr[i];
   }

   return NULL;
}

void pe_deinit(PE_FILE *pe)
{
	int i;

	if (pe->handle)
		fclose(pe->handle);

	if (pe->optional_ptr)
	{
		if (pe->optional_ptr->_32)
			free(pe->optional_ptr->_32);

		if (pe->optional_ptr->_64)
			free(pe->optional_ptr->_64);

		free(pe->optional_ptr);
	}

	if (pe->directories_ptr)
	{
		for (i=0; i < pe->num_directories; i++)
		{
			if (pe->directories_ptr[i])
				free(pe->directories_ptr[i]);
		}
		free(pe->directories_ptr);
	}

	if (pe->sections_ptr)
	{
		for (i=0; i < pe->num_sections; i++)
		{
			if (pe->sections_ptr[i])
				free(pe->sections_ptr[i]);
		}
		free(pe->sections_ptr);
	}

	if (pe->tls_ptr)
		free(pe->tls_ptr);
}

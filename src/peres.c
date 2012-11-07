/*
	pev - the PE file analyzer toolkit
	
	peres.c - retrive informations and binary data of resources

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

#include "peres.h"

#include "common.h"
#include "../lib/libudis86/udis86.h"


void discovery(PE_FILE *pe)
{
	static const char *directory_names[] =
	{
		"Export Table", // 0
		"Import Table",
		"Resource Table",
		"Exception Table",
		"Certificate Table",
		"Base Relocation Table",
		"Debug",
		"Architecture",
		"Global Ptr",
		"Thread Local Storage (TLS)", // 9
		"Load Config Table",
		"Bound Import",
		"Import Address Table (IAT)",
		"Delay Import Descriptor",
		"CLR Runtime Header", "" // 14
	};

	output("Data directories", NULL);

	if (!pe->directories_ptr)
		return;

	char s[MAX_MSG];
	QWORD raiz = rva2ofs(pe, pe->directories_ptr[2]->VirtualAddress);

	if (pe->directories_ptr[2]->Size)
	{
		snprintf(s, MAX_MSG, "%#x (%d bytes)",
				pe->directories_ptr[2]->VirtualAddress,
				pe->directories_ptr[2]->Size);

		output((char *) directory_names[2], s); // Resource table
		printf("Offset by RVA: 0x%x\n\n", raiz);
	}

	IMAGE_RESOURCE_DIRECTORY resourceDirectory1;
	IMAGE_RESOURCE_DIRECTORY resourceDirectory2;
	IMAGE_RESOURCE_DIRECTORY resourceDirectory3;
	IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry1;
	IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry2;
	IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry3;
	IMAGE_RESOURCE_DATA_STRING DataString;
	IMAGE_RESOURCE_DATA_ENTRY DataEntry;

	printf("Current Position: %x\n", ftell(pe->handle));
	fseek(pe->handle, raiz, SEEK_SET); // posiciona em 0x72
	printf("Current Position: %x\n\n", ftell(pe->handle));
	fread(&resourceDirectory1, sizeof(resourceDirectory1), 1, pe->handle);

	printf("Characteristics: %d\n", resourceDirectory1.Characteristics);
	printf("Timestamp: %d\n", resourceDirectory1.TimeDateStamp);
	printf("Major Version: %d\n", resourceDirectory1.MajorVersion);
	printf("Minor Version: %d\n", resourceDirectory1.MinorVersion);
	printf("Named entries: %d\n", resourceDirectory1.NumberOfNamedEntries);
	printf("Id entries: %d\n", resourceDirectory1.NumberOfIdEntries);

	printf("Current Position: %x\n\n", ftell(pe->handle));

	int i, j, y;
	int offsetDirectory1 = 0, offsetDirectory2 = 0;
	unsigned char *buffer;
	QWORD offsetData;
	char nomeArquivo[100];
	FILE *fpSave;

	for(i = 1, offsetDirectory1 = 0; i <= (resourceDirectory1.NumberOfNamedEntries+resourceDirectory1.NumberOfIdEntries); i++)
	{
		if(i == 1)
		{
			offsetDirectory1 += 16;
			fseek(pe->handle, raiz+offsetDirectory1, SEEK_SET); // posiciona em 0x72
		}
		else
		{
			offsetDirectory1 += 8;
			fseek(pe->handle, raiz+offsetDirectory1, SEEK_SET); // posiciona em 0x72
		}

		printf("\n\t%d - Resource Directory Entry:\n", i);
		fread(&directoryEntry1, sizeof(directoryEntry1), 1, pe->handle);
		printf("\tCurrent Position: %x\n", ftell(pe->handle));

		printf("\tName offset: %d\n", directoryEntry1.DirectoryName.name.NameOffset);
		printf("\tName is string: %d\n", directoryEntry1.DirectoryName.name.NameIsString);
		printf("\tOffset to directory: %x\n", directoryEntry1.DirectoryData.data.OffsetToDirectory);
		printf("\tData is directory: %d\n", directoryEntry1.DirectoryData.data.DataIsDirectory);

        if (directoryEntry1.DirectoryData.data.DataIsDirectory)
        {
        	fseek(pe->handle, (raiz + directoryEntry1.DirectoryData.data.OffsetToDirectory), SEEK_SET);
        	fread(&resourceDirectory2, sizeof(resourceDirectory2), 1, pe->handle);

        	printf("\n\t%d - Resource Directory:\n", i);
        	printf("\tCurrent Position: %x\n", ftell(pe->handle));
        	printf("\Characteristics: %d\n", resourceDirectory2.Characteristics);
        	printf("\tTimestamp: %d\n", resourceDirectory2.TimeDateStamp);
        	printf("\tMajor Version: %d\n", resourceDirectory2.MajorVersion);
        	printf("\tMinor Version: %d\n", resourceDirectory2.MinorVersion);
        	printf("\tNamed Entries: %d\n", resourceDirectory2.NumberOfNamedEntries);
        	printf("\tId Entries: %d\n", resourceDirectory2.NumberOfIdEntries);

        	for(j = 1, offsetDirectory2 = 0; j <= (resourceDirectory2.NumberOfNamedEntries+resourceDirectory2.NumberOfIdEntries); j++)
        	{
				if(j == 1)
				{
					offsetDirectory2 += 16;
					fseek(pe->handle, (raiz + directoryEntry1.DirectoryData.data.OffsetToDirectory)+offsetDirectory2, SEEK_SET);
				}
				else
				{
					offsetDirectory2 += 8;
					fseek(pe->handle, (raiz + directoryEntry1.DirectoryData.data.OffsetToDirectory)+offsetDirectory2, SEEK_SET);
				}

				printf("\n\t\t%d/%d - Resource directory entry:\n", i, j);
				fread(&directoryEntry2, sizeof(directoryEntry2), 1, pe->handle);
				printf("\t\tPosição atual: %x\n", ftell(pe->handle));
				printf("\t\tName offset: %d\n", directoryEntry2.DirectoryName.name.NameOffset);
				printf("\t\tName is string: %d\n", directoryEntry2.DirectoryName.name.NameIsString);
				printf("\t\tOffset to directory: %x\n", directoryEntry2.DirectoryData.data.OffsetToDirectory);
				printf("\t\tData is directory: %d\n", directoryEntry2.DirectoryData.data.DataIsDirectory);

				fseek(pe->handle, (raiz + directoryEntry2.DirectoryData.data.OffsetToDirectory), SEEK_SET); // posiciona em 0x72
				fread(&resourceDirectory3, sizeof(resourceDirectory3), 1, pe->handle);

				printf("\n\t\t%d/%d - Resource Directory:\n", i, j);
				printf("\t\tCurrent Position: %x\n", ftell(pe->handle));
				printf("\t\Characteristics: %d\n", resourceDirectory3.Characteristics);
				printf("\t\tTimestamp: %d\n", resourceDirectory3.TimeDateStamp);
				printf("\t\tMajor Version: %d\n", resourceDirectory3.MajorVersion);
				printf("\t\tMinor Version: %d\n", resourceDirectory3.MinorVersion);
				printf("\t\tNamed Entries: %d\n", resourceDirectory3.NumberOfNamedEntries);
				printf("\t\tId Entries: %d\n", resourceDirectory3.NumberOfIdEntries);

				for(y = 1; y <= (resourceDirectory3.NumberOfNamedEntries+resourceDirectory3.NumberOfIdEntries); y++)
				{
					printf("\n\t\t\t%d/%d/%d - Resource Directory Entry:\n", i, j, y);
					fread(&directoryEntry3, sizeof(directoryEntry3), 1, pe->handle);
					printf("\t\t\tCurrent Position: %x\n", ftell(pe->handle));
					printf("\t\t\tName offset: %d\n", directoryEntry3.DirectoryName.name.NameOffset);
					printf("\t\t\tName is string: %d\n", directoryEntry3.DirectoryName.name.NameIsString);
					printf("\t\t\tOffset to directory: %x\n", directoryEntry3.DirectoryData.data.OffsetToDirectory);
					printf("\t\t\tData is directory: %d\n", directoryEntry3.DirectoryData.data.DataIsDirectory);

					fseek(pe->handle, (raiz + directoryEntry3.DirectoryName.name.NameOffset), SEEK_SET);
					fread(&DataString, sizeof(DataString), 1, pe->handle);

					fseek(pe->handle, (raiz + directoryEntry3.DirectoryData.data.OffsetToDirectory), SEEK_SET);
					fread(&DataEntry, sizeof(DataEntry), 1, pe->handle);

					printf("\n\t\t\t%d/%d/%d - Read entry/string:\n", i, j, y);
					printf("\t\t\tPosition: %x\n", ftell(pe->handle));
					printf("\t\t\tString len: %d\n", DataString.Length);
					printf("\t\t\tString: %s\n\n", DataString.String);

					printf("\t\t\tOffsetToData: %x\n", DataEntry.OffsetToData);
					printf("\t\t\tSize: %d\n", DataEntry.Size);
					printf("\t\t\tCodePage: %d\n", DataEntry.CodePage);
					printf("\t\t\tReserved: %d\n", DataEntry.Reserved);

					buffer = xmalloc(DataEntry.Size);
					memset(buffer, 0, DataEntry.Size);
					printf("\n\t\t\tPosição: %x\n", ftell(pe->handle));
					offsetData = rva2ofs(pe, DataEntry.OffsetToData);
					fseek(pe->handle, offsetData, SEEK_SET);
					printf("\t\t\tRVA: %x, OFFSET: %x, POSITION: %x", DataEntry.OffsetToData, offsetData, ftell(pe->handle));
					memset(&nomeArquivo, 0, 100);
					if(fread(buffer, DataEntry.Size+1, 1, pe->handle))
					{
						snprintf(&nomeArquivo, 100, "../tests/%d-%d-%d.bin", i, j, y);
						fpSave = fopen(&nomeArquivo, "wb+");
						fwrite(buffer, DataEntry.Size, 1, fpSave);
						fclose(fpSave);
						printf("\n\t\t\tSave on: %s\n", nomeArquivo);
					}
					free(buffer);
				}
			}
        }
	}
}



int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp);

	if (!is_pe(&pe))
		EXIT_ERROR("not a valid PE file");

	rewind(pe.handle);

	pe_get_directories(&pe);

	discovery(&pe);

	pe_deinit(&pe);
	
	return 0;
}

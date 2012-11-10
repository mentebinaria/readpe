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

void showResourceDirectory(IMAGE_RESOURCE_DIRECTORY resourceDirectory)
{
	printf("Characteristics: %d\n", resourceDirectory.Characteristics);
	printf("Timestamp: %d\n", resourceDirectory.TimeDateStamp);
	printf("Major Version: %d\n", resourceDirectory.MajorVersion);
	printf("Minor Version: %d\n", resourceDirectory.MinorVersion);
	printf("Named entries: %d\n", resourceDirectory.NumberOfNamedEntries);
	printf("Id entries: %d\n", resourceDirectory.NumberOfIdEntries);
}

void showDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry)
{
	printf("Name offset: %d\n", directoryEntry.DirectoryName.name.NameOffset);
	printf("Name is string: %d\n", directoryEntry.DirectoryName.name.NameIsString);
	printf("Offset to directory: %x\n", directoryEntry.DirectoryData.data.OffsetToDirectory);
	printf("Data is directory: %d\n", directoryEntry.DirectoryData.data.DataIsDirectory);
}

void showDataString(IMAGE_RESOURCE_DATA_STRING dataString)
{
	printf("String len: %d\n", dataString.length);
	printf("String: %s\n\n", dataString.string);
}

void showDataEntry(IMAGE_RESOURCE_DATA_ENTRY dataEntry)
{
	printf("OffsetToData: %x\n", dataEntry.offsetToData);
	printf("Size: %d\n", dataEntry.size);
	printf("CodePage: %d\n", dataEntry.codePage);
	printf("Reserved: %d\n", dataEntry.reserved);
}

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
	IMAGE_RESOURCE_DATA_STRING dataString;
	IMAGE_RESOURCE_DATA_ENTRY dataEntry;

	printf("Current Position: %x\n", ftell(pe->handle));
	fseek(pe->handle, raiz, SEEK_SET); // posiciona em 0x72
	printf("Current Position: %x\n\n", ftell(pe->handle));
	fread(&resourceDirectory1, sizeof(resourceDirectory1), 1, pe->handle);

	showResourceDirectory(resourceDirectory1);

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

		showDirectoryEntry(directoryEntry1);

        if (directoryEntry1.DirectoryData.data.DataIsDirectory)
        {
        	fseek(pe->handle, (raiz + directoryEntry1.DirectoryData.data.OffsetToDirectory), SEEK_SET);
        	fread(&resourceDirectory2, sizeof(resourceDirectory2), 1, pe->handle);

        	printf("\n\t%d - Resource Directory:\n", i);
        	printf("\tCurrent Position: %x\n", ftell(pe->handle));

        	showResourceDirectory(resourceDirectory2);

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

				showDirectoryEntry(directoryEntry2);

				fseek(pe->handle, (raiz + directoryEntry2.DirectoryData.data.OffsetToDirectory), SEEK_SET); // posiciona em 0x72
				fread(&resourceDirectory3, sizeof(resourceDirectory3), 1, pe->handle);

				printf("\n\t\t%d/%d - Resource Directory:\n", i, j);
				printf("\t\tCurrent Position: %x\n", ftell(pe->handle));

				showResourceDirectory(resourceDirectory3);

				for(y = 1; y <= (resourceDirectory3.NumberOfNamedEntries+resourceDirectory3.NumberOfIdEntries); y++)
				{
					printf("\n\t\t\t%d/%d/%d - Resource Directory Entry:\n", i, j, y);
					fread(&directoryEntry3, sizeof(directoryEntry3), 1, pe->handle);
					printf("\t\t\tCurrent Position: %x\n", ftell(pe->handle));

					showDirectoryEntry(directoryEntry3);

					fseek(pe->handle, (raiz + directoryEntry3.DirectoryName.name.NameOffset), SEEK_SET);
					fread(&dataString, sizeof(dataString), 1, pe->handle);

					fseek(pe->handle, (raiz + directoryEntry3.DirectoryData.data.OffsetToDirectory), SEEK_SET);
					fread(&dataEntry, sizeof(dataEntry), 1, pe->handle);

					printf("\n\t\t\t%d/%d/%d - Read entry/string:\n", i, j, y);
					printf("\t\t\tPosition: %x\n", ftell(pe->handle));

					showDataString(dataString);

					showDataEntry(dataEntry);

					buffer = xmalloc(dataEntry.size);
					memset(buffer, 0, dataEntry.size);
					printf("\n\t\t\tPosição: %x\n", ftell(pe->handle));
					offsetData = rva2ofs(pe, dataEntry.offsetToData);
					fseek(pe->handle, offsetData, SEEK_SET);
					printf("\t\t\tRVA: %x, OFFSET: %x, POSITION: %x", dataEntry.offsetToData, offsetData, ftell(pe->handle));
					memset(&nomeArquivo, 0, 100);
					if(fread(buffer, dataEntry.size+1, 1, pe->handle))
					{
						snprintf(&nomeArquivo, 100, "../tests/%d-%d-%d.bin", i, j, y);
						fpSave = fopen(&nomeArquivo, "wb+");
						fwrite(buffer, dataEntry.size, 1, fpSave);
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

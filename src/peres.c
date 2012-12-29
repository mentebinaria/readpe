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

void showResourceDirectory(IMAGE_RESOURCE_DIRECTORY *resourceDirectory)
{
	char value[MAX_MSG];

	output("\nNode", "Resource Directory");

	snprintf(value, MAX_MSG, "%d", resourceDirectory->Characteristics);
	output("Characteristics", value);

	snprintf(value, MAX_MSG, "%d", resourceDirectory->TimeDateStamp);
	output("Timestamp", value);

	snprintf(value, MAX_MSG, "%d", resourceDirectory->MajorVersion);
	output("Major Version", value);

	snprintf(value, MAX_MSG, "%d", resourceDirectory->MinorVersion);
	output("Minor Version", value);

	snprintf(value, MAX_MSG, "%d", resourceDirectory->NumberOfNamedEntries);
	output("Named entries", value);

	snprintf(value, MAX_MSG, "%d", resourceDirectory->NumberOfIdEntries);
	output("Id entries", value);
}

void showDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry)
{
	char value[MAX_MSG];

	output("\nNode", "Directory Entry");

	snprintf(value, MAX_MSG, "%d", directoryEntry->DirectoryName.name.NameOffset);
	output("Name offset", value);

	snprintf(value, MAX_MSG, "%d", directoryEntry->DirectoryName.name.NameIsString);
	output("Name is string", value);

	snprintf(value, MAX_MSG, "%x", directoryEntry->DirectoryData.data.OffsetToDirectory);
	output("Offset to directory", value);

	snprintf(value, MAX_MSG, "%d", directoryEntry->DirectoryData.data.DataIsDirectory);
	output("Data is directory", value);
}

void showDataString(IMAGE_RESOURCE_DATA_STRING *dataString)
{
	char value[MAX_MSG];

	output("\nNode", "Data String");

	snprintf(value, MAX_MSG, "%d", dataString->length);
	output("String len", value);

	output("String", dataString->string);
}

void showDataEntry(IMAGE_RESOURCE_DATA_ENTRY *dataEntry)
{
	char value[MAX_MSG];

	output("\nNode", "Data Entry");

	snprintf(value, MAX_MSG, "%x", dataEntry->offsetToData);
	output("OffsetToData", value);

	snprintf(value, MAX_MSG, "%d", dataEntry->size);
	output("Size", value);

	snprintf(value, MAX_MSG, "%d", dataEntry->codePage);
	output("CodePage", value);

	snprintf(value, MAX_MSG, "%d", dataEntry->reserved);
	output("Reserved", value);
}

NODE_PERES * createNode(NODE_PERES *currentNode, NODE_TYPE_PERES typeOfNextNode)
{
	currentNode->nextNode = malloc(sizeof(NODE_PERES));
	((NODE_PERES *) currentNode->nextNode)->lastNode = currentNode;
	currentNode = currentNode->nextNode;
	currentNode->nodeType = typeOfNextNode;
	return currentNode;
}

NODE_PERES * lastNodeByType(NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch)
{
	if(currentNode->nodeType == nodeTypeSearch)
		return currentNode;

	while(currentNode->lastNode != NULL)
	{
		currentNode = currentNode->lastNode;
		if(currentNode->nodeType == nodeTypeSearch)
			return currentNode;
	}

	return NULL;
}

NODE_PERES * firstNodeByType(NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch)
{
	NODE_PERES *firstNode = NULL;

	if(currentNode->nodeType == nodeTypeSearch)
		firstNode = currentNode;

	while(currentNode->lastNode != NULL)
	{
		currentNode = currentNode->lastNode;
		if(currentNode->nodeType == nodeTypeSearch)
			firstNode = currentNode;
	}

	return firstNode;
}

NODE_PERES * getNodeByTypeAndLevel(NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch, NODE_LEVEL_PERES nodeLevelSearch)
{
	if(currentNode->nodeType == nodeTypeSearch && currentNode->nodeLevel == nodeLevelSearch)
		return currentNode;

	while(currentNode->lastNode != NULL)
	{
		currentNode = currentNode->lastNode;
		if(currentNode->nodeType == nodeTypeSearch && currentNode->nodeLevel == nodeLevelSearch)
			return currentNode;
	}

	return NULL;
}

void discovery(PE_FILE *pe)
{
	NODE_PERES *nodePeres;
	nodePeres = malloc(sizeof(NODE_PERES));
	nodePeres->lastNode = NULL; // root

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
		//printf("Offset by RVA: 0x%x\n\n", raiz);
	}

	fseek(pe->handle, raiz, SEEK_SET); // posiciona em 0x72

	nodePeres->nodeType = RDT_RESOURCE_DIRECTORY;
	nodePeres->nodeLevel = RDT_LEVEL1;
	fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
	showResourceDirectory((IMAGE_RESOURCE_DIRECTORY *) &nodePeres->node);

	int i, j, y;
	int offsetDirectory1 = 0, offsetDirectory2 = 0;
	unsigned char *buffer;
	QWORD offsetData;
	char nomeArquivo[100];
	FILE *fpSave;

	for(i = 1, offsetDirectory1 = 0; i <= (getNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL1)->node.resourceDirectory.NumberOfNamedEntries +
												getNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL1)->node.resourceDirectory.NumberOfIdEntries); i++)
	{
		if(i == 1)
		{
			offsetDirectory1 += 16;
			fseek(pe->handle, raiz+offsetDirectory1, SEEK_SET);
		}
		else
		{
			offsetDirectory1 += 8;
			fseek(pe->handle, raiz+offsetDirectory1, SEEK_SET);
		}

		nodePeres = createNode(nodePeres, RDT_DIRECTORY_ENTRY);
		nodePeres->nodeLevel = RDT_LEVEL1;
		fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);
		showDirectoryEntry((IMAGE_RESOURCE_DIRECTORY_ENTRY *) &nodePeres->node);

        if (getNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.DataIsDirectory)
        {
        	fseek(pe->handle, (raiz + getNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET);
        	nodePeres = createNode(nodePeres, RDT_RESOURCE_DIRECTORY);
        	nodePeres->nodeLevel = RDT_LEVEL2;
        	fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
        	showResourceDirectory((IMAGE_RESOURCE_DIRECTORY *) &nodePeres->node);

        	for(j = 1, offsetDirectory2 = 0; j <= (getNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL2)->node.resourceDirectory.NumberOfNamedEntries +
        												getNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL2)->node.resourceDirectory.NumberOfIdEntries); j++)
        	{
				if(j == 1)
				{
					offsetDirectory2 += 16;
					fseek(pe->handle, (raiz + getNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory)+offsetDirectory2, SEEK_SET);
				}
				else
				{
					offsetDirectory2 += 8;
					fseek(pe->handle, (raiz + getNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory)+offsetDirectory2, SEEK_SET);
				}

				nodePeres = createNode(nodePeres, RDT_DIRECTORY_ENTRY);
				nodePeres->nodeLevel = RDT_LEVEL2;
				fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);
				showDirectoryEntry((IMAGE_RESOURCE_DIRECTORY_ENTRY *) &nodePeres->node);

				fseek(pe->handle, (raiz + nodePeres->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET); // posiciona em 0x72
				nodePeres = createNode(nodePeres, RDT_RESOURCE_DIRECTORY);
				nodePeres->nodeLevel = RDT_LEVEL3;
				fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
				showResourceDirectory((IMAGE_RESOURCE_DIRECTORY *) &nodePeres->node);

				for(y = 1; y <= (getNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->node.resourceDirectory.NumberOfNamedEntries +
									getNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->node.resourceDirectory.NumberOfIdEntries); y++)
				{
					nodePeres = createNode(nodePeres, RDT_DIRECTORY_ENTRY);
					nodePeres->nodeLevel = RDT_LEVEL3;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);
					showDirectoryEntry((IMAGE_RESOURCE_DIRECTORY_ENTRY *) &nodePeres->node);

					fseek(pe->handle, (raiz + nodePeres->node.directoryEntry.DirectoryName.name.NameOffset), SEEK_SET);
					nodePeres = createNode(nodePeres, RDT_DATA_STRING);
					nodePeres->nodeLevel = RDT_LEVEL3;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DATA_STRING), 1, pe->handle);
					showDataString((IMAGE_RESOURCE_DATA_STRING *) &nodePeres->node);

					fseek(pe->handle, (raiz + ((NODE_PERES *)nodePeres->lastNode)->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET);
					nodePeres = createNode(nodePeres, RDT_DATA_ENTRY);
					nodePeres->nodeLevel = RDT_LEVEL3;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, pe->handle);
					showDataEntry((IMAGE_RESOURCE_DATA_ENTRY *) &nodePeres->node);

					buffer = xmalloc(lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size);
					memset(buffer, 0, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size);
					offsetData = rva2ofs(pe, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.offsetToData);
					fseek(pe->handle, offsetData, SEEK_SET);
					memset(&nomeArquivo, 0, 100);
					if(fread(buffer, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size + 1, 1, pe->handle))
					{
						snprintf(&nomeArquivo, 100, "../tests/%d-%d-%d.bin", i, j, y);
						fpSave = fopen(&nomeArquivo, "wb+");
						fwrite(buffer, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size, 1, fpSave);
						fclose(fpSave);
						printf("\n\t\t\tSave on: %s\n", nomeArquivo);
					}
					free(buffer);
				}
			}
        }
	}
}

int main(int argc, char **argv)
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

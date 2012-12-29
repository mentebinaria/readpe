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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void showNode(NODE_PERES *nodePeres)
{
	char value[MAX_MSG];

	switch(nodePeres->nodeType)
	{
		case RDT_RESOURCE_DIRECTORY:
			snprintf(value, MAX_MSG, "Resource Directory / %lu", nodePeres->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.resourceDirectory.Characteristics);
			output("Characteristics", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.resourceDirectory.TimeDateStamp);
			output("Timestamp", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.resourceDirectory.MajorVersion);
			output("Major Version", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.resourceDirectory.MinorVersion);
			output("Minor Version", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.resourceDirectory.NumberOfNamedEntries);
			output("Named entries", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.resourceDirectory.NumberOfIdEntries);
			output("Id entries", value);
			break;
		case RDT_DIRECTORY_ENTRY:
			snprintf(value, MAX_MSG, "Directory Entry / %lu", nodePeres->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.directoryEntry.DirectoryName.name.NameOffset);
			output("Name offset", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.directoryEntry.DirectoryName.name.NameIsString);
			output("Name is string", value);

			snprintf(value, MAX_MSG, "%x", nodePeres->node.directoryEntry.DirectoryData.data.OffsetToDirectory);
			output("Offset to directory", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.directoryEntry.DirectoryData.data.DataIsDirectory);
			output("Data is directory", value);
			break;
		case RDT_DATA_STRING:
			snprintf(value, MAX_MSG, "Data String / %lu", nodePeres->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.dataString.length);
			output("String len", value);

			output("String", nodePeres->node.dataString.string);

			break;
		case RDT_DATA_ENTRY:
			snprintf(value, MAX_MSG, "Data Entry / %lu", nodePeres->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%x", nodePeres->node.dataEntry.offsetToData);
			output("OffsetToData", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.dataEntry.size);
			output("Size", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.dataEntry.codePage);
			output("CodePage", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.dataEntry.reserved);
			output("Reserved", value);
			break;
		default:
			output("ShowNode", "ERROR - Invalid Node Type");
			break;
	}

}

NODE_PERES * createNode(NODE_PERES *currentNode, NODE_TYPE_PERES typeOfNextNode)
{
	currentNode->nextNode = xmalloc(sizeof(NODE_PERES));
	((NODE_PERES *) currentNode->nextNode)->lastNode = currentNode;
	currentNode = currentNode->nextNode;
	currentNode->nodeType = typeOfNextNode;
	currentNode->nextNode = NULL;
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

NODE_PERES * lastNodeByTypeAndLevel(NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch, NODE_LEVEL_PERES nodeLevelSearch)
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

void freeNodes(NODE_PERES *currentNode)
{
	while(currentNode->nextNode != NULL)
	{
		currentNode = currentNode->nextNode;
	}

	while(currentNode->lastNode != NULL)
	{
		currentNode = currentNode->lastNode;
		//printf("\nfree");
		free(currentNode->nextNode);
	}
	//printf("\nfree");
	free(currentNode);
}

RESOURCE_ENTRY * getResourceEntryByNameOffset(DWORD nameOffset)
{
	int i;
	for(i = 0; i < (sizeof(resourceTypes)/sizeof(RESOURCE_ENTRY)); i++)
	{
		if(resourceTypes[i].nameOffset == nameOffset)
			return &resourceTypes[i];
	}

	return NULL;
}

void saveResource(PE_FILE *pe, NODE_PERES *nodePeres, int count)
{
	FILE *fpSave;
	unsigned char *buffer;
	char dirName[100];
	char fileName[100];
	DWORD nameOffset;
	QWORD offsetData;
	struct stat statDir = {0};

	buffer = xmalloc(lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size);
	memset(buffer, 0, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size);
	offsetData = rva2ofs(pe, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.offsetToData);
	fseek(pe->handle, offsetData, SEEK_SET);
	memset(&fileName, 0, 100);
	memset(&dirName, 0, 100);
	nameOffset = ((NODE_PERES *)nodePeres->rootNode)->node.directoryEntry.DirectoryName.name.NameOffset;
	if(fread(buffer, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size + 1, 1, pe->handle))
	{
		if (stat(RESOURCE_DIR, &statDir) == -1)
			mkdir(RESOURCE_DIR, 0700);

		snprintf(&dirName, 100, "%s/%s", RESOURCE_DIR, getResourceEntryByNameOffset(nameOffset)->dirName);

		if (stat(dirName, &statDir) == -1)
			mkdir(dirName, 0700);

		if(getResourceEntryByNameOffset(nameOffset) != NULL)
			snprintf(&fileName, 100, "%s/%d%s", dirName, count, getResourceEntryByNameOffset(nameOffset)->extension);
		else
			snprintf(&fileName, 100, "%s/%d.bin", dirName, count);

		fpSave = fopen(&fileName, "wb+");
		fwrite(buffer, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size, 1, fpSave);
		fclose(fpSave);
		printf("Save on: %s\n", fileName);
		count++;
	}
	free(buffer);

}

void extractResources(PE_FILE *pe, NODE_PERES *nodePeres)
{
	int count = 1;

	while(nodePeres->lastNode != NULL)
	{
		nodePeres = nodePeres->lastNode;
	}

	while(nodePeres->nextNode != NULL)
	{
		if(nodePeres->nodeType != RDT_DATA_ENTRY)
		{
			nodePeres = nodePeres->nextNode;
			continue;
		}
		saveResource(pe, nodePeres, count);
		nodePeres = nodePeres->nextNode;
		count++;
	}

	saveResource(pe, nodePeres, count); // save last
}

NODE_PERES * discoveryNodesPeres(PE_FILE *pe)
{
	NODE_PERES *nodePeres;
	NODE_PERES *rootNodePeres;

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
		return NULL;

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

	nodePeres = xmalloc(sizeof(NODE_PERES));
	nodePeres->lastNode = NULL; // root
	nodePeres->nodeType = RDT_RESOURCE_DIRECTORY;
	nodePeres->nodeLevel = RDT_LEVEL1;
	fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
	showNode(nodePeres);

	int i, j, y;
	int offsetDirectory1 = 0, offsetDirectory2 = 0;
	for(i = 1, offsetDirectory1 = 0; i <= (lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL1)->node.resourceDirectory.NumberOfNamedEntries +
												lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL1)->node.resourceDirectory.NumberOfIdEntries); i++)
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
		rootNodePeres = nodePeres;
		nodePeres->nodeLevel = RDT_LEVEL1;
		nodePeres->rootNode = rootNodePeres;
		fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);

		showNode(nodePeres);
        if (lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.DataIsDirectory)
        {
        	fseek(pe->handle, (raiz + lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET);
        	nodePeres = createNode(nodePeres, RDT_RESOURCE_DIRECTORY);
        	nodePeres->nodeLevel = RDT_LEVEL2;
        	nodePeres->rootNode = lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1);
        	fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
        	showNode(nodePeres);

        	for(j = 1, offsetDirectory2 = 0; j <= (lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL2)->node.resourceDirectory.NumberOfNamedEntries +
        			lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL2)->node.resourceDirectory.NumberOfIdEntries); j++)
        	{
				if(j == 1)
				{
					offsetDirectory2 += 16;
					fseek(pe->handle, (raiz + lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory)+offsetDirectory2, SEEK_SET);
				}
				else
				{
					offsetDirectory2 += 8;
					fseek(pe->handle, (raiz + lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory)+offsetDirectory2, SEEK_SET);
				}

				nodePeres = createNode(nodePeres, RDT_DIRECTORY_ENTRY);
				nodePeres->nodeLevel = RDT_LEVEL2;
				nodePeres->rootNode = rootNodePeres;
				fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);
				showNode(nodePeres);

				fseek(pe->handle, (raiz + nodePeres->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET); // posiciona em 0x72
				nodePeres = createNode(nodePeres, RDT_RESOURCE_DIRECTORY);
				nodePeres->nodeLevel = RDT_LEVEL3;
				nodePeres->rootNode = rootNodePeres;
				fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
				showNode(nodePeres);

				for(y = 1; y <= (lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->node.resourceDirectory.NumberOfNamedEntries +
									lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->node.resourceDirectory.NumberOfIdEntries); y++)
				{
					nodePeres = createNode(nodePeres, RDT_DIRECTORY_ENTRY);
					nodePeres->nodeLevel = RDT_LEVEL3;
					nodePeres->rootNode = rootNodePeres;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);
					showNode(nodePeres);

					fseek(pe->handle, (raiz + nodePeres->node.directoryEntry.DirectoryName.name.NameOffset), SEEK_SET);
					nodePeres = createNode(nodePeres, RDT_DATA_STRING);
					nodePeres->nodeLevel = RDT_LEVEL3;
					nodePeres->rootNode = rootNodePeres;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DATA_STRING), 1, pe->handle);
					showNode(nodePeres);

					fseek(pe->handle, (raiz + ((NODE_PERES *)nodePeres->lastNode)->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET);
					nodePeres = createNode(nodePeres, RDT_DATA_ENTRY);
					nodePeres->nodeLevel = RDT_LEVEL3;
					nodePeres->rootNode = rootNodePeres;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, pe->handle);
					showNode(nodePeres);
				}
			}
        }
	}
	return nodePeres;
}

int main(int argc, char **argv)
{
	PE_FILE pe;
	FILE *fp = NULL;
	NODE_PERES *nodePeres;

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp);

	if (!is_pe(&pe))
		EXIT_ERROR("not a valid PE file");

	rewind(pe.handle);

	pe_get_directories(&pe);

	nodePeres = discoveryNodesPeres(&pe);
	extractResources(&pe, nodePeres);
	freeNodes(nodePeres);

	pe_deinit(&pe);
	
	return 0;
}

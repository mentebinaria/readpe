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

static int ind;

static void usage()
{
	printf("Usage: %s OPTIONS FILE\n"
	"Show information about resource section and extract it\n"
	"\nExample: %s -a putty.exe\n"
	"\nOptions:\n"
	" -a, --all					Show all information, statistics and extract resources\n"
	" -x, --extract					Extract resources\n"
	" -i, --info					Show informations\n"
	" -s, --statistics				Show statistics\n"
	" -v, --version					Show version and exit\n"
	" --help						Show this help and exit\n",
	PROGRAM, PROGRAM);
}

static void parse_options(int argc, char **argv)
{
	int c;
	static const char short_options[] = "a:x:i:s:v";

	static const struct option long_options[] = {

		{"all",              required_argument, NULL, 'a'},
		{"extract",       	 no_argument,       NULL, 'x'},
		{"info",             no_argument, 		NULL, 'i'},
		{"statistics",       no_argument, 		NULL, 's'},
		{"version",          no_argument,       NULL, 'v'},
		{"help",             no_argument,       NULL,  1 },
		{ NULL,              0,                 NULL,  0 }
	};

	//memset(&config, false, sizeof(config));

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 'a':
				config.all = true;
				break;
			case 'x':
				config.extract = true;
				break;
			case 'i':
				config.info = true;
				break;
			case 's':
				config.statistics = true;
				break;
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 1:
				usage();
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

void showNode(NODE_PERES *nodePeres)
{
	char value[MAX_MSG];

	switch(nodePeres->nodeType)
	{
		case RDT_RESOURCE_DIRECTORY:
			snprintf(value, MAX_MSG, "Resource Directory / %d", nodePeres->nodeLevel);
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
			snprintf(value, MAX_MSG, "Directory Entry / %d", nodePeres->nodeLevel);
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
			snprintf(value, MAX_MSG, "Data String / %d", nodePeres->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", nodePeres->node.dataString.length);
			output("String len", value);

			snprintf(value, MAX_MSG, "%d", (int) nodePeres->node.dataString.string);
			output("String", value);

			break;
		case RDT_DATA_ENTRY:
			snprintf(value, MAX_MSG, "Data Entry / %d", nodePeres->nodeLevel);
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
	currentNode = (NODE_PERES *) currentNode->nextNode;
	currentNode->nodeType = typeOfNextNode;
	currentNode->nextNode = NULL;
	return currentNode;
}

NODE_PERES * lastNodeByType(NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch)
{
	if(currentNode->nodeType == nodeTypeSearch)
		return currentNode;

	while(currentNode != NULL)
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

	while(currentNode != NULL)
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

	while(currentNode != NULL)
	{
		currentNode = currentNode->lastNode;
		if(currentNode->nodeType == nodeTypeSearch && currentNode->nodeLevel == nodeLevelSearch)
			return currentNode;
	}

	return NULL;
}

void freeNodes(NODE_PERES *currentNode)
{
	if(currentNode == NULL)
		return;

	while(currentNode->nextNode != NULL)
	{
		currentNode = currentNode->nextNode;
	}

	while(currentNode != NULL)
	{
		currentNode = currentNode->lastNode;

		if(currentNode == NULL)
		{
			free(currentNode);
			break;
		}

		if(currentNode->nextNode != NULL)
			free(currentNode->nextNode);
	}
}

RESOURCE_ENTRY * getResourceEntryByNameOffset(DWORD nameOffset)
{
	unsigned int i;
	for(i = 0; i < (sizeof(resourceTypes)/sizeof(RESOURCE_ENTRY)); i++)
	{
		if(resourceTypes[i].nameOffset == nameOffset)
			return (RESOURCE_ENTRY *)&resourceTypes[i];
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
		if (stat(resourceDir, &statDir) == -1)
			mkdir(resourceDir, 0700);

		snprintf(&dirName, 100, "%s/%s", resourceDir, getResourceEntryByNameOffset(nameOffset)->dirName);

		if (stat(dirName, &statDir) == -1)
			mkdir(dirName, 0700);

		if(getResourceEntryByNameOffset(nameOffset) != NULL)
			snprintf(&fileName, 100, "%s/%d%s", dirName, count, getResourceEntryByNameOffset(nameOffset)->extension);
		else
			snprintf(&fileName, 100, "%s/%d.bin", dirName, count);

		fpSave = fopen(&fileName, "wb+");
		fwrite(buffer, lastNodeByType(nodePeres, RDT_DATA_ENTRY)->node.dataEntry.size, 1, fpSave);
		fclose(fpSave);
		output("Save On", fileName);
		count++;
	}
	free(buffer);

}

void extractResources(PE_FILE *pe, NODE_PERES *nodePeres)
{
	int count = 0;

	while(nodePeres->lastNode != NULL)
	{
		nodePeres = nodePeres->lastNode;
	}

	output("!SAVE RESOURCES!", NULL);

	while(nodePeres != NULL)
	{
		if(nodePeres->nodeType != RDT_DATA_ENTRY)
		{
			nodePeres = nodePeres->nextNode;
			continue;
		}
		count++;
		saveResource(pe, nodePeres, count);
		nodePeres = nodePeres->nextNode;
	}
}

void showInformations(NODE_PERES *nodePeres)
{
	while(nodePeres->lastNode != NULL)
	{
		nodePeres = nodePeres->lastNode;
	}

	output("!SHOW INFORMATIONS!", NULL);

	while(nodePeres != NULL)
	{
		showNode(nodePeres);
		nodePeres = nodePeres->nextNode;
	}
}

void showStatistics(NODE_PERES *nodePeres)
{
	char value[MAX_MSG];
	int totalCount = 0;
	int totalResourceDirectory = 0;
	int totalDirectoryEntry = 0;
	int totalDataString = 0;
	int totalDataEntry = 0;

	while(nodePeres->lastNode != NULL)
	{
		nodePeres = nodePeres->lastNode;
	}

	output("!SHOW STATISTICS!", NULL);

	while(nodePeres != NULL)
	{
		totalCount++;
		switch(nodePeres->nodeType)
		{
			case RDT_RESOURCE_DIRECTORY:
				totalResourceDirectory++;
				break;
			case RDT_DIRECTORY_ENTRY:
				totalDirectoryEntry++;
				break;
			case RDT_DATA_STRING:
				totalDataString++;
				break;
			case RDT_DATA_ENTRY:
				totalDataEntry++;
				break;
		}
		nodePeres = nodePeres->nextNode;
	}

	snprintf(value, MAX_MSG, "%d", totalCount);
	output("Total Structs", value);

	snprintf(value, MAX_MSG, "%d", totalResourceDirectory);
	output("Total Resource Directory", value);

	snprintf(value, MAX_MSG, "%d", totalDirectoryEntry);
	output("Total Directory Entry", value);

	snprintf(value, MAX_MSG, "%d", totalDataString);
	output("Total Data String", value);

	snprintf(value, MAX_MSG, "%d", totalDataEntry);
	output("Total Data Entry", value);
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
	//showNode(nodePeres);

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

		//showNode(nodePeres);
        if (lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.DataIsDirectory)
        {
        	fseek(pe->handle, (raiz + lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET);
        	nodePeres = createNode(nodePeres, RDT_RESOURCE_DIRECTORY);
        	nodePeres->nodeLevel = RDT_LEVEL2;
        	nodePeres->rootNode = lastNodeByTypeAndLevel(nodePeres, RDT_DIRECTORY_ENTRY, RDT_LEVEL1);
        	fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
        	//showNode(nodePeres);

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
				//showNode(nodePeres);

				fseek(pe->handle, (raiz + nodePeres->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET); // posiciona em 0x72
				nodePeres = createNode(nodePeres, RDT_RESOURCE_DIRECTORY);
				nodePeres->nodeLevel = RDT_LEVEL3;
				nodePeres->rootNode = rootNodePeres;
				fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pe->handle);
				//showNode(nodePeres);

				for(y = 1; y <= (lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->node.resourceDirectory.NumberOfNamedEntries +
									lastNodeByTypeAndLevel(nodePeres, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->node.resourceDirectory.NumberOfIdEntries); y++)
				{
					nodePeres = createNode(nodePeres, RDT_DIRECTORY_ENTRY);
					nodePeres->nodeLevel = RDT_LEVEL3;
					nodePeres->rootNode = rootNodePeres;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pe->handle);
					//showNode(nodePeres);

					fseek(pe->handle, (raiz + nodePeres->node.directoryEntry.DirectoryName.name.NameOffset), SEEK_SET);
					nodePeres = createNode(nodePeres, RDT_DATA_STRING);
					nodePeres->nodeLevel = RDT_LEVEL3;
					nodePeres->rootNode = rootNodePeres;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DATA_STRING), 1, pe->handle);
					//showNode(nodePeres);

					fseek(pe->handle, (raiz + ((NODE_PERES *)nodePeres->lastNode)->node.directoryEntry.DirectoryData.data.OffsetToDirectory), SEEK_SET);
					nodePeres = createNode(nodePeres, RDT_DATA_ENTRY);
					nodePeres->nodeLevel = RDT_LEVEL3;
					nodePeres->rootNode = rootNodePeres;
					fread(&nodePeres->node, sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, pe->handle);
					//showNode(nodePeres);
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

	if (argc < 3)
	{
		usage();
		exit(EXIT_FAILURE);
	}

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp);

	if (!is_pe(&pe))
		EXIT_ERROR("not a valid PE file");

	rewind(pe.handle);

	pe_get_directories(&pe);

	nodePeres = discoveryNodesPeres(&pe);

	if(config.all)
	{
		showInformations(nodePeres);
		showStatistics(nodePeres);
		extractResources(&pe, nodePeres);
	}
	else
	{
		if(config.extract)
			extractResources(&pe, nodePeres);

		if(config.info)
			showInformations(nodePeres);

		if(config.statistics)
			showStatistics(nodePeres);
	}

	freeNodes(nodePeres);
	pe_deinit(&pe);
	return 0;
}

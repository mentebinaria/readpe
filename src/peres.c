/*
	pev - the PE file analyzer toolkit

	peres.c - retrive informations and binary data of resources

	Copyright (C) 2012 - 2017 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	In addition, as a special exception, the copyright holders give
	permission to link the code of portions of this program with the
	OpenSSL library under certain conditions as described in each
	individual source file, and distribute linked combinations
	including the two.
	
	You must obey the GNU General Public License in all respects
	for all of the code used other than OpenSSL.  If you modify
	file(s) with this exception, you may extend this exception to your
	version of the file(s), but you are not obligated to do so.  If you
	do not wish to do so, delete this exception statement from your
	version.  If you delete this exception statement from all source
	files in the program, then also delete it here.
*/

#include "common.h"
#include <string.h>

#define PROGRAM "peres"

static const RESOURCE_ENTRY resource_types[] = {
	{ "RT_CURSOR",			1, ".cur",		"cursors"		},
	{ "RT_BITMAP",			2, ".bmp",		"bitmaps"		},
	{ "RT_ICON",			3, ".ico",		"icons"			},
	{ "RT_MENU",			4, ".rc",		"menus"			},
	{ "RT_DIALOG",			5, ".dlg",		"dialogs"		},
	{ "RT_STRING",			6, ".rc",		"strings"		},
	{ "RT_FONTDIR",			7, ".fnt",		"fontdirs"		},
	{ "RT_FONT",			8, ".fnt",		"fonts"			},
	{ "RT_ACCELERATOR",		9, ".rc",		"accelerators"	},
	{ "RT_RCDATA",			10, ".rc",		"rcdatas"		},
	{ "RT_MESSAGETABLE",	11, ".mc",		"messagetables"	},
	{ "RT_GROUP_CURSOR",	12, ".cur",		"groupcursors"	},
	{ "RT_GROUP_ICON",		14, ".ico",		"groupicons"	},
	{ "RT_VERSION",			16, ".rc",		"versions"		},
	{ "RT_DLGINCLUDE",		17, ".rc",		"dlgincludes"	},
	{ "RT_PLUGPLAY",		19, ".rc",		"plugplays"		},
	{ "RT_VXD",				20, ".rc",		"xvds"			},
	{ "RT_ANICURSOR",		21, ".rc",		"anicursors"	},
	{ "RT_ANIICON",			22, ".rc",		"aniicons"		},
	{ "RT_HTML",			23, ".html",	"htmls"			},
	{ "RT_MANIFEST",		24, ".xml",		"manifests"		},
	{ "RT_DLGINIT",			240, ".rc",		"dlginits"		},
	{ "RT_TOOLBAR",			241, ".rc",		"toolbars"		}
};

const char *resourceDir = "resources";

#include "../lib/libudis86/udis86.h"
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
	bool all;
	bool extract;
	bool namedExtract;
	bool info;
	bool statistics;
	bool list;
	bool version;
	bool help;
} options_t;

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s OPTIONS FILE\n"
		"Show information about resource section and extract it\n"
		"\nExample: %s -a putty.exe\n"
		"\nOptions:\n"
		" -a, --all                              Show all information, statistics and extract resources\n"
		" -f, --format <%s> Change output format (default: text)\n"
		" -i, --info                             Show resources information\n"
		" -l, --list                             Show list view\n"
		" -s, --statistics                       Show resources statistics\n"
		" -x, --extract                          Extract resources\n"
		" -X, --named-extract                    Extract resources with path names\n"
		" -v, --file-version                     Show File Version from PE resource directory\n"
		" -V, --version                          Show version and exit\n"
		" --help                                 Show this help and exit\n",
		PROGRAM, PROGRAM, formats);
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	/* Parameters for getopt_long() function */
	static const char short_options[] = "a:f:ilsxXvV";

	static const struct option long_options[] = {
		{ "all",            required_argument,  NULL, 'a' },
		{ "format",         required_argument,  NULL, 'f' },
		{ "info",           no_argument,        NULL, 'i' },
		{ "list",           no_argument,        NULL, 'l' },
		{ "statistics",	    no_argument,        NULL, 's' },
		{ "extract",	    no_argument,        NULL, 'x' },
		{ "named-extract",  no_argument,        NULL, 'X' },
		{ "file-version",   no_argument,        NULL, 'v' },
		{ "version",	    no_argument,        NULL, 'V' },
		{ "help",           no_argument,        NULL,  1  },
		{ NULL,             0,                  NULL,  0  }
		};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 'a':
				options->all = true;
				break;
			case 'f':
				if (output_set_format_by_name(optarg) < 0)
					EXIT_ERROR("invalid format option");
				break;
			case 'i':
				options->info = true;
				break;
			case 'l':
				options->list = true;
				break;
			case 's':
				options->statistics = true;
				break;
			case 'x':
				options->extract = true;
				break;
			case 'X':
				options->extract = true;
				options->namedExtract = true;
				break;
			case 'v':
				options->version = true;
				break;
			case 'V':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 1: // --help option
				usage();
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	return options;
}

static void widecharToASCII(const char *ascii, const char *widechar, const uint16_t length){
	// quick & dirty UFT16 to ASCII conversion
	for (uint16_t p = 0; p <= length; p += 1){
		memcpy(ascii + p, (uint16_t*)(widechar) + p, 1);
	}
}

static void showNode(const NODE_PERES *node)
{
	char value[MAX_MSG];

	switch (node->nodeType)
	{
		default:
			output("ShowNode", "ERROR - Invalid Node Type");
			break;
		case RDT_RESOURCE_DIRECTORY:
		{
			const IMAGE_RESOURCE_DIRECTORY * const resourceDirectory = node->resource.resourceDirectory;

			snprintf(value, MAX_MSG, "Resource Directory / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

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
			break;
		}
		case RDT_DIRECTORY_ENTRY:
		{
			const IMAGE_RESOURCE_DIRECTORY_ENTRY * const directoryEntry = node->resource.directoryEntry;

			snprintf(value, MAX_MSG, "Directory Entry / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", directoryEntry->DirectoryName.name.NameOffset);
			output("Name offset", value);

			snprintf(value, MAX_MSG, "%d", directoryEntry->DirectoryName.name.NameIsString);
			output("Name is string", value);

			snprintf(value, MAX_MSG, "%x", directoryEntry->DirectoryData.data.OffsetToDirectory);
			output("Offset to directory", value);

			snprintf(value, MAX_MSG, "%d", directoryEntry->DirectoryData.data.DataIsDirectory);
			output("Data is directory", value);
			break;
		}
		case RDT_DATA_STRING:
		{
			const IMAGE_RESOURCE_DATA_STRING * const dataString = node->resource.dataString;
            const char name[MAX_PATH];

			snprintf(value, MAX_MSG, "Data String / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", dataString->length);
			output("String len", value);

			uint16_t stringSize = dataString->length;
			if (stringSize + 1 > MAX_PATH){
				stringSize = MAX_PATH - 1;
			}
			widecharToASCII(name, dataString->string, stringSize);
			strncpy(name + stringSize, "\0", 2);
			snprintf(value, MAX_MSG, "%s", name);
			output("String", value);
			break;
		}
		case RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY * const dataEntry = node->resource.dataEntry;

			snprintf(value, MAX_MSG, "Data Entry / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%x", dataEntry->offsetToData);
			output("OffsetToData", value);

			snprintf(value, MAX_MSG, "%d", dataEntry->size);
			output("Size", value);

			snprintf(value, MAX_MSG, "%d", dataEntry->codePage);
			output("CodePage", value);

			snprintf(value, MAX_MSG, "%d", dataEntry->reserved);
			output("Reserved", value);
			break;
		}
	}
}

static void freeNodes(NODE_PERES *currentNode)
{
	if (currentNode == NULL)
		return;

	while (currentNode->nextNode != NULL) {
		currentNode = currentNode->nextNode;
	}

	while (currentNode != NULL) {
		if (currentNode->lastNode == NULL) {
			free(currentNode);
			break;
		} else {
			currentNode = currentNode->lastNode;
			if (currentNode->nextNode != NULL)
				free(currentNode->nextNode);
		}
	}
}

static NODE_PERES * createNode(NODE_PERES *currentNode, NODE_TYPE_PERES typeOfNextNode)
{
	assert(currentNode != NULL);
	NODE_PERES *newNode = malloc_s(sizeof(NODE_PERES));
	memset(newNode, 0, sizeof(*newNode));
	newNode->lastNode = currentNode;
	newNode->nextNode = NULL;
	newNode->nodeType = typeOfNextNode;
	currentNode->nextNode = newNode;
	return newNode;
}

static const NODE_PERES * lastNodeByType(const NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch)
{
	assert(currentNode != NULL);
	if (currentNode->nodeType == nodeTypeSearch)
		return currentNode;

	while (currentNode != NULL) {
		currentNode = currentNode->lastNode;
		if (currentNode != NULL && currentNode->nodeType == nodeTypeSearch)
			return currentNode;
	}

	return NULL;
}

/*
static const NODE_PERES * firstNodeByType(const NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch)
{
	assert(currentNode != NULL);
	const NODE_PERES *firstNode = NULL;

	if (currentNode->nodeType == nodeTypeSearch)
		firstNode = currentNode;

	while (currentNode != NULL) {
		currentNode = currentNode->lastNode;
		if (currentNode != NULL && currentNode->nodeType == nodeTypeSearch)
			firstNode = currentNode;
	}

	return firstNode;
}
*/

static const NODE_PERES * lastNodeByTypeAndLevel(const NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch, NODE_LEVEL_PERES nodeLevelSearch)
{
	assert(currentNode != NULL);
	if (currentNode->nodeType == nodeTypeSearch && currentNode->nodeLevel == nodeLevelSearch)
		return currentNode;

	while (currentNode != NULL) {
		currentNode = currentNode->lastNode;
		if (currentNode != NULL && currentNode->nodeType == nodeTypeSearch && currentNode->nodeLevel == nodeLevelSearch)
			return currentNode;
	}

	return NULL;
}

static const RESOURCE_ENTRY * getResourceEntryByNameOffset(uint32_t nameOffset)
{
	for (size_t i = 0; i < LIBPE_SIZEOF_ARRAY(resource_types); i++) {
		if (resource_types[i].nameOffset == nameOffset)
			return &resource_types[i];
	}

	return NULL;
}

static void getPath(const pe_ctx_t *ctx, const NODE_PERES *node, char* path){

	for (int level = RDT_LEVEL1; level <= node->nodeLevel; level++) {
		const char name[MAX_PATH];

		const NODE_PERES *parent = lastNodeByTypeAndLevel(node, RDT_DIRECTORY_ENTRY, level);
		if (parent->resource.directoryEntry->DirectoryName.name.NameIsString) {

			const IMAGE_DATA_DIRECTORY * const resourceDirectory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE);
			if (resourceDirectory == NULL || resourceDirectory->Size == 0)
				return;

			const uint64_t offsetString = pe_rva2ofs(ctx, resourceDirectory->VirtualAddress + parent->resource.directoryEntry->DirectoryName.name.NameOffset);
			const IMAGE_RESOURCE_DATA_STRING *ptr = LIBPE_PTR_ADD(ctx->map_addr, offsetString);

			if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
				// TODO: Should we report something?
				return;
			}
			uint16_t stringSize = ptr->length;
			if (stringSize + 2 > MAX_PATH){
				stringSize = MAX_PATH -2;
			}
			widecharToASCII(name, ptr->string, stringSize);
			strncpy(name + stringSize, " \0", 2);
		}
		else {
			const RESOURCE_ENTRY *resourceEntry;
			if (level == RDT_LEVEL1 && (resourceEntry = getResourceEntryByNameOffset(parent->resource.directoryEntry->DirectoryName.name.NameOffset))) {
				snprintf(name, MAX_PATH, "%s ", resourceEntry->name);
			} else {
				snprintf(name, MAX_PATH, "%04x ", parent->resource.directoryEntry->DirectoryName.name.NameOffset);
			}
		}
		strncat(path, name, MAX_PATH - strlen(path));
	}
	path[strlen(path)-1] = 0;
}

static void printPathAndSize(const pe_ctx_t *ctx, const NODE_PERES *node)
{
	char path[MAX_PATH];
	path[0] = 0;		// clear String

	assert(node->nodeType == RDT_DATA_ENTRY);
	
	getPath(ctx, node, path);

	printf("%s (%d bytes)\n", path, node->resource.dataEntry->size);

}

static void showList(const pe_ctx_t *ctx, const NODE_PERES *node)
{
	assert(node != NULL);
	
	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		if (node->nodeType == RDT_DATA_ENTRY) {
			printPathAndSize(ctx, node);
		}
		node = node->nextNode;
	}

}

static void saveResource(pe_ctx_t *ctx, const NODE_PERES *node, bool namedExtract)
{
	assert(node != NULL);
	const NODE_PERES *dataEntryNode = lastNodeByType(node, RDT_DATA_ENTRY);
	if (dataEntryNode == NULL)
		return;

	const uint64_t offsetData = pe_rva2ofs(ctx, dataEntryNode->resource.dataEntry->offsetToData);
	const size_t dataEntrySize = dataEntryNode->resource.dataEntry->size;
	const char *buffer = LIBPE_PTR_ADD(ctx->map_addr, offsetData);
	if (!pe_can_read(ctx, buffer, dataEntrySize)) {
		// TODO: Should we report something?
		return;
	}

	struct stat statDir;
	if (stat(resourceDir, &statDir) == -1)
		mkdir(resourceDir, 0700);

	char dirName[100];
	memset(dirName, 0, sizeof(dirName));

	uint32_t nameOffset = node->rootNode->resource.directoryEntry->DirectoryName.name.NameOffset;
	const RESOURCE_ENTRY *resourceEntry = getResourceEntryByNameOffset(nameOffset);

	if (resourceEntry != NULL) {
		snprintf(dirName, sizeof(dirName), "%s/%s", resourceDir, resourceEntry->dirName);
	} else {
		snprintf(dirName, sizeof(dirName), "%s", resourceDir);
	}

	// TODO(jweyrich): Would it make sense to hardcode `RDT_LEVEL2` rather than use `node->nodeLevel-1` ?
	const NODE_PERES *nameNode = lastNodeByTypeAndLevel(node, RDT_DIRECTORY_ENTRY, node->nodeLevel - 1);
	//fprintf(stderr, "DEBUG: %d\n", nameNode->resource.directoryEntry->DirectoryName.name.NameOffset);

	if (stat(dirName, &statDir) == -1)
		mkdir(dirName, 0700);

	char relativeFileName[MAX_PATH + 105];
	memset(relativeFileName, 0, sizeof(relativeFileName));

	if(namedExtract){
		char fileName[MAX_PATH];
		memset(fileName, 0, sizeof(fileName));

		getPath(ctx, node, fileName),
		snprintf(relativeFileName, sizeof(relativeFileName), "%s/%s%s",
			dirName,
			fileName,
			resourceEntry != NULL ? resourceEntry->extension : ".bin");
	} else {
		snprintf(relativeFileName, sizeof(relativeFileName), "%s/" "%" PRIu32 "%s",
			dirName,
			nameNode->resource.directoryEntry->DirectoryName.name.NameOffset,
			resourceEntry != NULL ? resourceEntry->extension : ".bin");
	}

	FILE *fp = fopen(relativeFileName, "wb+");
	if (fp == NULL) {
		// TODO: Should we report something?
		return;
	}
	fwrite(buffer, dataEntrySize, 1, fp);
	fclose(fp);
	output("Save On", relativeFileName);
}

static void extractResources(pe_ctx_t *ctx, const NODE_PERES *node, bool namedExtract)
{
	assert(node != NULL);
	int count = 0;

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		if (node->nodeType != RDT_DATA_ENTRY) {
			node = node->nextNode;
			continue;
		}
		count++;
		saveResource(ctx, node, namedExtract);
		node = node->nextNode;
	}
}

static void showVersion(pe_ctx_t *ctx, const NODE_PERES *node)
{
	assert(node != NULL);

	int count = 0;
	const NODE_PERES *dataEntryNode;
	uint32_t nameOffset;
	bool found = false;

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		if (node->nodeType != RDT_DATA_ENTRY) {
			node = node->nextNode;
			continue;
		}
		count++;
		//if (count==19)
		dataEntryNode = lastNodeByType(node, RDT_DATA_ENTRY);
		if (dataEntryNode == NULL)
			return;
		nameOffset = node->rootNode->resource.directoryEntry->DirectoryName.name.NameOffset;
		if (nameOffset == 16) {
			found = true;
			break;
		}
		node = node->nextNode;
	}

	if (!found)
		return;
	
	const uint64_t offsetData = pe_rva2ofs(ctx, dataEntryNode->resource.dataEntry->offsetToData);
	const size_t dataEntrySize = dataEntryNode->resource.dataEntry->size;
	const char *buffer = LIBPE_PTR_ADD(ctx->map_addr, 32 + offsetData);
	if (!pe_can_read(ctx, buffer, dataEntrySize)) {
		// TODO: Should we report something?
		return;
	}

	VS_FIXEDFILEINFO *info = (VS_FIXEDFILEINFO *) buffer;
	char value[MAX_MSG];

	//snprintf(value, MAX_MSG, "%d", totalCount);
	
	
	snprintf(value, MAX_MSG, "%u.%u.%u.%u",
	(unsigned int)(info->dwProductVersionMS & 0xffff0000) >> 16,
	(unsigned int)info->dwProductVersionMS & 0x0000ffff,
	(unsigned int)(info->dwProductVersionLS & 0xffff0000) >> 16,
	(unsigned int)info->dwProductVersionLS & 0x0000ffff);

	output("File Version", value);

}

static void showInformations(const NODE_PERES *node)
{
	assert(node != NULL);

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		showNode(node);
		node = node->nextNode;
	}
}

static void showStatistics(const NODE_PERES *node)
{
	assert(node != NULL);

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	int totalCount = 0;
	int totalResourceDirectory = 0;
	int totalDirectoryEntry = 0;
	int totalDataString = 0;
	int totalDataEntry = 0;

	while (node != NULL) {
		totalCount++;
		switch (node->nodeType) {
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
		node = node->nextNode;
	}

	char value[MAX_MSG];

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

static NODE_PERES * discoveryNodesPeres(pe_ctx_t *ctx)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
	typedef struct {
		ImageDirectoryEntry entry;
		const char * const name;
	} ImageDirectoryEntryName;
	static const ImageDirectoryEntryName directoryEntryNames[] = {
		{ IMAGE_DIRECTORY_ENTRY_EXPORT,			"Export Table"				}, // "Export directory",
		{ IMAGE_DIRECTORY_ENTRY_IMPORT,			"Import Table"				}, // "Import directory",
		{ IMAGE_DIRECTORY_ENTRY_RESOURCE,		"Resource Table"			}, // "Resource directory",
		{ IMAGE_DIRECTORY_ENTRY_EXCEPTION,		"Exception Table"			}, // "Exception directory",
		{ IMAGE_DIRECTORY_ENTRY_SECURITY,		"Certificate Table"			}, // "Security directory",
		{ IMAGE_DIRECTORY_ENTRY_BASERELOC,		"Base Relocation Table"		}, // "Base relocation table",
		{ IMAGE_DIRECTORY_ENTRY_DEBUG,			"Debug"						}, // "Debug directory",
		{ IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,	"Architecture"				}, // "Architecture-specific data",
		{ IMAGE_DIRECTORY_ENTRY_GLOBALPTR,		"Global Ptr"				}, // "Global pointer",
		{ IMAGE_DIRECTORY_ENTRY_TLS,			"Thread Local Storage (TLS)"}, // "Thread local storage (TLS) directory",
		{ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,	"Load Config Table"			}, // "Load configuration directory",
		{ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,	"Bound Import"				}, // "Bound import directory",
		{ IMAGE_DIRECTORY_ENTRY_IAT,			"Import Address Table (IAT)"}, // "Import address table (IAT)",
		{ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,	"Delay Import Descriptor"	}, // "Delay import table",
		{ IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,	"CLR Runtime Header"		}, // "COM descriptor table"
		{ IMAGE_DIRECTORY_RESERVED,				""							}  // "Reserved"
	};
	//static const size_t max_directory_entry = LIBPE_SIZEOF_ARRAY(names);
#endif

	const IMAGE_DATA_DIRECTORY * const resourceDirectory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (resourceDirectory == NULL || resourceDirectory->Size == 0)
		return NULL;

	uint64_t resourceDirOffset = pe_rva2ofs(ctx, resourceDirectory->VirtualAddress);
	/*char s[MAX_MSG];

	if (resourceDirectory->Size != 0) {
		snprintf(s, MAX_MSG, "%#x (%d bytes)",
				resourceDirectory->VirtualAddress,
				resourceDirectory->Size);

#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
		output(directory_names[IMAGE_DIRECTORY_ENTRY_RESOURCE], s); // Resource table
#else
		output(pe_directory_name(IMAGE_DIRECTORY_ENTRY_RESOURCE), s); // Resource table
#endif
		//printf("Offset by RVA: 0x%x\n\n", resourceDirOffset);
	}*/

	uintptr_t offset = resourceDirOffset;
	void *ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
	if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
		// TODO: Should we report something?
		return NULL;
	}

	NODE_PERES *node = malloc_s(sizeof(NODE_PERES));
	memset(node, 0, sizeof(*node));
	node->lastNode = NULL; // root
	node->rootNode = NULL; // root
	node->nodeType = RDT_RESOURCE_DIRECTORY;
	node->nodeLevel = RDT_LEVEL1;
	node->resource.resourceDirectory = ptr;
	//showNode(node);

	for (int i = 1, offsetDirectory1 = 0; i <= (lastNodeByTypeAndLevel(node, RDT_RESOURCE_DIRECTORY, RDT_LEVEL1)->resource.resourceDirectory->NumberOfNamedEntries +
												lastNodeByTypeAndLevel(node, RDT_RESOURCE_DIRECTORY, RDT_LEVEL1)->resource.resourceDirectory->NumberOfIdEntries); i++)
	{
		offsetDirectory1 += (i == 1) ? 16 : 8;
		offset = resourceDirOffset + offsetDirectory1;
		ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
		if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
			// TODO: Should we report something?
			goto _error;
		}

		node = createNode(node, RDT_DIRECTORY_ENTRY);
		NODE_PERES *rootNode = node;
		node->rootNode = rootNode;
		node->nodeLevel = RDT_LEVEL1;
		node->resource.directoryEntry = ptr;
		//showNode(node);

		if (node->resource.directoryEntry->DirectoryName.name.NameIsString == 1){
			offset = resourceDirOffset + node->resource.directoryEntry->DirectoryName.name.NameOffset;
			ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
			if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
				// TODO: Should we report something?
				goto _error;
			}
			node = createNode(node, RDT_DATA_STRING);
			node->rootNode = rootNode;
			node->nodeLevel = RDT_LEVEL1;
			node->resource.dataString = ptr;
			//showNode(node);
		}

		const NODE_PERES * lastDirectoryEntryNodeAtLevel1 = lastNodeByTypeAndLevel(node, RDT_DIRECTORY_ENTRY, RDT_LEVEL1);

		if (lastDirectoryEntryNodeAtLevel1->resource.directoryEntry->DirectoryData.data.DataIsDirectory)
		{
			offset = resourceDirOffset + lastDirectoryEntryNodeAtLevel1->resource.directoryEntry->DirectoryData.data.OffsetToDirectory;
			ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
			if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
				// TODO: Should we report something?
				goto _error;
			}

			node = createNode(node, RDT_RESOURCE_DIRECTORY);
			node->rootNode = (NODE_PERES *)lastDirectoryEntryNodeAtLevel1;
			node->nodeLevel = RDT_LEVEL2;
			node->resource.resourceDirectory = ptr;
			//showNode(node);

			for (int j = 1, offsetDirectory2 = 0; j <= (lastNodeByTypeAndLevel(node, RDT_RESOURCE_DIRECTORY, RDT_LEVEL2)->resource.resourceDirectory->NumberOfNamedEntries +
					lastNodeByTypeAndLevel(node, RDT_RESOURCE_DIRECTORY, RDT_LEVEL2)->resource.resourceDirectory->NumberOfIdEntries); j++)
			{
				offsetDirectory2 += (j == 1) ? 16 : 8;
				offset = resourceDirOffset + lastNodeByTypeAndLevel(node, RDT_DIRECTORY_ENTRY, RDT_LEVEL1)->resource.directoryEntry->DirectoryData.data.OffsetToDirectory + offsetDirectory2;
				ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
				if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
					// TODO: Should we report something?
					goto _error;
				}

				node = createNode(node, RDT_DIRECTORY_ENTRY);
				node->rootNode = rootNode;
				node->nodeLevel = RDT_LEVEL2;
				node->resource.directoryEntry = ptr;
				//showNode(node);

				if (node->resource.directoryEntry->DirectoryName.name.NameIsString == 1){
					offset = resourceDirOffset + node->resource.directoryEntry->DirectoryName.name.NameOffset;
					ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
					if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
						// TODO: Should we report something?
						goto _error;
					}
					node = createNode(node, RDT_DATA_STRING);
					node->rootNode = rootNode;
					node->nodeLevel = RDT_LEVEL2;
					node->resource.dataString = ptr;
					//showNode(node);
				}

				const NODE_PERES * lastDirectoryEntryNodeAtLevel2 = lastNodeByTypeAndLevel(node, RDT_DIRECTORY_ENTRY, RDT_LEVEL2);
				offset = resourceDirOffset + lastDirectoryEntryNodeAtLevel2->resource.directoryEntry->DirectoryData.data.OffsetToDirectory;

				ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
				if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
					// TODO: Should we report something?
					goto _error;
				}

				node = createNode(node, RDT_RESOURCE_DIRECTORY);
				node->rootNode = rootNode;
				node->nodeLevel = RDT_LEVEL3;
				node->resource.resourceDirectory = ptr;
				//showNode(node);

				offset += sizeof(IMAGE_RESOURCE_DIRECTORY);

				for (int y = 1; y <= (lastNodeByTypeAndLevel(node, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->resource.resourceDirectory->NumberOfNamedEntries +
									lastNodeByTypeAndLevel(node, RDT_RESOURCE_DIRECTORY, RDT_LEVEL3)->resource.resourceDirectory->NumberOfIdEntries); y++)
				{
					ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
					if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
						// TODO: Should we report something?
						goto _error;
					}
					node = createNode(node, RDT_DIRECTORY_ENTRY);
					node->rootNode = rootNode;
					node->nodeLevel = RDT_LEVEL3;
					node->resource.directoryEntry = ptr;
					//showNode(node);

					if (node->resource.directoryEntry->DirectoryName.name.NameIsString == 1){
						offset = resourceDirOffset + node->resource.directoryEntry->DirectoryName.name.NameOffset;
						ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
						if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
							// TODO: Should we report something?
							goto _error;
						}
						node = createNode(node, RDT_DATA_STRING);
						node->rootNode = rootNode;
						node->nodeLevel = RDT_LEVEL3;
						node->resource.dataString = ptr;
						//showNode(node);
					}

					const NODE_PERES * lastDirectoryEntryNodeAtLevel3 = lastNodeByTypeAndLevel(node, RDT_DIRECTORY_ENTRY, RDT_LEVEL3);
					offset = resourceDirOffset + lastDirectoryEntryNodeAtLevel3->resource.directoryEntry->DirectoryData.data.OffsetToDirectory;
					ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
					if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
						// TODO: Should we report something?
						goto _error;
					}
					node = createNode(node, RDT_DATA_ENTRY);
					node->rootNode = rootNode;
					node->nodeLevel = RDT_LEVEL3;
					node->resource.dataEntry = ptr;
					//showNode(node);

					offset += sizeof(IMAGE_RESOURCE_DATA_ENTRY);
				}
			}
		}
	}

	return node;

_error:
	if (node != NULL)
		freeNodes(node);
	return NULL;
}

int main(int argc, char **argv)
{
	pev_config_t config;
	PEV_INITIALIZE(&config);

	if (argc < 3) {
		usage();
		exit(EXIT_FAILURE);
	}

	output_set_cmdline(argc, argv);

	options_t *options = parse_options(argc, argv); // opcoes

	const char *path = argv[argc-1];
	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, path);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx))
		EXIT_ERROR("not a valid PE file");

	output_open_document();

	NODE_PERES *node = discoveryNodesPeres(&ctx);
	if (node == NULL) {
		WARNING("this file has no resources");
		return EXIT_SUCCESS;
	}

	if (options->all) {
		showInformations(node);
		showStatistics(node);
		showList(&ctx, node);
		extractResources(&ctx, node, options->namedExtract);
		showVersion(&ctx, node);
	} else {
		if (options->extract)
			extractResources(&ctx, node, options->namedExtract);
		if (options->info)
			showInformations(node);
		if (options->list)
			showList(&ctx, node);
		if (options->statistics)
			showStatistics(node);
		if (options->version)
			showVersion(&ctx, node);
	}

	output_close_document();

	freeNodes(node);

	// libera a memoria
	free_options(options);

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	PEV_FINALIZE(&config);

	return EXIT_SUCCESS;
}

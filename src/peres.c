/*
	pev - the PE file analyzer toolkit

	peres.c - retrive informations and binary data of resources

	Copyright (C) 2012 - 2020 pev authors

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
#include "utils.h"
#include <string.h>

#define PROGRAM "peres"

typedef struct {
	char name[20];
	uint32_t name_offset;
	char extension[20];
	char dir_name[20];
} PERES_RESOURCE_ENTRY_LOOKUP;

// REFERENCE: https://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
static const PERES_RESOURCE_ENTRY_LOOKUP g_resource_entry_lookup_table[] = {
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

typedef struct {
	char name[20];
	uint32_t nameOffset;
	char extension[20];
	char dirName[20];
} PERES_RESOURCE_ENTRY;

const char *g_resourceDir = "resources";

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
		" -f, --format <%s>  change output format (default: text)\n"
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

static const PERES_RESOURCE_ENTRY_LOOKUP * pe_resource_entry_lookup(uint32_t name_offset) {
	for (size_t i = 0; i < LIBPE_SIZEOF_ARRAY(g_resource_entry_lookup_table); i++) {
		if (g_resource_entry_lookup_table[i].name_offset == name_offset)
			return &g_resource_entry_lookup_table[i];
	}
	return NULL;
}

static void peres_show_node(const libpe_resource_node_t *node)
{
	char value[MAX_MSG];

	switch (node->nodeType)
	{
		default:
			WARNING("Invalid node type");
			break;
		case LIBPE_RDT_RESOURCE_DIRECTORY:
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
		case LIBPE_RDT_DIRECTORY_ENTRY:
		{
			const IMAGE_RESOURCE_DIRECTORY_ENTRY * const directoryEntry = node->resource.directoryEntry;

			snprintf(value, MAX_MSG, "Directory Entry / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", directoryEntry->u0.data.NameOffset);
			output("Name offset", value);

			snprintf(value, MAX_MSG, "%d", directoryEntry->u0.data.NameIsString);
			output("Name is string", value);

			snprintf(value, MAX_MSG, "%x", directoryEntry->u1.data.OffsetToDirectory);
			output("Offset to directory", value);

			snprintf(value, MAX_MSG, "%d", directoryEntry->u1.data.DataIsDirectory);
			output("Data is directory", value);
			break;
		}
		case LIBPE_RDT_DATA_STRING:
		{
			const IMAGE_RESOURCE_DATA_STRING * const dataString = node->resource.dataString;
            char name[MAX_PATH];

			snprintf(value, MAX_MSG, "Data String / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", dataString->Length);
			output("String len", value);

			uint16_t stringSize = (size_t)dataString->Length + 1 > sizeof(name) ? sizeof(name) - 1 : dataString->Length; // min(sizeof(name) - 1, dataString->length)
			utils_str_widechar2ascii(name, dataString->String, stringSize);
			name[stringSize] = '\0';
			snprintf(value, MAX_MSG, "%s", name);
			output("String", value);
			break;
		}
		case LIBPE_RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY * const dataEntry = node->resource.dataEntry;

			snprintf(value, MAX_MSG, "Data Entry / %d", node->nodeLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%x", dataEntry->OffsetToData);
			output("OffsetToData", value);

			snprintf(value, MAX_MSG, "%d", dataEntry->Size);
			output("Size", value);

			snprintf(value, MAX_MSG, "%d", dataEntry->CodePage);
			output("CodePage", value);

			snprintf(value, MAX_MSG, "%d", dataEntry->Reserved);
			output("Reserved", value);
			break;
		}
	}
}

static void peres_free_nodes(libpe_resource_node_t *currentNode)
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

static libpe_resource_node_t * peres_create_node(libpe_resource_node_t *currentNode, LIBPE_RESOURCE_NODE_TYPE typeOfNextNode)
{
	assert(currentNode != NULL);
	libpe_resource_node_t *newNode = malloc_s(sizeof(libpe_resource_node_t));
	memset(newNode, 0, sizeof(*newNode));
	newNode->lastNode = currentNode;
	newNode->nextNode = NULL;
	newNode->nodeType = typeOfNextNode;
	currentNode->nextNode = newNode;
	return newNode;
}

static const libpe_resource_node_t * peres_last_node_by_type(const libpe_resource_node_t *currentNode, LIBPE_RESOURCE_NODE_TYPE nodeTypeSearch)
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

static const libpe_resource_node_t * peres_last_node_by_type_and_level(const libpe_resource_node_t *currentNode, LIBPE_RESOURCE_NODE_TYPE nodeTypeSearch, LIBPE_RESOURCE_LEVEL nodeLevelSearch)
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

static void peres_build_node_relative_path(pe_ctx_t *ctx, const libpe_resource_node_t *node, char *output, size_t output_size)
{
	for (uint32_t level = LIBPE_RDT_LEVEL1; level <= node->nodeLevel; level++) {
		char partial_path[MAX_PATH];

		const libpe_resource_node_t *parent = peres_last_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, level);
		if (parent->resource.directoryEntry->u0.data.NameIsString) {
			const IMAGE_DATA_DIRECTORY * const resourceDirectory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE);
			if (resourceDirectory == NULL || resourceDirectory->Size == 0)
				return;

			const uint64_t offsetString = pe_rva2ofs(ctx, resourceDirectory->VirtualAddress + parent->resource.directoryEntry->u0.data.NameOffset);
			const IMAGE_RESOURCE_DATA_STRING *ptr = LIBPE_PTR_ADD(ctx->map_addr, offsetString);

			if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
				// TODO: Should we report something?
				return;
			}
			const uint16_t stringSize = (size_t)ptr->Length + 2 > sizeof(partial_path) ? sizeof(partial_path) - 2 : ptr->Length; // min(sizeof(partial_path) - 2, ptr->Length)
			utils_str_widechar2ascii(partial_path, ptr->String, stringSize);
			partial_path[stringSize] = ' ';
			partial_path[stringSize + 1] = '\0';
		} else {
			const PERES_RESOURCE_ENTRY_LOOKUP *resourceEntry = pe_resource_entry_lookup(parent->resource.directoryEntry->u0.data.NameOffset);
			if (level == LIBPE_RDT_LEVEL1 && resourceEntry != NULL) {
				snprintf(partial_path, sizeof(partial_path), "%s ", resourceEntry->name);
			} else {
				snprintf(partial_path, sizeof(partial_path), "%04x ", parent->resource.directoryEntry->u0.data.NameOffset);
			}
		}

		strncat(output, partial_path, output_size - strlen(output) - 1);
	}

	size_t length = strlen(output);
	output[length-1] = 0;
}

static void peres_show_list(pe_ctx_t *ctx, const libpe_resource_node_t *node)
{
	assert(node != NULL);

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		if (node->nodeType == LIBPE_RDT_DATA_ENTRY) {
			char path[MAX_PATH];
			memset(path, 0, sizeof(path));
			peres_build_node_relative_path(ctx, node, path, sizeof(path));
			printf("%s (%d bytes)\n", path, node->resource.dataEntry->Size);
		}
		node = node->nextNode;
	}
}

static void peres_save_resource(pe_ctx_t *ctx, const libpe_resource_node_t *node, bool namedExtract)
{
	assert(node != NULL);
	const libpe_resource_node_t *dataEntryNode = peres_last_node_by_type(node, LIBPE_RDT_DATA_ENTRY);
	if (dataEntryNode == NULL)
		return;

	const uint64_t raw_data_offset = pe_rva2ofs(ctx, dataEntryNode->resource.dataEntry->OffsetToData);
	const size_t raw_data_size = dataEntryNode->resource.dataEntry->Size;
	uint8_t *raw_data_ptr = LIBPE_PTR_ADD(ctx->map_addr, raw_data_offset);
	if (!pe_can_read(ctx, raw_data_ptr, raw_data_size)) {
		// TODO: Should we report something?
		printf("Attempted to read range [ %p, %p ] which is not within the mapped range [ %p, %lx ]\n",
			raw_data_ptr, LIBPE_PTR_ADD(raw_data_ptr, raw_data_size),
			ctx->map_addr, ctx->map_end);
		return;
	}

	struct stat statDir;
	if (stat(g_resourceDir, &statDir) == -1)
		mkdir(g_resourceDir, 0700);

	char dirName[100];
	memset(dirName, 0, sizeof(dirName));

	uint32_t nameOffset = node->rootNode->resource.directoryEntry->u0.data.NameOffset;
	const PERES_RESOURCE_ENTRY_LOOKUP *resourceEntry = pe_resource_entry_lookup(nameOffset);

	if (resourceEntry != NULL) {
		snprintf(dirName, sizeof(dirName), "%s/%s", g_resourceDir, resourceEntry->dir_name);
	} else {
		snprintf(dirName, sizeof(dirName), "%s", g_resourceDir);
	}

	// TODO(jweyrich): Would it make sense to hardcode `LIBPE_RDT_LEVEL2` rather than use `node->nodeLevel-1` ?
	const libpe_resource_node_t *nameNode = peres_last_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, node->nodeLevel - 1);
	//fprintf(stderr, "DEBUG: %d\n", nameNode->resource.directoryEntry->u0.data.NameOffset);

	if (stat(dirName, &statDir) == -1)
		mkdir(dirName, 0700);

	char relativeFileName[MAX_PATH + 105];
	memset(relativeFileName, 0, sizeof(relativeFileName));

	if(namedExtract) {
		char fileName[MAX_PATH];
		memset(fileName, 0, sizeof(fileName));

		peres_build_node_relative_path(ctx, node, fileName, sizeof(fileName)),
		snprintf(relativeFileName, sizeof(relativeFileName), "%s/%s%s",
			dirName,
			fileName,
			resourceEntry != NULL ? resourceEntry->extension : ".bin");
	} else {
		snprintf(relativeFileName, sizeof(relativeFileName), "%s/" "%" PRIu32 "%s",
			dirName,
			nameNode->resource.directoryEntry->u0.data.NameOffset,
			resourceEntry != NULL ? resourceEntry->extension : ".bin");
	}

	//printf("raw_data_offset=%#lx, raw_data_size=%ld, relativeFileName=%s\n", raw_data_offset, raw_data_size, relativeFileName);

	FILE *fp = fopen(relativeFileName, "wb+");
	if (fp == NULL) {
		// TODO: Should we report something?
		return;
	}
	fwrite(raw_data_ptr, raw_data_size, 1, fp);
	fclose(fp);
	output("Save On", relativeFileName);
}

static void peres_save_all_resources(pe_ctx_t *ctx, const libpe_resource_node_t *node, bool namedExtract)
{
	assert(node != NULL);
	int count = 0;

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		if (node->nodeType != LIBPE_RDT_DATA_ENTRY) {
			node = node->nextNode;
			continue;
		}
		count++;
		peres_save_resource(ctx, node, namedExtract);
		node = node->nextNode;
	}
}

static void peres_show_version(pe_ctx_t *ctx, const libpe_resource_node_t *node)
{
	assert(node != NULL);

	int count = 0;
	const libpe_resource_node_t *dataEntryNode;
	uint32_t nameOffset;
	bool found = false;

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		if (node->nodeType != LIBPE_RDT_DATA_ENTRY) {
			node = node->nextNode;
			continue;
		}
		count++;
		//if (count==19)
		dataEntryNode = peres_last_node_by_type(node, LIBPE_RDT_DATA_ENTRY);
		if (dataEntryNode == NULL)
			return;
		nameOffset = node->rootNode->resource.directoryEntry->u0.data.NameOffset;
		if (nameOffset == 16) {
			found = true;
			break;
		}
		node = node->nextNode;
	}

	if (!found)
		return;

	const uint64_t offsetData = pe_rva2ofs(ctx, dataEntryNode->resource.dataEntry->OffsetToData);
	const size_t dataEntrySize = dataEntryNode->resource.dataEntry->Size;
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

static void peres_show_nodes(const libpe_resource_node_t *node)
{
	assert(node != NULL);

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		peres_show_node(node);
		node = node->nextNode;
	}
}

static void peres_show_stats(const libpe_resource_node_t *node)
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
			case LIBPE_RDT_RESOURCE_DIRECTORY:
				totalResourceDirectory++;
				break;
			case LIBPE_RDT_DIRECTORY_ENTRY:
				totalDirectoryEntry++;
				break;
			case LIBPE_RDT_DATA_STRING:
				totalDataString++;
				break;
			case LIBPE_RDT_DATA_ENTRY:
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

static libpe_resource_node_t * peres_parse_resources(pe_ctx_t *ctx)
{
	const IMAGE_DATA_DIRECTORY * const resourceDirectory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (resourceDirectory == NULL || resourceDirectory->Size == 0)
		return NULL;

	uint64_t resourceDirOffset = pe_rva2ofs(ctx, resourceDirectory->VirtualAddress);

	uintptr_t offset = resourceDirOffset;
	void *ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
	if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
		// TODO: Should we report something?
		return NULL;
	}

	libpe_resource_node_t *node = malloc_s(sizeof(libpe_resource_node_t));
	memset(node, 0, sizeof(*node));
	node->lastNode = NULL; // root
	node->rootNode = NULL; // root
	node->nodeType = LIBPE_RDT_RESOURCE_DIRECTORY;
	node->nodeLevel = LIBPE_RDT_LEVEL1;
	node->resource.resourceDirectory = ptr;
	//peres_show_node(node);

	const libpe_resource_node_t * lastResourceDirNodeAtLevel1 = peres_last_node_by_type_and_level(node, LIBPE_RDT_RESOURCE_DIRECTORY, LIBPE_RDT_LEVEL1);
	size_t total_entries = lastResourceDirNodeAtLevel1->resource.resourceDirectory->NumberOfNamedEntries
		+ lastResourceDirNodeAtLevel1->resource.resourceDirectory->NumberOfIdEntries;
	for (size_t i = 1, offsetDirectory1 = 0; i <= total_entries; i++)
	{
		offsetDirectory1 += (i == 1) ? 16 : 8;
		offset = resourceDirOffset + offsetDirectory1;
		ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
		if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
			// TODO: Should we report something?
			goto _error;
		}

		node = peres_create_node(node, LIBPE_RDT_DIRECTORY_ENTRY);
		libpe_resource_node_t *rootNode = node;
		node->rootNode = rootNode;
		node->nodeLevel = LIBPE_RDT_LEVEL1;
		node->resource.directoryEntry = ptr;
		//peres_show_node(node);

		if (node->resource.directoryEntry->u0.data.NameIsString == 1){
			offset = resourceDirOffset + node->resource.directoryEntry->u0.data.NameOffset;
			ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
			if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
				// TODO: Should we report something?
				goto _error;
			}
			node = peres_create_node(node, LIBPE_RDT_DATA_STRING);
			node->rootNode = rootNode;
			node->nodeLevel = LIBPE_RDT_LEVEL1;
			node->resource.dataString = ptr;
			//peres_show_node(node);
		}

		const libpe_resource_node_t * lastDirectoryEntryNodeAtLevel1 = peres_last_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, LIBPE_RDT_LEVEL1);

		if (lastDirectoryEntryNodeAtLevel1->resource.directoryEntry->u1.data.DataIsDirectory)
		{
			offset = resourceDirOffset + lastDirectoryEntryNodeAtLevel1->resource.directoryEntry->u1.data.OffsetToDirectory;
			ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
			if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
				// TODO: Should we report something?
				goto _error;
			}

			node = peres_create_node(node, LIBPE_RDT_RESOURCE_DIRECTORY);
			node->rootNode = (libpe_resource_node_t *)lastDirectoryEntryNodeAtLevel1;
			node->nodeLevel = LIBPE_RDT_LEVEL2;
			node->resource.resourceDirectory = ptr;
			//peres_show_node(node);

			for (int j = 1, offsetDirectory2 = 0; j <= (peres_last_node_by_type_and_level(node, LIBPE_RDT_RESOURCE_DIRECTORY, LIBPE_RDT_LEVEL2)->resource.resourceDirectory->NumberOfNamedEntries +
					peres_last_node_by_type_and_level(node, LIBPE_RDT_RESOURCE_DIRECTORY, LIBPE_RDT_LEVEL2)->resource.resourceDirectory->NumberOfIdEntries); j++)
			{
				offsetDirectory2 += (j == 1) ? 16 : 8;
				offset = resourceDirOffset + peres_last_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, LIBPE_RDT_LEVEL1)->resource.directoryEntry->u1.data.OffsetToDirectory + offsetDirectory2;
				ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
				if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
					// TODO: Should we report something?
					goto _error;
				}

				node = peres_create_node(node, LIBPE_RDT_DIRECTORY_ENTRY);
				node->rootNode = rootNode;
				node->nodeLevel = LIBPE_RDT_LEVEL2;
				node->resource.directoryEntry = ptr;
				//peres_show_node(node);

				if (node->resource.directoryEntry->u0.data.NameIsString == 1){
					offset = resourceDirOffset + node->resource.directoryEntry->u0.data.NameOffset;
					ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
					if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
						// TODO: Should we report something?
						goto _error;
					}
					node = peres_create_node(node, LIBPE_RDT_DATA_STRING);
					node->rootNode = rootNode;
					node->nodeLevel = LIBPE_RDT_LEVEL2;
					node->resource.dataString = ptr;
					//peres_show_node(node);
				}

				const libpe_resource_node_t * lastDirectoryEntryNodeAtLevel2 = peres_last_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, LIBPE_RDT_LEVEL2);
				offset = resourceDirOffset + lastDirectoryEntryNodeAtLevel2->resource.directoryEntry->u1.data.OffsetToDirectory;

				ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
				if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
					// TODO: Should we report something?
					goto _error;
				}

				node = peres_create_node(node, LIBPE_RDT_RESOURCE_DIRECTORY);
				node->rootNode = rootNode;
				node->nodeLevel = LIBPE_RDT_LEVEL3;
				node->resource.resourceDirectory = ptr;
				//peres_show_node(node);

				offset += sizeof(IMAGE_RESOURCE_DIRECTORY);

				for (int y = 1; y <= (peres_last_node_by_type_and_level(node, LIBPE_RDT_RESOURCE_DIRECTORY, LIBPE_RDT_LEVEL3)->resource.resourceDirectory->NumberOfNamedEntries +
									peres_last_node_by_type_and_level(node, LIBPE_RDT_RESOURCE_DIRECTORY, LIBPE_RDT_LEVEL3)->resource.resourceDirectory->NumberOfIdEntries); y++)
				{
					ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
					if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
						// TODO: Should we report something?
						goto _error;
					}
					node = peres_create_node(node, LIBPE_RDT_DIRECTORY_ENTRY);
					node->rootNode = rootNode;
					node->nodeLevel = LIBPE_RDT_LEVEL3;
					node->resource.directoryEntry = ptr;
					//peres_show_node(node);

					if (node->resource.directoryEntry->u0.data.NameIsString == 1){
						offset = resourceDirOffset + node->resource.directoryEntry->u0.data.NameOffset;
						ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
						if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_STRING))) {
							// TODO: Should we report something?
							goto _error;
						}
						node = peres_create_node(node, LIBPE_RDT_DATA_STRING);
						node->rootNode = rootNode;
						node->nodeLevel = LIBPE_RDT_LEVEL3;
						node->resource.dataString = ptr;
						//peres_show_node(node);
					}

					const libpe_resource_node_t * lastDirectoryEntryNodeAtLevel3 = peres_last_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, LIBPE_RDT_LEVEL3);
					offset = resourceDirOffset + lastDirectoryEntryNodeAtLevel3->resource.directoryEntry->u1.data.OffsetToDirectory;
					ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
					if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
						// TODO: Should we report something?
						goto _error;
					}
					node = peres_create_node(node, LIBPE_RDT_DATA_ENTRY);
					node->rootNode = rootNode;
					node->nodeLevel = LIBPE_RDT_LEVEL3;
					node->resource.dataEntry = ptr;
					//peres_show_node(node);

					offset += sizeof(IMAGE_RESOURCE_DATA_ENTRY);
				}
			}
		}
	}

	return node;

_error:
	if (node != NULL)
		peres_free_nodes(node);
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

	libpe_resource_node_t *root_node = peres_parse_resources(&ctx);
	if (root_node == NULL) {
		WARNING("this file has no resources");
		return EXIT_SUCCESS;
	}

	if (options->all) {
		peres_show_nodes(root_node);
		peres_show_stats(root_node);
		peres_show_list(&ctx, root_node);
		peres_save_all_resources(&ctx, root_node, options->namedExtract);
		peres_show_version(&ctx, root_node);
	} else {
		if (options->extract)
			peres_save_all_resources(&ctx, root_node, options->namedExtract);
		if (options->info)
			peres_show_nodes(root_node);
		if (options->list)
			peres_show_list(&ctx, root_node);
		if (options->statistics)
			peres_show_stats(root_node);
		if (options->version)
			peres_show_version(&ctx, root_node);
	}

	peres_free_nodes(root_node);

	output_close_document();

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

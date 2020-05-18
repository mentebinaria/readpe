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
#include <libpe/utlist.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROGRAM "peres"

const char *g_resourceDir = "resources";

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

static void peres_show_node(const pe_resource_node_t *node)
{
	char value[MAX_MSG];

	switch (node->type)
	{
		default:
			LIBPE_WARNING("Invalid node type");
			break;
		case LIBPE_RDT_RESOURCE_DIRECTORY:
		{
			const IMAGE_RESOURCE_DIRECTORY * const resourceDirectory = node->raw.resourceDirectory;

			snprintf(value, MAX_MSG, "Resource Directory / %d", node->dirLevel);
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
			const IMAGE_RESOURCE_DIRECTORY_ENTRY * const directoryEntry = node->raw.directoryEntry;

			snprintf(value, MAX_MSG, "Directory Entry / %d", node->dirLevel);
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
			const IMAGE_RESOURCE_DATA_STRING_U * const dataString = node->raw.dataString;

			snprintf(value, MAX_MSG, "Data String / %d", node->dirLevel);
			output("\nNode Type / Level", value);

			snprintf(value, MAX_MSG, "%d", dataString->Length);
			output("String len", value);

			char ascii_string[MAX_MSG];
			size_t min_size = pe_utils_min(sizeof(ascii_string), dataString->Length + 1);
			pe_utils_str_widechar2ascii(ascii_string, (const char *)dataString->String, min_size);
			ascii_string[min_size - 1] = '\0'; // Null terminate it.

			snprintf(value, MAX_MSG, "%s", ascii_string);
			output("String", value);
			break;
		}
		case LIBPE_RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY * const dataEntry = node->raw.dataEntry;

			snprintf(value, MAX_MSG, "Data Entry / %d", node->dirLevel);
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

static void peres_show_nodes(pe_ctx_t *ctx, const pe_resource_node_t *node)
{
	if (node == NULL)
		return;

	peres_show_node(node);
		
	peres_show_nodes(ctx, node->childNode);
	peres_show_nodes(ctx, node->nextNode);
}

static void peres_build_node_filename(pe_ctx_t *ctx, char *output, size_t output_size, const pe_resource_node_t *node)
{
	UNUSED(ctx);
	char partial_path[MAX_PATH];

	for (pe_resource_level_e level = LIBPE_RDT_LEVEL1; level <= node->dirLevel; level++) {
		const pe_resource_node_t *dir_entry_node = pe_resource_find_parent_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, level);
		if (dir_entry_node->raw.directoryEntry->u0.data.NameIsString) {
			snprintf(partial_path, sizeof(partial_path), "%s ", dir_entry_node->name);
		} else {
			const pe_resource_entry_info_t *match = pe_resource_entry_info_lookup(dir_entry_node->raw.directoryEntry->u0.data.NameOffset);
			if (match != NULL && level == LIBPE_RDT_LEVEL1) {
				snprintf(partial_path, sizeof(partial_path), "%s ", match->name);
			} else {
				snprintf(partial_path, sizeof(partial_path), "%04x ", dir_entry_node->raw.directoryEntry->u0.data.NameOffset);
			}
		}

		strncat(output, partial_path, output_size - strlen(output) - 1);
	}

	size_t length = strlen(output);
	output[length - 1] = '\0'; // Remove the last whitespace.
}

static void peres_show_list_node(pe_ctx_t *ctx, const pe_resource_node_t *node)
{
	if (node->type != LIBPE_RDT_DATA_ENTRY)
		return;

	char node_info[MAX_PATH];
	memset(node_info, 0, sizeof(node_info));
	peres_build_node_filename(ctx, node_info, sizeof(node_info), node);
	printf("%s (%d bytes)\n", node_info, node->raw.dataEntry->Size);
}

static void peres_show_list(pe_ctx_t *ctx, const pe_resource_node_t *node)
{
	if (node == NULL)
		return;

	peres_show_list_node(ctx, node);

	peres_show_list(ctx, node->childNode);
	peres_show_list(ctx, node->nextNode);
}

#pragma pack(push, 1)
typedef struct {
	uint32_t biSize;
	int32_t  biWidth;
	int32_t  biHeight;
	uint16_t biPlanes;
	uint16_t biBitCount;
	uint32_t biCompression;
	uint32_t biSizeImage;
	int32_t  biXPelsPerMeter;
	int32_t  biYPelsPerMeter;
	uint32_t biClrUsed;
	uint32_t biClrImportant;
} BITMAPINFOHEADER;
#pragma pack(pop)

#pragma pack(push, 2)
typedef struct {
	uint16_t icReserved;   // Always zero
	uint16_t icType;       // 1 for .ico, 2 for .cur, other values are invalid
	uint16_t icImageCount; // number of images in the file
} ICOFILEHEADER;

typedef struct {
	uint8_t biWidth;        // Width of image
	uint8_t biHeight;       // Height of image
	uint8_t biClrUsed;      // Number of colors used
	uint8_t biReserved;     // Reserved
	union {
		uint16_t biPlanes;   // ICO - Number of color planes. Should be 0 or 1
		uint16_t biXHotspot; // CUR - Horizontal coord of the hotspot in number of pixels from the left
	} u0;
	union {
		uint16_t biBitCount; // ICO - Number of bits per pixel
		uint16_t biYHotspot; // CUR - Vertical coord of the hotspot in number of pixels from the top
	} u1;
	uint32_t biSizeImage;   // Size of image data in bytes
	uint32_t biOffBits;     // Offset of BMP or PNG data from the beggining of the ICO/CUR file
} ICODIRENTRY;
#pragma pack(pop)

typedef struct {
	bool is_modified;
	uint8_t *restore_buffer;
	size_t restore_size;
} peres_resource_restore_t;

static void peres_restore_resource_icon(peres_resource_restore_t *restore, const pe_resource_entry_info_t *entry_info, void *raw_data_ptr, size_t raw_data_size)
{
	if (memcmp(raw_data_ptr, "\x89PNG", 4) == 0) {
		// A PNG icon is stored along with its original header, so just return untouched.
		return;
	}

	const BITMAPINFOHEADER *bitmap = raw_data_ptr;

	// Is it valid?
	if (bitmap->biSize != 40) {
		LIBPE_WARNING("RT_ICON bitmap is not valid");
		return;
	}

	ICOFILEHEADER fileheader = {
		.icReserved = 0,
		.icType = 1,
		.icImageCount = 1,
	};
	ICODIRENTRY direntry = {
		.biWidth = bitmap->biWidth,
		.biHeight = bitmap->biHeight / ((entry_info->type == RT_ICON || entry_info->type == RT_CURSOR || entry_info->type == RT_BITMAP) ? 2 : 1),
		.biClrUsed = 0, // What should we put here?
		.biReserved = 0,
		.u0 = { .biPlanes = 1 },
		.u1 = { .biBitCount = bitmap->biBitCount },
		.biSizeImage = bitmap->biSizeImage,
		.biOffBits = sizeof(ICOFILEHEADER) + sizeof(ICODIRENTRY)
	};

	size_t written = 0;
	uint8_t *buffer = malloc_s(sizeof(ICOFILEHEADER) + sizeof(ICODIRENTRY) + raw_data_size);

#define PERES_APPEND(dst, src, size)	memcpy(dst + written, src, size); written += size
	PERES_APPEND(buffer, &fileheader, sizeof(ICOFILEHEADER));
	PERES_APPEND(buffer, &direntry, sizeof(ICODIRENTRY));
	PERES_APPEND(buffer, raw_data_ptr, raw_data_size);
#undef PERES_APPEND

	restore->is_modified = true;
	restore->restore_buffer = buffer;
	restore->restore_size = written;
}

static void peres_restore_resource(peres_resource_restore_t *restore, const pe_resource_entry_info_t *entry_info, void *raw_data_ptr, size_t raw_data_size)
{
	assert(restore != NULL);
	assert(raw_data_ptr != NULL);

	// If we don't know this type or the data size is 0, just return with the raw information untouched.
	if (entry_info == NULL || raw_data_size == 0) {
		goto fallback_untouched;
	}

	switch (entry_info->type) {
		default: goto fallback_untouched;
		case RT_ICON:
			peres_restore_resource_icon(restore, entry_info, raw_data_ptr, raw_data_size);
			break;
	}

	if (restore->is_modified)
		return;

fallback_untouched:
	restore->is_modified = false;
	restore->restore_buffer = raw_data_ptr;
	restore->restore_size = raw_data_size;
}

static void peres_save_resource(pe_ctx_t *ctx, const pe_resource_node_t *node, bool namedExtract)
{
	UNUSED(ctx);
	assert(node != NULL);
	assert(node->type == LIBPE_RDT_DATA_ENTRY);
	assert(node->dirLevel == LIBPE_RDT_LEVEL3);

	const IMAGE_RESOURCE_DATA_ENTRY *entry = node->raw.dataEntry;

	const uint64_t raw_data_offset = pe_rva2ofs(ctx, entry->OffsetToData);
	const size_t raw_data_size = entry->Size;
	uint8_t *raw_data_ptr = LIBPE_PTR_ADD(ctx->map_addr, raw_data_offset);
	if (!pe_can_read(ctx, raw_data_ptr, raw_data_size)) {
		// TODO: Should we report something?
		fprintf(stderr, "Attempted to read range [ %p, %p ] which is not within the mapped range [ %p, %lx ]\n",
			(void *)raw_data_ptr, LIBPE_PTR_ADD(raw_data_ptr, raw_data_size),
			ctx->map_addr, ctx->map_end);
		return;
	}

	struct stat statDir;
	if (stat(g_resourceDir, &statDir) == -1)
		mkdir(g_resourceDir, 0700);

	char dirName[100];
	memset(dirName, 0, sizeof(dirName));

	const pe_resource_node_t *folder_node = pe_resource_find_parent_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, LIBPE_RDT_LEVEL1); // dirLevel == 1 is where Resource Types are defined.
	const pe_resource_entry_info_t *entry_info = pe_resource_entry_info_lookup(folder_node->raw.directoryEntry->u0.Name);
	if (entry_info != NULL) {
		snprintf(dirName, sizeof(dirName), "%s/%s", g_resourceDir, entry_info->dir_name);
	} else {
		snprintf(dirName, sizeof(dirName), "%s", g_resourceDir);
	}

	if (stat(dirName, &statDir) == -1)
		mkdir(dirName, 0700);

	const pe_resource_node_t *name_node = pe_resource_find_parent_node_by_type_and_level(node, LIBPE_RDT_DIRECTORY_ENTRY, LIBPE_RDT_LEVEL2); // dirLevel == 2
	if (name_node == NULL) {
		// TODO: Should we report something?
		fprintf(stderr, "pe_resource_find_parent_node_by_type_and_level returned NULL\n");
		return;
	}
	//fprintf(stderr, "DEBUG: Name=%d\n", name_node->raw.directoryEntry->u0.Name);

	char relativeFileName[MAX_PATH]; // Wait, WHAT?!
	memset(relativeFileName, 0, sizeof(relativeFileName));

	if (namedExtract) {
		char fileName[MAX_PATH];
		memset(fileName, 0, sizeof(fileName));

		peres_build_node_filename(ctx, fileName, sizeof(fileName), node),
		snprintf(relativeFileName, sizeof(relativeFileName), "%s/%s%s",
			dirName,
			fileName,
			entry_info != NULL ? entry_info->extension : ".bin");
	} else {
		snprintf(relativeFileName, sizeof(relativeFileName), "%s/" "%" PRIu32 "%s",
			dirName,
			name_node->raw.directoryEntry->u0.data.NameOffset,
			entry_info != NULL ? entry_info->extension : ".bin");
	}
	//printf("DEBUG: raw_data_offset=%#llx, raw_data_size=%ld, relativeFileName=%s\n", raw_data_offset, raw_data_size, relativeFileName);

	peres_resource_restore_t restore = {0};
	peres_restore_resource(&restore, entry_info, raw_data_ptr, raw_data_size);

	FILE *fp = fopen(relativeFileName, "wb+");
	if (fp == NULL) {
		// TODO: Should we report something?
		return;
	}
	fwrite(restore.restore_buffer, restore.restore_size, 1, fp);
	fclose(fp);

	if (restore.is_modified) {
		free(restore.restore_buffer);
	}

	output("Save On", relativeFileName);
}

static void peres_save_all_resources(pe_ctx_t *ctx, const pe_resource_node_t *node, bool namedExtract)
{
	if (node == NULL)
		return;

	if (node->type == LIBPE_RDT_DATA_ENTRY && node->dirLevel == 3) {
		peres_save_resource(ctx, node, namedExtract);
	}

	peres_save_all_resources(ctx, node->childNode, namedExtract);
	peres_save_all_resources(ctx, node->nextNode, namedExtract);
}

bool peres_contains_version_node(const pe_resource_node_t *node) {
	if (node->type != LIBPE_RDT_DIRECTORY_ENTRY)
		return false;
	if (node->dirLevel != LIBPE_RDT_LEVEL1) // dirLevel == 1 belongs to the resource type directory.
		return false;
	if (node->raw.directoryEntry->u0.data.NameOffset != RT_VERSION)
		return false;
	return true;
}

static void peres_show_version(pe_ctx_t *ctx, const pe_resource_node_t *node)
{
	if (node == NULL)
		return;

	pe_resource_node_search_result_t search_result = {0};
	pe_resource_search_nodes(&search_result, node, peres_contains_version_node);

	pe_resource_node_search_result_item_t *result_item = {0};
	LL_FOREACH(search_result.items, result_item) {
		const pe_resource_node_t *version_node = pe_resource_find_node_by_type_and_level(result_item->node, LIBPE_RDT_DATA_ENTRY, LIBPE_RDT_LEVEL3);
		if (version_node != NULL) {
			const uint64_t data_offset = pe_rva2ofs(ctx, version_node->raw.dataEntry->OffsetToData);
			const size_t data_size = version_node->raw.dataEntry->Size;
			const void *data_ptr = LIBPE_PTR_ADD(ctx->map_addr, 32 + data_offset); // TODO(jweyrich): The literal 32 refers to the size of the 
			if (!pe_can_read(ctx, data_ptr, data_size)) {
				LIBPE_WARNING("Cannot read VS_FIXEDFILEINFO");
				return;
			}

			const VS_FIXEDFILEINFO *info_ptr = data_ptr;
			
			char value[MAX_MSG];
			snprintf(value, MAX_MSG, "%u.%u.%u.%u",
				(uint32_t)(info_ptr->dwFileVersionMS & 0xffff0000) >> 16,
				(uint32_t)info_ptr->dwFileVersionMS & 0x0000ffff,
				(uint32_t)(info_ptr->dwFileVersionLS & 0xffff0000) >> 16,
				(uint32_t)info_ptr->dwFileVersionLS & 0x0000ffff);
			output("File Version", value);

			snprintf(value, MAX_MSG, "%u.%u.%u.%u",
				(uint32_t)(info_ptr->dwProductVersionMS & 0xffff0000) >> 16,
				(uint32_t)info_ptr->dwProductVersionMS & 0x0000ffff,
				(uint32_t)(info_ptr->dwProductVersionLS & 0xffff0000) >> 16,
				(uint32_t)info_ptr->dwProductVersionLS & 0x0000ffff);
			output("Product Version", value);
		}
	}
	pe_resources_dealloc_node_search_result(&search_result);
}

typedef struct {
	int totalCount;
	int totalResourceDirectory;
	int totalDirectoryEntry;
	int totalDataString;
	int totalDataEntry;
} peres_stats_t;

static void peres_generate_stats(peres_stats_t *stats, const pe_resource_node_t *node) {
	if (node == NULL)
		return;
	
	stats->totalCount++;
	
	switch (node->type) {
		case LIBPE_RDT_RESOURCE_DIRECTORY:
			stats->totalResourceDirectory++;
			break;
		case LIBPE_RDT_DIRECTORY_ENTRY:
			stats->totalDirectoryEntry++;
			break;
		case LIBPE_RDT_DATA_STRING:
			stats->totalDataString++;
			break;
		case LIBPE_RDT_DATA_ENTRY:
			stats->totalDataEntry++;
			break;
	}
	
	if (node->childNode) {
		peres_generate_stats(stats, node->childNode);
	}

	if (node->nextNode) {
		peres_generate_stats(stats, node->nextNode);
	}
}

static void peres_show_stats(const pe_resource_node_t *node)
{
	peres_stats_t stats = {0};
	peres_generate_stats(&stats, node);

	char value[MAX_MSG];

	snprintf(value, MAX_MSG, "%d", stats.totalCount);
	output("Total Structs", value);

	snprintf(value, MAX_MSG, "%d", stats.totalResourceDirectory);
	output("Total Resource Directory", value);

	snprintf(value, MAX_MSG, "%d", stats.totalDirectoryEntry);
	output("Total Directory Entry", value);

	snprintf(value, MAX_MSG, "%d", stats.totalDataString);
	output("Total Data String", value);

	snprintf(value, MAX_MSG, "%d", stats.totalDataEntry);
	output("Total Data Entry", value);
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

	pe_resources_t *resources = pe_resources(&ctx);
	if (resources == NULL || resources->err != LIBPE_E_OK) {
		LIBPE_WARNING("This file has no resources");
		return EXIT_SUCCESS;
	}

	pe_resource_node_t *root_node = resources->root_node;

	if (options->all) {
		peres_show_nodes(&ctx, root_node);
		peres_show_stats(root_node);
		peres_show_list(&ctx, root_node);
		peres_save_all_resources(&ctx, root_node, options->namedExtract);
		peres_show_version(&ctx, root_node);
	} else {
		if (options->extract)
			peres_save_all_resources(&ctx, root_node, options->namedExtract);
		if (options->info)
			peres_show_nodes(&ctx, root_node);
		if (options->list)
			peres_show_list(&ctx, root_node);
		if (options->statistics)
			peres_show_stats(root_node);
		if (options->version)
			peres_show_version(&ctx, root_node);
	}

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

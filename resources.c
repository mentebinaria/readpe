/*
	libpe - the PE library

	Copyright (C) 2010 - 2017 libpe authors

	This file is part of libpe.

	libpe is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	libpe is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "libpe/resources.h"
#include "libpe/dir_resources.h"
#include "libpe/pe.h"
#include "libpe/utlist.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// REFERENCE: https://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
static const pe_resource_entry_info_t g_resource_dataentry_info_table[] = {
	{ "???_0",				0,					".0",		"_0"			},
	{ "RT_CURSOR",			RT_CURSOR,			".cur",		"cursors"		},
	{ "RT_BITMAP",			RT_BITMAP,			".bmp",		"bitmaps"		},
	{ "RT_ICON",			RT_ICON,			".ico",		"icons"			},
	{ "RT_MENU",			RT_MENU,			".rc",		"menus"			},
	{ "RT_DIALOG",			RT_DIALOG,			".dlg",		"dialogs"		},
	{ "RT_STRING",			RT_STRING,			".rc",		"strings"		},
	{ "RT_FONTDIR",			RT_FONTDIR,			".fnt",		"fontdirs"		},
	{ "RT_FONT",			RT_FONT,			".fnt",		"fonts"			},
	{ "RT_ACCELERATOR",		RT_ACCELERATOR,		".rc",		"accelerators"	},
	{ "RT_RCDATA",			RT_RCDATA,			".rc",		"rcdatas"		},
	{ "RT_MESSAGETABLE",	RT_MESSAGETABLE,	".mc",		"messagetables"	},
	{ "RT_GROUP_CURSOR",	RT_GROUP_CURSOR,	".cur",		"groupcursors"	},
	{ "???_13",				13,					".13",		"_13"			},
	{ "RT_GROUP_ICON",		RT_GROUP_ICON,		".ico",		"groupicons"	},
	{ "???_15",				15,					".15",		"_15"			},
	{ "RT_VERSION",			RT_VERSION,			".rc",		"versions"		},
	{ "RT_DLGINCLUDE",		RT_DLGINCLUDE,		".rc",		"dlgincludes"	},
	{ "???_18",				18,					".18",		"_18"			},
	{ "RT_PLUGPLAY",		RT_PLUGPLAY,		".rc",		"plugplays"		},
	{ "RT_VXD",				RT_VXD,				".rc",		"vxds"			},
	{ "RT_ANICURSOR",		RT_ANICURSOR,		".rc",		"anicursors"	},
	{ "RT_ANIICON",			RT_ANIICON,			".rc",		"aniicons"		},
	{ "RT_HTML",			RT_HTML,			".html",	"htmls"			},
	{ "RT_MANIFEST",		RT_MANIFEST,		".xml",		"manifests"		},
	{ "RT_DLGINIT",			RT_DLGINIT,			".rc",		"dlginits"		},
	{ "RT_TOOLBAR",			RT_TOOLBAR,			".rc",		"toolbars"		}
};

const pe_resource_entry_info_t *pe_resource_entry_info_lookup(uint32_t name_offset) {
	for (size_t i = 0; i < LIBPE_SIZEOF_ARRAY(g_resource_dataentry_info_table); i++) {
		if (g_resource_dataentry_info_table[i].type == name_offset)
			return &g_resource_dataentry_info_table[i];
	}
	return NULL;
}

void pe_resources_dealloc_node_search_result(pe_resource_node_search_result_t *result) {
	if (result == NULL)
		return;

	pe_resource_node_search_result_item_t *item = result->items;
	while (item != NULL) {
		pe_resource_node_search_result_item_t *next = item->next;
		free(item);
		item = next;
	}
}

void pe_resource_search_nodes(pe_resource_node_search_result_t *result, const pe_resource_node_t *node, pe_resource_node_predicate_fn predicate) {
	assert(result != NULL);

	if (node == NULL)
		return;

	if (predicate(node)) {
		// Found the matching node. Return it.
		pe_resource_node_search_result_item_t *item = malloc(sizeof(*item));
		if (item == NULL) {
			// TODO: Handle allocation failure.
			abort();
		}
		memset(item, 0, sizeof(*item));
		item->node = node;
		LL_APPEND(result->items, item);
		result->count++;
		// IMPORTANT: We do NOT return early because we want all matching nodes.
	}

	// Traverse the tree to find the matching node.
	pe_resource_search_nodes(result, node->childNode, predicate);
	pe_resource_search_nodes(result, node->nextNode, predicate);
}

pe_resource_node_t *pe_resource_root_node(const pe_resource_node_t *node) {
	if (node == NULL)
		return NULL;

	// Traverse the linked-list to find the root parent node.
	pe_resource_node_t *parent = node->parentNode;
	while (parent != NULL) {
		if (parent->parentNode == NULL) {
			// Found the root parent node. Return it.
			return parent;
		}
		// Move to the next parent node.
		parent = parent->parentNode;
	}

	return (pe_resource_node_t *)node; // Return the node itself if it has no parent.
}

pe_resource_node_t *pe_resource_last_child_node(const pe_resource_node_t *parent_node) {
	if (parent_node == NULL)
		return NULL;

	// Traverse the linked-list to find the last child node.
	pe_resource_node_t *child = parent_node->childNode;
	while (child != NULL) {
		if (child->nextNode == NULL) {
			// Found the last child node. Return it.
			return child;
		}
		// Move to the next node.
		child = child->nextNode;
	}

	return NULL;
}

pe_resource_node_t *pe_resource_find_node_by_type_and_level(const pe_resource_node_t *node, pe_resource_node_type_e type, uint32_t dirLevel) {
	if (node == NULL)
		return NULL;

	// Found the matching node. Return it.
	if (node->type == type && node->dirLevel == dirLevel) {
		return (pe_resource_node_t *)node;
	}

	// Traverse the tree to find the matching node.

	const pe_resource_node_t *child = pe_resource_find_node_by_type_and_level(node->childNode, type, dirLevel);
	// Found the matching node. Return it.
	if (child != NULL)
		return (pe_resource_node_t *)child;

	const pe_resource_node_t *sibling = pe_resource_find_node_by_type_and_level(node->nextNode, type, dirLevel);
	// Found the matching node. Return it.
	if (sibling != NULL)
		return (pe_resource_node_t *)sibling;

	return NULL;
}

pe_resource_node_t *pe_resource_find_parent_node_by_type_and_level(const pe_resource_node_t *node, pe_resource_node_type_e type, uint32_t dirLevel) {
	if (node == NULL)
		return NULL;

	// Traverse the linked-list to find the matching parent node.
	pe_resource_node_t *parent = node->parentNode;
	while (parent != NULL) {
		if (parent->type == type && parent->dirLevel == dirLevel) {
			// Found the matching parent node. Return it.
			return parent;
		}
		// Move to the next parent node.
		parent = parent->parentNode;
	}

	return NULL;
}

static char *pe_resource_parse_string_u(pe_ctx_t *ctx, char *output, size_t output_size, const IMAGE_RESOURCE_DATA_STRING_U *data_string_ptr) {
	if (data_string_ptr == NULL)
		return NULL;

	const size_t buffer_size = pe_utils_min(output_size <= 0 ? 256 : output_size, (size_t)data_string_ptr->Length + 1);
	if (!pe_can_read(ctx, data_string_ptr->String, buffer_size)) {
		LIBPE_WARNING("Cannot read string from IMAGE_RESOURCE_DATA_STRING_U");
		return NULL;
	}

	// If the caller provided a NULL pointer, we do the allocation and return it.
	if (output == NULL) {
		output = malloc(buffer_size);
		if (output == NULL) {
			// TODO: Handle allocation failure.
			abort();
		}
	}

	//strncpy(buffer, data_string_ptr->String, buffer_size);
	pe_utils_str_widechar2ascii(output, (const char *)data_string_ptr->String, buffer_size);

	output[buffer_size - 1] = '\0';

	return output;
}

static char *pe_resource_name_from_id(pe_ctx_t *ctx, char *out_name, size_t out_name_size, uint32_t id) {
	const bool is_string = id & IMAGE_RESOURCE_NAME_IS_STRING; // entry->u0.data.NameIsString

	// If it's a regular ID, simply use it.
	if (!is_string) {
		if (out_name == NULL) {
			const size_t estimated_size = 8 + 1; // 8 == strlen("FFFFFFFF"), +1 for the `\0`.
			out_name = malloc(estimated_size);
			if (out_name == NULL) {
				// TODO: Handle allocation failure.
				abort();
			}
		}

		snprintf(out_name, out_name_size, "%X", id);
		return out_name;
	}

	id &= ~(uint32_t)IMAGE_RESOURCE_NAME_IS_STRING; // Ignore the highest bit.
	const IMAGE_RESOURCE_DATA_STRING_U *data_string_u = LIBPE_PTR_ADD(ctx->cached_data.resources->resource_base_ptr, id);
	if (!pe_can_read(ctx, data_string_u, sizeof(IMAGE_RESOURCE_DATA_STRING_U))) {
		LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DATA_STRING_U");
		return false;
	}

	out_name = pe_resource_parse_string_u(ctx, out_name, out_name_size, data_string_u);
	return out_name;
}

static char *pe_resource_name_from_type(char *out_name, size_t out_name_size, uint32_t type) {
	const pe_resource_entry_info_t *match = pe_resource_entry_info_lookup(type);

	if (out_name == NULL) {
		const size_t estimated_size = (match != NULL ? strlen(match->name) : 8) + 1; // 8 == strlen("FFFFFFFF"), +1 for the `\0`.
		out_name = malloc(estimated_size);
		if (out_name == NULL) {
			// TODO: Handle allocation failure.
			abort();
		}
	}

	if (match != NULL) {
		strncpy(out_name, match->name, out_name_size);
		out_name[out_name_size - 1] = '\0';
	} else {
		snprintf(out_name, out_name_size, "%" PRIX32, type);
	}

	return out_name;
}

static void pe_resource_debug_node(pe_ctx_t *ctx, const pe_resource_node_t *node) {
	if (node == NULL)
		return;

	switch (node->type) {
		default:
			LIBPE_WARNING("Invalid node type");
			break;
		case LIBPE_RDT_RESOURCE_DIRECTORY:
		{
			char resource_name[256];
			const size_t resource_name_size = sizeof(resource_name);
			memset(resource_name, 0, resource_name_size);

			if (node->dirLevel == LIBPE_RDT_LEVEL1) { // dirLevel == 1 is where Resource Types are defined.
				if (node->parentNode != NULL && node->parentNode->type == LIBPE_RDT_DIRECTORY_ENTRY) {
					IMAGE_RESOURCE_DIRECTORY_ENTRY *dir_entry = node->parentNode->raw.directoryEntry;
					if (dir_entry->u0.data.NameIsString) {
						pe_resource_name_from_id(ctx, resource_name, resource_name_size, dir_entry->u0.Name);
					} else {
						pe_resource_name_from_type(resource_name, resource_name_size, dir_entry->u0.Name);
					}
				}
			} else {
				if (node->parentNode != NULL && node->parentNode->type == LIBPE_RDT_DIRECTORY_ENTRY) {
					IMAGE_RESOURCE_DIRECTORY_ENTRY *dir_entry = node->parentNode->raw.directoryEntry;
					pe_resource_name_from_id(ctx, resource_name, resource_name_size, dir_entry->u0.Name);
				} else {
					resource_name[0] = '0';
					resource_name[1] = '\0';
				}
			}

			const IMAGE_RESOURCE_DIRECTORY * const dir = node->raw.resourceDirectory;

			// Indentation.
			for (size_t i=0; i < node->depth; i++)
				printf("  ");
			printf("LIBPE_RDT_RESOURCE_DIRECTORY [dirLevel=%d]: ", node->dirLevel);

			printf("ResDir (%s) Entries:%02u[%02X] (Named:%02u[%02X], ID:%02u[%02X]) TimeDate:%08u[%08X]",
				resource_name,
				dir->NumberOfIdEntries + dir->NumberOfNamedEntries,
				dir->NumberOfIdEntries + dir->NumberOfNamedEntries,
				dir->NumberOfNamedEntries,
				dir->NumberOfNamedEntries,
				dir->NumberOfIdEntries,
				dir->NumberOfIdEntries,
				dir->TimeDateStamp,
				dir->TimeDateStamp
			);

			if (dir->MajorVersion || dir->MinorVersion)
				printf(" Vers:%u.%02u", dir->MajorVersion, dir->MinorVersion);

			if (dir->Characteristics)
				printf(" Char:%08u[%08X]", dir->Characteristics, dir->Characteristics);

			printf("\n");
			break;
		}
		case LIBPE_RDT_DIRECTORY_ENTRY:
		{
			// Indentation.
			for (size_t i=0; i < node->depth; i++)
				printf("  ");
			printf("LIBPE_RDT_DIRECTORY_ENTRY [dirLevel=%d]: ", node->dirLevel);

			const IMAGE_RESOURCE_DIRECTORY_ENTRY * const entry = node->raw.directoryEntry;

			if (entry->u0.data.NameIsString) { // entry->u0.Name & IMAGE_RESOURCE_NAME_IS_STRING
				char res_name[256];
				pe_resource_name_from_id(ctx, res_name, sizeof(res_name), entry->u0.Name);
				printf("Name: %s  DataEntryOffs: %08u[%08X]\n",
					res_name, entry->u1.OffsetToData, entry->u1.OffsetToData);
			} else {
				printf("ID: %08u[%08X]  DataEntryOffs: %08u[%08X]\n",
					entry->u0.Name, entry->u0.Name, entry->u1.OffsetToData, entry->u1.OffsetToData);
			}
			break;
		}
		case LIBPE_RDT_DATA_STRING:
		{
			const IMAGE_RESOURCE_DATA_STRING_U * const dataString = node->raw.dataString;

			char ascii_string[256];
			pe_resource_parse_string_u(ctx, ascii_string, sizeof(ascii_string), dataString);

			// Indentation.
			for (size_t i=0; i < node->depth; i++)
				printf("  ");
			printf("LIBPE_RDT_DATA_STRING [dirLevel=%d]: ", node->dirLevel);

			printf("String: %s  Length: %02d\n", ascii_string, dataString->Length);
			break;
		}
		case LIBPE_RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY * const data_entry = node->raw.dataEntry;

			// Indentation.
			for (size_t i=0; i < node->depth; i++)
				printf("  ");
			printf("LIBPE_RDT_DATA_ENTRY [dirLevel=%d]: ", node->dirLevel);

			printf("DataRVA: %05u[%05X]  DataSize: %05u[%05X]  CodePage: %u[%X]\n",
				data_entry->OffsetToData,
				data_entry->OffsetToData,
				data_entry->Size,
				data_entry->Size,
				data_entry->CodePage,
				data_entry->CodePage);
			break;
		}
	}
}

static void pe_resource_debug_nodes(pe_ctx_t *ctx, const pe_resource_node_t *node) {
	if (node == NULL)
		return;

	pe_resource_debug_node(ctx, node);

	pe_resource_debug_nodes(ctx, node->childNode);
	pe_resource_debug_nodes(ctx, node->nextNode);
}

static pe_resource_node_t *pe_resource_create_node(uint8_t depth, pe_resource_node_type_e type, void *raw_ptr, pe_resource_node_t *parent_node) {
	pe_resource_node_t *node = malloc(sizeof(pe_resource_node_t));
	if (node == NULL) {
		// TODO: Handle allocation failure.
		abort();
	}
	memset(node, 0, sizeof(*node));
	node->depth = depth;
	node->type = type;

	// Determine directory level.
	if (parent_node != NULL) {
		// node->dirLevel = parent_node->type == LIBPE_RDT_RESOURCE_DIRECTORY && node->type == LIBPE_RDT_DIRECTORY_ENTRY
		node->dirLevel = parent_node->type == LIBPE_RDT_RESOURCE_DIRECTORY
			? parent_node->dirLevel + 1
			: parent_node->dirLevel;
	} else {
		node->dirLevel = 0; // Only the root directory has dirLevel == 0.
	}

	// Establish relationships. Makes the node more human!
	if (parent_node != NULL) {
		node->parentNode = parent_node;

		if (parent_node->childNode == NULL) {
			// This is the 1st child node of parent_node.
			parent_node->childNode = node;
		} else {
			// This is NOT the 1st child node of parent_node, so we need to append it to the end of the linked-list.
			pe_resource_node_t *last_child_node = pe_resource_last_child_node(parent_node);
			if (last_child_node != NULL) {
				// Found the last child node. Append our new node.
				last_child_node->nextNode = node;
			}
		}
	}

	node->raw.raw_ptr = raw_ptr;

	switch (type) {
		default:
			LIBPE_WARNING("Invalid node type");
			break;
		case LIBPE_RDT_RESOURCE_DIRECTORY:
			node->raw.resourceDirectory = raw_ptr;
			break;
		case LIBPE_RDT_DIRECTORY_ENTRY:
			node->raw.directoryEntry = raw_ptr;
			break;
		case LIBPE_RDT_DATA_STRING:
			node->raw.dataString = raw_ptr;
			break;
		case LIBPE_RDT_DATA_ENTRY:
			node->raw.dataEntry = raw_ptr;
			break;
	}

	return node;
}

static void pe_resource_free_nodes(pe_resource_node_t *node) {
	if (node == NULL)
		return;

	pe_resource_free_nodes(node->childNode);
	pe_resource_free_nodes(node->nextNode);

	free(node->name);
	free(node);
}

static bool pe_resource_parse_nodes(pe_ctx_t *ctx, pe_resource_node_t *node) {
	switch (node->type) {
		default:
			LIBPE_WARNING("Invalid node type");
			return false;
		case LIBPE_RDT_RESOURCE_DIRECTORY:
		{
			const IMAGE_RESOURCE_DIRECTORY * const resdir_ptr = node->raw.resourceDirectory;
			IMAGE_RESOURCE_DIRECTORY_ENTRY *first_entry_ptr = LIBPE_PTR_ADD(resdir_ptr, sizeof(IMAGE_RESOURCE_DIRECTORY));
			const size_t total_entries = resdir_ptr->NumberOfIdEntries + resdir_ptr->NumberOfNamedEntries;

			for (size_t i = 0; i < total_entries; i++) {
				IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = &first_entry_ptr[i];
				if (!pe_can_read(ctx, entry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
					LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DIRECTORY_ENTRY");
					break;
				}

				pe_resource_node_t *new_node = pe_resource_create_node(node->depth + 1, LIBPE_RDT_DIRECTORY_ENTRY, entry, node);
				pe_resource_parse_nodes(ctx, new_node);
			}
			break;
		}
		case LIBPE_RDT_DIRECTORY_ENTRY:
		{
			const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry_ptr = node->raw.directoryEntry;

			fprintf(stdout, "DEBUG: id=%#x, dataOffset=%#x\n", entry_ptr->u0.Id, entry_ptr->u1.OffsetToData);

			pe_resource_node_t *new_node = NULL;

			// This resource has a name?
			if (entry_ptr->u0.data.NameIsString) { // entry->u0.Name & IMAGE_RESOURCE_NAME_IS_STRING
				IMAGE_RESOURCE_DATA_STRING_U *data_string_ptr = LIBPE_PTR_ADD(ctx->cached_data.resources->resource_base_ptr, entry_ptr->u0.data.NameOffset);
				if (!pe_can_read(ctx, data_string_ptr, sizeof(IMAGE_RESOURCE_DATA_STRING_U))) {
					LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DATA_STRING_U");
					return NULL;
				}

				node->name = pe_resource_parse_string_u(ctx, NULL, 0, data_string_ptr);

				new_node = pe_resource_create_node(node->depth + 1, LIBPE_RDT_DATA_STRING, data_string_ptr, node);
				pe_resource_parse_nodes(ctx, new_node);
			}

			// Is it a directory?
			if (entry_ptr->u1.data.DataIsDirectory) { // entry->u1.OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY
				IMAGE_RESOURCE_DIRECTORY *child_resdir_ptr = LIBPE_PTR_ADD(ctx->cached_data.resources->resource_base_ptr, entry_ptr->u1.data.OffsetToDirectory);
				if (!pe_can_read(ctx, child_resdir_ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
					LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DIRECTORY");
					break;
				}
				new_node = pe_resource_create_node(node->depth + 1, LIBPE_RDT_RESOURCE_DIRECTORY, child_resdir_ptr, node);
			} else { // Not a directory
				IMAGE_RESOURCE_DATA_ENTRY *data_entry_ptr = LIBPE_PTR_ADD(ctx->cached_data.resources->resource_base_ptr, entry_ptr->u1.data.OffsetToDirectory);
				if (!pe_can_read(ctx, data_entry_ptr, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
					LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DATA_ENTRY");
					break;
				}
				new_node = pe_resource_create_node(node->depth + 1, LIBPE_RDT_DATA_ENTRY, data_entry_ptr, node);
			}

			pe_resource_parse_nodes(ctx, new_node);

			break;
		}
		case LIBPE_RDT_DATA_STRING:
		{
			const IMAGE_RESOURCE_DATA_STRING_U *data_string_ptr = node->raw.dataString;
			if (!pe_can_read(ctx, data_string_ptr, sizeof(IMAGE_RESOURCE_DATA_STRING_U))) {
				LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DATA_STRING_U");
				break;
			}

			// TODO(jweyrich): We should store the result in the node to be useful,
			// but we still don't store specific data in the node, except for its name.
			char *buffer = pe_resource_parse_string_u(ctx, NULL, 0, data_string_ptr);
			fprintf(stdout, "DEBUG: Length=%d, String=%s\n", data_string_ptr->Length, buffer);
			free(buffer);
			break;
		}
		case LIBPE_RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY *data_entry_ptr = node->raw.dataEntry;

			fprintf(stdout, "DEBUG: CodePage=%u, OffsetToData=%u[%#x], Reserved=%u[%#x], Size=%u[%#x]\n",
				data_entry_ptr->CodePage,
				data_entry_ptr->OffsetToData,
				data_entry_ptr->OffsetToData,
				data_entry_ptr->Reserved,
				data_entry_ptr->Reserved,
				data_entry_ptr->Size,
				data_entry_ptr->Size);

			////////////////////////////////////////////////////////////////////////////////////
			// TODO(jweyrich): To be written.
			////////////////////////////////////////////////////////////////////////////////////
			break;
		}
	}

	return true;
}

static pe_resource_node_t *pe_resource_parse(pe_ctx_t *ctx, void *resource_base_ptr) {
	pe_resource_node_t *root_node = pe_resource_create_node(0, LIBPE_RDT_RESOURCE_DIRECTORY, resource_base_ptr, NULL);
	pe_resource_parse_nodes(ctx, root_node);
	//pe_resource_debug_nodes(ctx, root_node);
	return root_node;
}

static void *pe_resource_base_ptr(pe_ctx_t *ctx) {
	const IMAGE_DATA_DIRECTORY * const directory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (directory == NULL) {
		LIBPE_WARNING("Resource directory does not exist")
		return NULL;
	}
	if (directory->VirtualAddress == 0 || directory->Size == 0) {
		LIBPE_WARNING("Resource directory VA is zero")
		return NULL;
	}
	if (directory->Size == 0) {
		LIBPE_WARNING("Resource directory size is 0")
		return NULL;
	}

	const uintptr_t offset = pe_rva2ofs(ctx, directory->VirtualAddress);
	void *ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
	if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
		LIBPE_WARNING("Cannot read IMAGE_RESOURCE_DIRECTORY");
		return NULL;
	}

	return ptr;
}

pe_resources_t *pe_resources(pe_ctx_t *ctx) {
	if (ctx->cached_data.resources != NULL)
		return ctx->cached_data.resources;

	pe_resources_t *res_ptr = malloc(sizeof(pe_resources_t));
	if (res_ptr == NULL) {
		// TODO: Handle allocation failure.
		abort();
	}
	memset(res_ptr, 0, sizeof(*res_ptr));

	ctx->cached_data.resources = res_ptr;
	ctx->cached_data.resources->err = LIBPE_E_OK;
	ctx->cached_data.resources->resource_base_ptr = pe_resource_base_ptr(ctx); // Various parts of the parsing rely on `resource_base_ptr`.
	if (ctx->cached_data.resources->resource_base_ptr != NULL) {
		ctx->cached_data.resources->root_node = pe_resource_parse(ctx, ctx->cached_data.resources->resource_base_ptr);
	}

	return ctx->cached_data.resources;
}

void pe_resources_dealloc(pe_resources_t *obj) {
	if (obj == NULL)
		return;
	pe_resource_free_nodes(obj->root_node);
	free(obj);
}

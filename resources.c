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

#include "libpe/pe.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static output_node_t *showNode(const NODE_PERES *node, output_node_t *output) {
	switch (node->nodeType) {
		default: return NULL;
		case RDT_RESOURCE_DIRECTORY:
		{
			const IMAGE_RESOURCE_DIRECTORY *resourceDirectory = node->resource.resourceDirectory;
			output->kind = RDT_RESOURCE_DIRECTORY;
			output->node_type.resourcesDirectory.NodeType = node->nodeLevel;
			output->node_type.resourcesDirectory.Characteristics = resourceDirectory->Characteristics;
			output->node_type.resourcesDirectory.TimeDateStamp = resourceDirectory->TimeDateStamp;
			output->node_type.resourcesDirectory.MajorVersion = resourceDirectory->MajorVersion;
			output->node_type.resourcesDirectory.MinorVersion = resourceDirectory->MinorVersion;
			output->node_type.resourcesDirectory.NumberOfNamedEntries = resourceDirectory->NumberOfNamedEntries;
			output->node_type.resourcesDirectory.NumberOfIdEntries = resourceDirectory->NumberOfIdEntries;
			break;
		}
		case RDT_DIRECTORY_ENTRY:
		{
			const IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry = node->resource.directoryEntry;
			output->kind = RDT_DIRECTORY_ENTRY;
			output->node_type.directoryEntry.NodeType = node->nodeLevel;
			output->node_type.directoryEntry.NameOffset = directoryEntry->DirectoryName.name.NameOffset;
			output->node_type.directoryEntry.NameIsString = directoryEntry->DirectoryName.name.NameIsString;
			output->node_type.directoryEntry.OffsetIsDirectory = directoryEntry->DirectoryData.data.OffsetToDirectory;
			output->node_type.directoryEntry.DataIsDirectory = directoryEntry->DirectoryData.data.DataIsDirectory;

			break;
		}
		case RDT_DATA_STRING:
		{
			const IMAGE_RESOURCE_DATA_STRING *dataString = node->resource.dataString;
			output->kind = RDT_DATA_STRING;
			output->node_type.dataString.NodeType = node->nodeLevel;
			output->node_type.dataString.Strlen = dataString->length;
			output->node_type.dataString.String = dataString->string[0];
			break;
		}
		case RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY *dataEntry = node->resource.dataEntry;
			output->kind = RDT_DATA_ENTRY;
			output->node_type.dataEntry.NodeType = node->nodeLevel;
			output->node_type.dataEntry.OffsetToData = dataEntry->offsetToData;
			output->node_type.dataEntry.Size = dataEntry->size;
			output->node_type.dataEntry.CodePage = dataEntry->codePage;
			output->node_type.dataEntry.CodePage = dataEntry->codePage;
			output->node_type.dataEntry.Reserved = dataEntry->reserved;
			break;
		}
	}

	return output;
}

static NODE_PERES * createNode(NODE_PERES *currentNode, NODE_TYPE_PERES typeOfNextNode) {
	assert(currentNode != NULL);

	NODE_PERES *newNode = malloc(sizeof(NODE_PERES));
	if (newNode == NULL) {
		// TODO(jweyrich): Report allocation failure?
		return NULL;
	}

	memset(newNode, 0, sizeof(NODE_PERES));
	newNode->lastNode = currentNode;
	newNode->nextNode = NULL;
	newNode->nodeType = typeOfNextNode;
	currentNode->nextNode = newNode;
	return newNode;
}

static const NODE_PERES * lastNodeByTypeAndLevel(const NODE_PERES *currentNode, NODE_TYPE_PERES nodeTypeSearch, NODE_LEVEL_PERES nodeLevelSearch) {
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

static void freeNodes(NODE_PERES *currentNode) {
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

static count_output_node_t countNode(NODE_PERES *node) {
	count_output_node_t count;
	memset(&count, 0, sizeof(count_output_node_t));

	switch (node->nodeType) {
		default: return count;
		case RDT_RESOURCE_DIRECTORY:
			count.kind = RDT_RESOURCE_DIRECTORY;
			break;
		case RDT_DIRECTORY_ENTRY:
			count.kind = RDT_DIRECTORY_ENTRY;
			break;
		case RDT_DATA_STRING:
			count.kind = RDT_DATA_STRING;
			break;
		case RDT_DATA_ENTRY:
			count.kind = RDT_DATA_ENTRY;
			break;
	}

	return count;
}

static pe_resources_count_t get_count(NODE_PERES *node) {
	pe_resources_count_t count;
	int resourcesDirectory = 0;
	int directoryEntry = 0;
	int dataString = 0;
	int dataEntry = 0;

	count_output_node_t output;
	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	while (node != NULL) {
		output = countNode(node);
		if (output.kind == RDT_RESOURCE_DIRECTORY)
			resourcesDirectory++;
		if (output.kind == RDT_DIRECTORY_ENTRY)
			directoryEntry++;
		if (output.kind == RDT_DATA_STRING)
			dataString++;
		if (output.kind == RDT_DATA_ENTRY)
			dataEntry++;
		node = node->nextNode;
	}
	count.resourcesDirectory = resourcesDirectory;
	count.directoryEntry = directoryEntry;
	count.dataString = dataString;
	count.dataEntry = dataEntry;
	return count;
}

static NODE_PERES * discoveryNodesPeres(pe_ctx_t *ctx) {
	const IMAGE_DATA_DIRECTORY * resourceDirectory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (resourceDirectory == NULL || resourceDirectory->Size == 0)
		return NULL;

	uint64_t resourceDirOffset = pe_rva2ofs(ctx, resourceDirectory->VirtualAddress);

	uintptr_t offset = resourceDirOffset;
	void *ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
	if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
		// TODO: Should we report something?
		return NULL;
	}

	NODE_PERES *node = malloc(sizeof(NODE_PERES));
	if (node == NULL) {
		// TODO(jweyrich): Report allocation failure?
		return NULL;
	}
	memset(node, 0, sizeof(NODE_PERES));
	node->lastNode = NULL; // root
	node->nodeType = RDT_RESOURCE_DIRECTORY;
	node->nodeLevel = RDT_LEVEL1;
	node->resource.resourceDirectory = ptr;

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

				offset = resourceDirOffset + node->resource.directoryEntry->DirectoryData.data.OffsetToDirectory; // posiciona em 0x72
				ptr = LIBPE_PTR_ADD(ctx->map_addr, offset);
				if (!pe_can_read(ctx, ptr, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
					// TODO: Should we report something?
					goto _error;
				}

				node = createNode(node, RDT_RESOURCE_DIRECTORY);
				node->rootNode = rootNode;
				node->nodeLevel = RDT_LEVEL3;
				node->resource.resourceDirectory = ptr;

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

					offset = resourceDirOffset + node->lastNode->resource.directoryEntry->DirectoryData.data.OffsetToDirectory;
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


pe_final_output_t pe_get_resources(pe_ctx_t *ctx) {
	pe_final_output_t sum_output;
	sum_output.resourcesDirectory = NULL;
	sum_output.directoryEntry = NULL;
	sum_output.dataString = NULL;
	sum_output.dataEntry = NULL;
	NODE_PERES *node = discoveryNodesPeres(ctx);
	if (node == NULL) {
		//fprintf(stderr, "this file has no resources\n");
		sum_output.err = LIBPE_E_ALLOCATION_FAILURE;
		freeNodes(node);
		return sum_output;
	}

	output_node_t *output = malloc(sizeof(output_node_t));
	if (output == NULL) {
		sum_output.err = LIBPE_E_ALLOCATION_FAILURE;
		freeNodes(node);
		return sum_output;
	}
	memset(output, 0, sizeof(output_node_t));

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}

	pe_resources_count_t count = get_count(node);

	int index_resourcesDirectory = 0;
	int index_directoryEntry = 0;
	int index_dataString = 0;
	int index_dataEntry = 0;

	type_RDT_RESOURCE_DIRECTORY *resourcesDirectory = malloc(count.resourcesDirectory * sizeof(type_RDT_RESOURCE_DIRECTORY));
	type_RDT_DIRECTORY_ENTRY *directoryEntry = malloc(count.directoryEntry * sizeof(type_RDT_DIRECTORY_ENTRY));
	type_RDT_DATA_STRING *dataString = malloc(count.dataString * sizeof(type_RDT_DATA_STRING));
	type_RDT_DATA_ENTRY *dataEntry = malloc(count.dataEntry * sizeof(type_RDT_DATA_ENTRY));

	// TODO: Handle allocation failure.
	NODE_PERES *Todelete = node;
	while (node != NULL) {
		output = showNode(node, output);
		if (output == NULL)
			continue;

		if (output->kind == RDT_RESOURCE_DIRECTORY) {
			resourcesDirectory[index_resourcesDirectory] = output->node_type.resourcesDirectory;
			index_resourcesDirectory++;
		}	

		if (output->kind == RDT_DIRECTORY_ENTRY) {
			directoryEntry[index_directoryEntry] = output->node_type.directoryEntry;
			index_directoryEntry++;
		}

		if (output->kind == RDT_DATA_STRING) {
			dataString[index_dataString] = output->node_type.dataString;
			index_dataString++;
		}

		if (output->kind == RDT_DATA_ENTRY) {
			dataEntry[index_dataEntry] = output->node_type.dataEntry;
			index_dataEntry++;
		}
		node = node->nextNode;
	}
	sum_output.resourcesDirectory = resourcesDirectory;
	sum_output.directoryEntry = directoryEntry;
	sum_output.dataString = dataString;
	sum_output.dataEntry = dataEntry;

	free(output);
	freeNodes(Todelete);
	sum_output.err = LIBPE_E_OK;
	return sum_output;
}

pe_resources_count_t pe_get_resources_count(pe_ctx_t *ctx) {
	pe_resources_count_t count;
	NODE_PERES *node = discoveryNodesPeres(ctx);
	if (node == NULL) {
		//fprintf(stderr, "this file has no resources\n");
		count.resourcesDirectory = 0;
		count.directoryEntry = 0;
		count.dataString = 0;
		count.dataEntry = 0;

		return count;
	}

	count = get_count(node);
	freeNodes(node);
	return count;
}

void pe_dealloc_resources(pe_final_output_t obj){
	free(obj.resourcesDirectory);
	free(obj.directoryEntry);
	free(obj.dataString);
	free(obj.dataEntry);
}

//#include "common.h"
#include <string.h>

const char *resourceDir = "resources";

#include "udis86.h"
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	free(options);
}

output_node *showNode(const NODE_PERES *node, output_node *output)
{
	switch (node->nodeType)
	{
		default:
			return NULL;
			break;
		case RDT_RESOURCE_DIRECTORY:
		{
			const IMAGE_RESOURCE_DIRECTORY * const resourceDirectory = node->resource.resourceDirectory;
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
			const IMAGE_RESOURCE_DIRECTORY_ENTRY * const directoryEntry = node->resource.directoryEntry;

			output->kind = RDT_DIRECTORY_ENTRY;

			output->node_type.directoryEntry.NodeType = node->nodeLevel;

			output->node_type.directoryEntry.NameOffset = directoryEntry->DirectoryName.name.NameOffset;

			output->node_type.directoryEntry.NameIsString = directoryEntry->DirectoryName.name.NameIsString;

			output->node_type.directoryEntry.OffsetIsDirectory = directoryEntry->DirectoryData.data.OffsetToDirectory

			output->node_type.directoryEntry.DataIsDirectory = directoryEntry->DirectoryData.data.DataIsDirectory;

			break;
		}
		case RDT_DATA_STRING:
		{
			const IMAGE_RESOURCE_DATA_STRING * const dataString = node->resource.dataString;

			output->kind = RDT_DATA_STRING;

			output->node_type.dataString.type_RDT_DATA_STRING.NodeType = node->nodeLevel;

			outputdataStringtype_RDT_DATA_STRING.Strlen = dataString->length;

			outputtype_RDT_DATA_STRING.String = dataString->string[0];

			break;
		}
		case RDT_DATA_ENTRY:
		{
			const IMAGE_RESOURCE_DATA_ENTRY * const dataEntry = node->resource.dataEntry;

			output->kind = RDT_DATA_ENTRY;

			output->node_type.type_RDT_DATA_ENTRY.NodeType = node->nodeLevel;

			output->node_type.type_RDT_DATA_ENTRY.OffsetToData = dataEntry->offsetToData;

			output->node_type.type_RDT_DATA_ENTRY.Size = dataEntry->size;
			
			output->node_type.type_RDT_DATA_ENTRY.CodePage = dataEntry->codePage;

			output->node_type.dataEntry.CodePage = dataEntry->codePage;

			output->node_type.dataEntry.Reserved = dataEntry->reserved;
			
			break;
		}
	}
	return output;
}

final_output get_resources(pe_ctx_t *ctx) {
	NODE_PERES *node = discoveryNodesPeres(&ctx);
	if (node == NULL) {
		fprintf(stderr, "this file has no resources\n");
		return EXIT_SUCCESS;
	}

	while (node->lastNode != NULL) {
		node = node->lastNode;
	}
	output_node *output;
	output_count count = get_count(node);

	int index_resourcesDirectory = 0;
	int index_directoryEntry = 0;
	int index_dataString = 0;
	int index_dataEntry = 0;

	type_RDT_RESOURCE_DIRECTORY *resourcesDirectory = (type_RDT_RESOURCE_DIRECTORY *)malloc(count.resourceDirectory*sizeof(type_RDT_RESOURCE_DIRECTORY *));
	type_RDT_DIRECTORY_ENTRY *directoryEntry = (type_RDT_DIRECTORY_ENTRY *)malloc(count.directoryEntry*sizeof(type_RDT_DIRECTORY_ENTRY *));
	type_RDT_DATA_STRING *dataString = (type_RDT_DATA_STRING *)malloc(count.dataString*sizeof(type_RDT_DATA_STRING *));
	type_RDT_DATA_ENTRY *dataentry = (type_RDT_DATA_ENTRY *)malloc(count.dataEntry*sizeof(type_RDT_DATA_ENTRY *));

	while (node != NULL) {
		output = showNode(node, output);
		if (output.kind == RDT_RESOURCE_DIRECTORY) {
			resourcesDirectory[index_resourcesDirectory] = output->node_type.resourcesDirectory;
			index_resourcesDirectory++;
		}	
		
		if (output.kind == RDT_DIRECTORY_ENTRY) {
			directoryEntry[index_directoryEntry] = output->node_type.directoryEntry;
			index_directoryEntry++;
		}

		if (output.kind == RDT_DATA_STRING) {
			dataString[index_dataString] = output->node_type.dataString;
			index_dataString++;
		}

		if (output.kind == RDT_DATA_ENTRY) {
			dataEntry[index_dataEntry] = output->node_type.dataEntry;
			index_dataEntry++;
		}
		node = node->nextNode;
	}

final_output sum_output;
sum_output->resourceDirectory = resourcesDirectory;
sum_output->directoryEntry = directoryEntry;
sum_output->dataString = dataString;
sum_output->dataEntry = dataEntry;

	freeNodes(node);
	return sum_output;
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
	newNode->lastNode = currentNode;
	newNode->nextNode = NULL;
	newNode->nodeType = typeOfNextNode;
	currentNode->nextNode = newNode;
	return newNode;
}

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

static NODE_PERES * discoveryNodesPeres(pe_ctx_t *ctx)
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

	NODE_PERES *node = malloc_s(sizeof(NODE_PERES));
	node->lastNode = NULL; // root
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

count_output_node countNode(NODE_PERES *node) {
	count_output_node count;
	switch (node->nodeType)
	    {
				default:
					return 0;
				case RDT_RESOURCE_DIRECTORY:
				{
					count.kind = RDT_RESOURCE_DIRECTORY;
				}

				case RDT_DIRECTORY_ENTRY:
				{
					count.kind = RDT_DIRECTORY_ENTRY;
				}

				case RDT_DATA_STRING:
				{
					count.kind = RDT_DATA_STRING;
				}

				case RDT_DATA_ENTRY:
				{
					count.kind = RDT_DATA_ENTRY;
				}

	}
}

output_count get_count(NODE_PERES *node) {
	output_count count;
	int resourcesDirectory = 0;
	int directoryEntry = 0;
	int dataString = 0;
	int dataEntry = 0;

	count_output_node output;
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

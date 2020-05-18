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

#ifndef LIBPE_RESOURCES_H
#define LIBPE_RESOURCES_H

#include <stdbool.h>
#include <stdint.h>
#include "error.h"
#include "dir_resources.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBPE_RDT_LEVEL1 = 1,
	LIBPE_RDT_LEVEL2 = 2,
	LIBPE_RDT_LEVEL3 = 3
} pe_resource_level_e;

typedef enum {
	LIBPE_RDT_RESOURCE_DIRECTORY = 1,
	LIBPE_RDT_DIRECTORY_ENTRY = 2,
	LIBPE_RDT_DATA_STRING = 3,
	LIBPE_RDT_DATA_ENTRY = 4
} pe_resource_node_type_e;

typedef struct pe_resource_node {
	uint16_t depth;
	uint32_t dirLevel; // pe_resouces_level_e
	pe_resource_node_type_e type;
	char *name;
	union {
		void *raw_ptr; // We are allowed to rely on type-punning in C99, but not in C++.
		IMAGE_RESOURCE_DIRECTORY *resourceDirectory; // type == LIBPE_RDT_RESOURCE_DIRECTORY
		IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry; // type == LIBPE_RDT_DIRECTORY_ENTRY
		IMAGE_RESOURCE_DATA_STRING_U *dataString; // type == LIBPE_RDT_DATA_STRING
		IMAGE_RESOURCE_DATA_ENTRY *dataEntry; // type == LIBPE_RDT_DATA_ENTRY
	} raw;
	struct pe_resource_node *parentNode; // Points to the parent node, if any.
	struct pe_resource_node *childNode; // Points to the 1st child node, if any.
	struct pe_resource_node *nextNode; // Points to the next sibling node, if any.
} pe_resource_node_t;

typedef struct {
	pe_err_e err;
	void *resource_base_ptr; // A pointer to the beggining of the `IMAGE_RESOURCE_DIRECTORY`.
	pe_resource_node_t *root_node;
} pe_resources_t;

//
// Type Lookup for IMAGE_RESOURCE_DATA_ENTRY
//

typedef struct {
	char name[20];
	ResourceType type;
	char extension[20];
	char dir_name[20];
} pe_resource_entry_info_t;

const pe_resource_entry_info_t *pe_resource_entry_info_lookup(uint32_t name_offset);

//
// Search nodes
//

typedef bool (* pe_resource_node_predicate_fn)(const pe_resource_node_t *node);

typedef struct pe_resource_node_search_result_item {
	const pe_resource_node_t *node;
	struct pe_resource_node_search_result_item *next;
} pe_resource_node_search_result_item_t;

typedef struct {
	size_t count;
	pe_resource_node_search_result_item_t *items;
} pe_resource_node_search_result_t;

void pe_resource_search_nodes(pe_resource_node_search_result_t *result, const pe_resource_node_t *node, pe_resource_node_predicate_fn predicate);
void pe_resources_dealloc_node_search_result(pe_resource_node_search_result_t *result);

//
// Main
//

pe_resource_node_t *pe_resource_root_node(const pe_resource_node_t *node);
pe_resource_node_t *pe_resource_last_child_node(const pe_resource_node_t *parent_node);
pe_resource_node_t *pe_resource_find_node_by_type_and_level(const pe_resource_node_t *node, pe_resource_node_type_e type, uint32_t dirLevel);
pe_resource_node_t *pe_resource_find_parent_node_by_type_and_level(const pe_resource_node_t *node, pe_resource_node_type_e type, uint32_t dirLevel);
void pe_resources_dealloc(pe_resources_t *obj);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

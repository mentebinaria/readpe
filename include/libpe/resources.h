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
#include "context.h"
#include "error.h"
#include "dir_resources.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Type Lookup for IMAGE_RESOURCE_DATA_ENTRY
//

typedef struct {
	char *name;
	ResourceType type;
	char *extension;
	char *dir_name;
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
char *pe_resource_parse_string_u(pe_ctx_t *ctx, char *output, size_t output_size, const IMAGE_RESOURCE_DATA_STRING_U *data_string_ptr);
void pe_resources_dealloc(pe_resources_t *obj);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

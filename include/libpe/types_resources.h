/*
    libpe - the PE library

    Copyright (C) 2010 - 2023 libpe authors
    
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

#ifndef LIBPE_TYPES_RESOURCES_H
#define LIBPE_TYPES_RESOURCES_H

#include <stdint.h>
#include "dir_resources.h"
#include "error.h"

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

#endif

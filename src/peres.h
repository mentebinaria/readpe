/*
	pev - the PE file analyzer toolkit
	
	peres.h - definitions for peres.c

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

#ifndef PERES_H
#define PERES_H

#include "common.h"

#define PROGRAM "peres"

struct options {
	bool exportAll;
	bool infoAll;
	bool exportType;
	bool infoType;
};

typedef struct _NODE_PERES
{
	union
	{
		IMAGE_RESOURCE_DIRECTORY resourceDirectory;
		IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry;
		IMAGE_RESOURCE_DATA_STRING dataString;
		IMAGE_RESOURCE_DATA_ENTRY dataEntry;
	} node;
} NODE_PERES;

struct options config;

#endif

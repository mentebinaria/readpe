/*
	pev - the PE file analyzer toolkit
	
	pedis.h - definitions for pedis.c

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

#ifndef READPE_H 
#define READPE_H

#include "common.h"
#include "../lib/libudis86/udis86.h"

#define PROGRAM "pedis"

#define SYN_ATT 1
#define SYN_INTEL 0

struct options {
	bool all_sections;
	char *section;
	bool syntax;
	QWORD offset;
	QWORD nbytes;           // limit the number of bytes instructions. 0 means no limit.
	QWORD ninstructions;     // limit the number of disassembled instructions. 0 means no limit.
	bool entrypoint;
	bool offset_is_rva;
	WORD mode;
};

struct options config;

#endif

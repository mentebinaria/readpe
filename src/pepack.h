/*
	pev - the PE file analyzer toolkit
	
	pepack.h - definitions for packid.c

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

#ifndef PACKID_H 
#define PACKID_H

#include "common.h"
#include <strings.h>

#define PROGRAM "pepack"
#define MAX_SIG_SIZE 2048

struct options {
   char *dbfile;
};

#endif

/*
	pev - PE information dump utility

	Copyright (C) 2010 - 2011 Coding 40°

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

#include "tls.h"
#include "../defs.h"

/* this function receive the RVA of TLS directory  and print 
* the address of TLS callback functions by converting these RVA
* to an offset (subtract their section RVA and add the secion
* offset) and looping through the pointer at AddressOfCallbacks
* field. */
void get_tls_callbacks(int rva, int sec_rva, int sec_offset, int imagebase, FILE *fp)
{
	IMAGE_TLS_DIRECTORY32 dir;
	long original_pos;
	unsigned int funcaddr;
	int i=0;

	if (fp == NULL) EXIT_WITH_ERROR("null file pointer received");
	
	original_pos = ftell(fp);
	
	fseek(fp, rva - sec_rva + sec_offset, SEEK_SET);
	fread(&dir, sizeof(IMAGE_TLS_DIRECTORY32), 1, fp);
	
	printf(" TLS callbacks detected:\t");

	fseek(fp, dir.AddressOfCallBacks - imagebase - sec_rva + sec_offset, SEEK_SET);
	
	do
	{
		fread(&funcaddr, sizeof(int), 1, fp);

		if (funcaddr)
			printf("Function %d at address %#x\n\n", ++i, funcaddr);

	} while (funcaddr);
	
	/* restore position */
	fseek(fp, original_pos, SEEK_SET);	
}

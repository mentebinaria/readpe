/*
	libpe - the PE library

	Copyright (C) 2010 - 2013 libpe authors

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

#include "pe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PTR_ADD(p, o)	((void *)((char *)p + o))
#define sizeof_member(type, member) sizeof(((type *)0)->member)

int pe_load(pe_ctx_t *ctx, const char *path) {
	int ret = 0;

	ctx->path = strdup(path);
	if (ctx->path == NULL) {
		perror("strdup");
		return -1;
	}

	// Open the file.
	const int fd = open(ctx->path, O_RDWR);
	if (fd == -1) {
		perror("open");
		return -2;
	}

	// Stat the fd to retrieve the file informations.
	// If file is a symlink, fstat will stat the pointed file, not the link.
	ret = fstat(fd, &ctx->stat);
	if (ret == -1) {
		perror("fstat");
		return -3;
	}

	// Check if we're dealing with a regular file.
	if (!S_ISREG(ctx->stat.st_mode)) {
		fprintf(stderr, "%s is not a file\n", ctx->path);
		return -4;
	}

	// Create the virtual memory mapping.
	ctx->map_addr = mmap(NULL, ctx->stat.st_size, PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, 0);
	if (ctx->map_addr == MAP_FAILED) {
		perror("mmap");
		return -5; 
	}

	// We can now close the fd.
	ret = close(fd);
	if (ret == -1) {
		perror("close");
		return -6;
	}

	// Give advice about how we'll use our memory mapping.
	ret = madvise(ctx->map_addr, ctx->stat.st_size, MADV_SEQUENTIAL);
	if (ret < 0) {
		perror("madvise");
		// NOTE: This is a recoverable error. Do not abort.
	}

	return 0;
}

int pe_unload(pe_ctx_t *ctx) {
	int ret = 0;

	if (ctx->path != NULL) {
		free(ctx->path);
		ctx->path = NULL;
	}

	const off_t st_size = ctx->stat.st_size;
	memset(&ctx->stat, 0, sizeof(struct stat));

	if (ctx->map_addr != NULL) {
		ret = munmap(ctx->map_addr, st_size);
		if (ret != 0) {
			perror("munmap");
			return -1;
		}
		ctx->map_addr = NULL;
	}

	return 0;
}

int pe_parse(pe_ctx_t *ctx) {
	//int ret = 0;

	ctx->pe.dos_hdr = ctx->map_addr;
	const uint32_t *signature_ptr = PTR_ADD(ctx->pe.dos_hdr, ctx->pe.dos_hdr->e_lfanew);
	// NT signature (PE\0\0), or 16-bit Windows NE signature (NE\0\0).
	ctx->pe.signature = *signature_ptr;

	switch (ctx->pe.signature) {
		default:
			fprintf(stderr, "Invalid signature: %x\n", ctx->pe.signature);
			return -1;
		case SIGNATURE_NE:
		case SIGNATURE_PE:
			break;
	}
	
	ctx->pe.coff_hdr = PTR_ADD(signature_ptr, sizeof_member(PE_FILE, signature));
	ctx->pe.optional_hdr = PTR_ADD(ctx->pe.coff_hdr, sizeof(IMAGE_COFF_HEADER));
	ctx->pe.num_sections = ctx->pe.coff_hdr->NumberOfSections;

	switch (ctx->pe.optional_hdr->type) {
		default:
		case MAGIC_ROM:
			// TODO: Oh boy! Abort!
			break;
		case MAGIC_PE32:
			ctx->pe.optional_hdr->_32 = (IMAGE_OPTIONAL_HEADER_32 *)ctx->pe.optional_hdr;
			ctx->pe.optional_hdr->length = sizeof(IMAGE_OPTIONAL_HEADER_32);
			ctx->pe.num_directories = ctx->pe.optional_hdr->_32->NumberOfRvaAndSizes;
			break;
		case MAGIC_PE64:
			ctx->pe.optional_hdr->_64 = (IMAGE_OPTIONAL_HEADER_64 *)ctx->pe.optional_hdr;
			ctx->pe.optional_hdr->length = sizeof(IMAGE_OPTIONAL_HEADER_64);
			ctx->pe.num_directories = ctx->pe.optional_hdr->_64->NumberOfRvaAndSizes;
			break;
	}

	// TODO: Validate ctx->pe.num_directories and ctx->pe.num_sections

	ctx->pe.directories = malloc(ctx->pe.num_directories * sizeof(IMAGE_DATA_DIRECTORY *));
	ctx->pe.sections = malloc(ctx->pe.num_sections * sizeof(IMAGE_SECTION_HEADER *));
	// TODO: Check allocation failures

	ctx->pe.directories_ptr = PTR_ADD(ctx->pe.optional_hdr, ctx->pe.optional_hdr->length);
	ctx->pe.sections_ptr = ctx->pe.directories_ptr;

	for (uint32_t i = 0; i < ctx->pe.num_directories; i++) {
		ctx->pe.directories[i] = PTR_ADD(ctx->pe.directories_ptr, i * sizeof(IMAGE_DATA_DIRECTORY));
		ctx->pe.sections_ptr = PTR_ADD(ctx->pe.sections_ptr, sizeof(IMAGE_DATA_DIRECTORY));
	}

	for (uint16_t i = 0; i < ctx->pe.num_sections; i++) {
		ctx->pe.sections[i] = PTR_ADD(ctx->pe.sections_ptr, i * sizeof(IMAGE_SECTION_HEADER));
	}

	return 0;
}

bool is_pe(pe_ctx_t *ctx) {
	// check MZ header
	if (ctx->pe.dos_hdr == NULL || ctx->pe.dos_hdr->e_magic != MAGIC_MZ)
		return false;

	// check PE signature
	if (ctx->pe.signature != SIGNATURE_PE)
		return false;

	return true;
}

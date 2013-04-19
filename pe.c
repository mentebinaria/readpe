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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LIBPE_PTR_ADD(p, o)						((void *)((char *)p + o))
#define LIBPE_SIZEOF_MEMBER(type, member)		sizeof(((type *)0)->member)
#define LIBPE_IS_PAST_THE_END(ctx, ptr, type)	\
	((uintptr_t)((ptr) + sizeof(type)) > (ctx)->map_end)

const char *pe_error_msg(pe_err_e error) {
	static const char * const errors[] = {
		"no error", // LIBPE_E_OK,
		"allocation failure", // LIBPE_E_ALLOCATION_FAILURE,
		"open() failed", // LIBPE_E_OPEN_FAILED,
		"fstat() failed", // LIBPE_E_FSTAT_FAILED,
		"not a regular file", // LIBPE_E_NOT_A_FILE,
		"not a PE file", // LIBPE_E_NOT_A_PE_FILE,
		"invalid e_lfanew", // LIBPE_E_INVALID_LFANEW,
		"missing COFF header", // LIBPE_E_MISSING_COFF_HEADER,
		"missing OPTIONAL header", // LIBPE_E_MISSING_OPTIONAL_HEADER,
		"invalid signature", // LIBPE_E_INVALID_SIGNATURE,
		"unsupported image format", // LIBPE_E_UNSUPPORTED_IMAGE,
		"mmap() failed", // LIBPE_E_MMAP_FAILED,
		"munmap() failed", // LIBPE_E_MUNMAP_FAILED,
		"close() failed", // LIBPE_E_CLOSE_FAILED,
		"too many directories", // LIBPE_E_TOO_MANY_DIRECTORIES,
		"too many sections", // LIBPE_E_TOO_MANY_SECTIONS,
	};
	static const size_t index_max = sizeof(errors) / sizeof(errors[0]);
	size_t index = index_max + error;
	return (index < index_max)
		? errors[index]
		: (index == index_max)
			? errors[0] // LIBPE_E_OK
			: "invalid error code";
}

void pe_error_print(FILE *stream, pe_err_e error) {
	if (errno == 0) {
		fprintf(stream, "ERROR [%d]: %s\n", error, pe_error_msg(error));
	} else {
		char errmsg[255];
		strerror_r(errno, errmsg, sizeof(errmsg));
		fprintf(stream, "ERROR [%d]: %s (%s)\n", error, pe_error_msg(error),
			errmsg);
	}
}

pe_err_e pe_load(pe_ctx_t *ctx, const char *path) {
	int ret = 0;

	// Cleanup the whole struct.
	memset(ctx, 0, sizeof(pe_ctx_t));

	ctx->path = strdup(path);
	if (ctx->path == NULL) {
		//perror("strdup");
		return LIBPE_E_ALLOCATION_FAILURE;
	}

	// Open the file.
	const int fd = open(ctx->path, O_RDWR);
	if (fd == -1) {
		//perror("open");
		return LIBPE_E_OPEN_FAILED;
	}

	// Stat the fd to retrieve the file informations.
	// If file is a symlink, fstat will stat the pointed file, not the link.
	struct stat stat;
	ret = fstat(fd, &stat);
	if (ret == -1) {
		//perror("fstat");
		return LIBPE_E_FSTAT_FAILED;
	}

	// Check if we're dealing with a regular file.
	if (!S_ISREG(stat.st_mode)) {
		//fprintf(stderr, "%s is not a file\n", ctx->path);
		return LIBPE_E_NOT_A_FILE;
	}

	// Grab the file size.
	ctx->map_size = stat.st_size;

	// Create the virtual memory mapping.
	ctx->map_addr = mmap(NULL, ctx->map_size, PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, 0);
	if (ctx->map_addr == MAP_FAILED) {
		//perror("mmap");
		return LIBPE_E_MMAP_FAILED;
	}

	ctx->map_end = (uintptr_t)LIBPE_PTR_ADD(ctx->map_addr, ctx->map_size);

	// We can now close the fd.
	ret = close(fd);
	if (ret == -1) {
		//perror("close");
		return LIBPE_E_CLOSE_FAILED;
	}

	// Give advice about how we'll use our memory mapping.
	ret = madvise(ctx->map_addr, ctx->map_size, MADV_SEQUENTIAL);
	if (ret < 0) {
		//perror("madvise");
		// NOTE: This is a recoverable error. Do not abort.
	}

	return LIBPE_E_OK;
}

pe_err_e pe_unload(pe_ctx_t *ctx) {
	int ret = 0;

	if (ctx->path != NULL) {
		free(ctx->path);
	}

	if (ctx->map_addr != NULL) {
		ret = munmap(ctx->map_addr, ctx->map_size);
		if (ret != 0) {
			//perror("munmap");
			return LIBPE_E_MUNMAP_FAILED;
		}
	}

	// TODO: Dealloc ctx->pe internal pointers.

	// Cleanup the whole struct.
	memset(ctx, 0, sizeof(pe_ctx_t));

	return LIBPE_E_OK;
}

pe_err_e pe_parse(pe_ctx_t *ctx) {
	ctx->pe.dos_hdr = ctx->map_addr;
	if (ctx->pe.dos_hdr->e_magic != MAGIC_MZ)
		return LIBPE_E_NOT_A_PE_FILE;

	const uint32_t *signature_ptr = LIBPE_PTR_ADD(ctx->pe.dos_hdr,
		ctx->pe.dos_hdr->e_lfanew);
	if (LIBPE_IS_PAST_THE_END(ctx, signature_ptr, uint32_t))
		return LIBPE_E_INVALID_LFANEW;

	// NT signature (PE\0\0), or 16-bit Windows NE signature (NE\0\0).
	ctx->pe.signature = *signature_ptr;

	switch (ctx->pe.signature) {
		default:
			//fprintf(stderr, "Invalid signature: %x\n", ctx->pe.signature);
			return LIBPE_E_INVALID_SIGNATURE;
		case SIGNATURE_NE:
		case SIGNATURE_PE:
			break;
	}

	ctx->pe.coff_hdr = LIBPE_PTR_ADD(signature_ptr,
		LIBPE_SIZEOF_MEMBER(PE_FILE, signature));
	if (LIBPE_IS_PAST_THE_END(ctx, ctx->pe.coff_hdr, IMAGE_COFF_HEADER))
		return LIBPE_E_MISSING_COFF_HEADER;

	ctx->pe.optional_hdr = LIBPE_PTR_ADD(ctx->pe.coff_hdr,
		sizeof(IMAGE_COFF_HEADER));
	if (LIBPE_IS_PAST_THE_END(ctx, ctx->pe.optional_hdr, IMAGE_COFF_HEADER))
		return LIBPE_E_MISSING_OPTIONAL_HEADER;

	ctx->pe.num_sections = ctx->pe.coff_hdr->NumberOfSections;

	switch (ctx->pe.optional_hdr->type) {
		default:
		case MAGIC_ROM:
			// Oh boy! We do not support ROM. Abort!
			//fprintf(stderr, "ROM image is not supported\n");
			return LIBPE_E_UNSUPPORTED_IMAGE;
		case MAGIC_PE32:
			ctx->pe.optional_hdr->_32 =
				(IMAGE_OPTIONAL_HEADER_32 *)ctx->pe.optional_hdr;
			ctx->pe.optional_hdr->length = sizeof(IMAGE_OPTIONAL_HEADER_32);
			ctx->pe.num_directories =
				ctx->pe.optional_hdr->_32->NumberOfRvaAndSizes;
			break;
		case MAGIC_PE64:
			ctx->pe.optional_hdr->_64 =
				(IMAGE_OPTIONAL_HEADER_64 *)ctx->pe.optional_hdr;
			ctx->pe.optional_hdr->length = sizeof(IMAGE_OPTIONAL_HEADER_64);
			ctx->pe.num_directories =
				ctx->pe.optional_hdr->_64->NumberOfRvaAndSizes;
			break;
	}

	if (ctx->pe.num_directories > MAX_DIRECTORIES) {
		//fprintf(stderr, "Too many directories (%u)\n", ctx->pe.num_directories);
		return LIBPE_E_TOO_MANY_DIRECTORIES;
	}

	if (ctx->pe.num_sections > MAX_SECTIONS) {
		//fprintf(stderr, "Too many sections (%u)\n", ctx->pe.num_sections);
		return LIBPE_E_TOO_MANY_SECTIONS;
	}

	ctx->pe.directories_ptr = LIBPE_PTR_ADD(ctx->pe.optional_hdr,
		ctx->pe.optional_hdr->length);
	// If there are no directories, sections_ptr must point right
	// after the optional header.
	ctx->pe.sections_ptr = ctx->pe.directories_ptr;

	if (ctx->pe.num_directories > 0) {
		ctx->pe.directories = malloc(ctx->pe.num_directories
			* sizeof(IMAGE_DATA_DIRECTORY *));
		if (ctx->pe.directories == NULL)
			return LIBPE_E_ALLOCATION_FAILURE;
		for (uint32_t i = 0; i < ctx->pe.num_directories; i++) {
			ctx->pe.directories[i] = LIBPE_PTR_ADD(ctx->pe.directories_ptr,
				i * sizeof(IMAGE_DATA_DIRECTORY));
			// Calculate sections' start address.
			ctx->pe.sections_ptr = LIBPE_PTR_ADD(ctx->pe.sections_ptr,
				sizeof(IMAGE_DATA_DIRECTORY));
		}
	} else {
		ctx->pe.directories_ptr = NULL;
	}

	if (ctx->pe.num_sections > 0) {
		ctx->pe.sections = malloc(ctx->pe.num_sections
			* sizeof(IMAGE_SECTION_HEADER *));
		if (ctx->pe.sections == NULL)
			return LIBPE_E_ALLOCATION_FAILURE;
		for (uint32_t i = 0; i < ctx->pe.num_sections; i++) {
			ctx->pe.sections[i] = LIBPE_PTR_ADD(ctx->pe.sections_ptr,
				i * sizeof(IMAGE_SECTION_HEADER));
		}
	} else {
		ctx->pe.sections_ptr = NULL;
	}

	return LIBPE_E_OK;
}

bool pe_is_pe(pe_ctx_t *ctx) {
	// Check MZ header
	if (ctx->pe.dos_hdr == NULL || ctx->pe.dos_hdr->e_magic != MAGIC_MZ)
		return false;

	// Check PE signature
	if (ctx->pe.signature != SIGNATURE_PE)
		return false;

	return true;
}

uint64_t pe_filesize(pe_ctx_t *ctx) {
	return ctx->map_size;
}

// return the section of given rva
IMAGE_SECTION_HEADER *pe_rva2section(pe_ctx_t *ctx, uint64_t rva) {
	if (rva == 0 || ctx->pe.sections == NULL)
		return NULL;

	for (uint32_t i=0; i < ctx->pe.num_sections; i++) {
		if (rva >= ctx->pe.sections[i]->VirtualAddress &&
			rva <= ctx->pe.sections[i]->VirtualAddress
				+ ctx->pe.sections[i]->Misc.VirtualSize)
			return ctx->pe.sections[i];
	}
	return NULL;
}

uint64_t pe_rva2ofs(pe_ctx_t *ctx, uint64_t rva) {
	if (rva == 0 || ctx->pe.sections == NULL)
		return 0;

	for (uint32_t i=0; i < ctx->pe.num_sections; i++) {
		if (rva >= ctx->pe.sections[i]->VirtualAddress &&
			rva < (ctx->pe.sections[i]->VirtualAddress
				+ ctx->pe.sections[i]->SizeOfRawData))
			return rva - ctx->pe.sections[i]->VirtualAddress
				+ ctx->pe.sections[i]->PointerToRawData;
	}
	return 0;
}

// return a rva of given offset
uint32_t pe_ofs2rva(pe_ctx_t *ctx, uint32_t ofs) {
	if (ofs == 0 || ctx->pe.sections == NULL)
		return 0;

	for (uint32_t i=0; i < ctx->pe.num_sections; i++) {
		// if offset is inside section, return your VA in section
		if (ofs >= ctx->pe.sections[i]->PointerToRawData &&
			ofs < (ctx->pe.sections[i]->PointerToRawData
				+ ctx->pe.sections[i]->SizeOfRawData))
			return ofs + ctx->pe.sections[i]->VirtualAddress;
	}
	return 0;
}

IMAGE_DOS_HEADER *pe_dos(pe_ctx_t *ctx) {
	return ctx->pe.dos_hdr;
}

IMAGE_COFF_HEADER *pe_coff(pe_ctx_t *ctx) {
	return ctx->pe.coff_hdr;
}

IMAGE_OPTIONAL_HEADER *pe_optional(pe_ctx_t *ctx) {
	return ctx->pe.optional_hdr;
}

uint32_t pe_directories_count(pe_ctx_t *ctx) {
	return ctx->pe.num_directories;
}

IMAGE_DATA_DIRECTORY **pe_directories(pe_ctx_t *ctx) {
	return ctx->pe.directories;
}

uint32_t pe_sections_count(pe_ctx_t *ctx) {
	return ctx->pe.num_sections;
}

IMAGE_SECTION_HEADER **pe_sections(pe_ctx_t *ctx) {
	return ctx->pe.sections;
}

IMAGE_SECTION_HEADER *pe_section_by_name(pe_ctx_t *ctx, const char *name) {
	if (ctx->pe.sections == NULL || name == NULL)
		return NULL;

	size_t name_len = strlen(name);
	for (uint32_t i=0; i < ctx->pe.num_sections; i++) {
		if (memcmp(ctx->pe.sections[i]->Name, name, name_len) == 0)
			return ctx->pe.sections[i];
	}
	return NULL;
}

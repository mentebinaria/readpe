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
		close(fd);
		//perror("fstat");
		return LIBPE_E_FSTAT_FAILED;
	}

	// Check if we're dealing with a regular file.
	if (!S_ISREG(stat.st_mode)) {
		close(fd);
		//fprintf(stderr, "%s is not a file\n", ctx->path);
		return LIBPE_E_NOT_A_FILE;
	}

	// Grab the file size.
	ctx->map_size = stat.st_size;

	// Create the virtual memory mapping.
	ctx->map_addr = mmap(NULL, ctx->map_size, PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, 0);
	if (ctx->map_addr == MAP_FAILED) {
		close(fd);
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

	// Dealloc internal pointers.
	if (ctx->pe.directories != NULL) {
		free(ctx->pe.directories);
	}
	if (ctx->pe.sections != NULL) {
		free(ctx->pe.sections);
	}

	// Dealloc the virtual mapping.
	if (ctx->map_addr != NULL) {
		ret = munmap(ctx->map_addr, ctx->map_size);
		if (ret != 0) {
			//perror("munmap");
			return LIBPE_E_MUNMAP_FAILED;
		}
	}

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
	if (LIBPE_IS_PAST_THE_END(ctx, signature_ptr, sizeof(uint32_t)))
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
		LIBPE_SIZEOF_MEMBER(pe_file_t, signature));
	if (LIBPE_IS_PAST_THE_END(ctx, ctx->pe.coff_hdr,
		sizeof(IMAGE_COFF_HEADER)))
		return LIBPE_E_MISSING_COFF_HEADER;

	ctx->pe.num_sections = ctx->pe.coff_hdr->NumberOfSections;

	// Optional header points right after the COFF header.
	ctx->pe.optional_hdr_ptr = LIBPE_PTR_ADD(ctx->pe.coff_hdr,
		sizeof(IMAGE_COFF_HEADER));

	// Figure out whether it's a PE32 or PE32+.
	uint16_t *opt_type_ptr = ctx->pe.optional_hdr_ptr;
	if (LIBPE_IS_PAST_THE_END(ctx, opt_type_ptr,
		LIBPE_SIZEOF_MEMBER(IMAGE_OPTIONAL_HEADER, type)))
		return LIBPE_E_MISSING_OPTIONAL_HEADER;

	ctx->pe.optional_hdr.type = *opt_type_ptr;

	switch (ctx->pe.optional_hdr.type) {
		default:
		case MAGIC_ROM:
			// Oh boy! We do not support ROM. Abort!
			//fprintf(stderr, "ROM image is not supported\n");
			return LIBPE_E_UNSUPPORTED_IMAGE;
		case MAGIC_PE32:
			if (LIBPE_IS_PAST_THE_END(ctx, ctx->pe.optional_hdr_ptr,
				sizeof(IMAGE_OPTIONAL_HEADER_32)))
				return LIBPE_E_MISSING_OPTIONAL_HEADER;
			ctx->pe.optional_hdr._32 = ctx->pe.optional_hdr_ptr;
			ctx->pe.optional_hdr.length = sizeof(IMAGE_OPTIONAL_HEADER_32);
			ctx->pe.num_directories =
				ctx->pe.optional_hdr._32->NumberOfRvaAndSizes;
			ctx->pe.entrypoint = ctx->pe.optional_hdr._32->AddressOfEntryPoint;
			ctx->pe.imagebase = ctx->pe.optional_hdr._32->ImageBase;
			break;
		case MAGIC_PE64:
			if (LIBPE_IS_PAST_THE_END(ctx, ctx->pe.optional_hdr_ptr,
				sizeof(IMAGE_OPTIONAL_HEADER_64)))
				return LIBPE_E_MISSING_OPTIONAL_HEADER;
			ctx->pe.optional_hdr._64 = ctx->pe.optional_hdr_ptr;
			ctx->pe.optional_hdr.length = sizeof(IMAGE_OPTIONAL_HEADER_64);
			ctx->pe.num_directories =
				ctx->pe.optional_hdr._64->NumberOfRvaAndSizes;
			ctx->pe.entrypoint = ctx->pe.optional_hdr._64->AddressOfEntryPoint;
			ctx->pe.imagebase = ctx->pe.optional_hdr._64->ImageBase;
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

	ctx->pe.directories_ptr = LIBPE_PTR_ADD(ctx->pe.optional_hdr_ptr,
		ctx->pe.optional_hdr.length);
	// If there are no directories, sections_ptr will point right
	// after the OPTIONAL header.
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

bool pe_is_dll(pe_ctx_t *ctx) {
	if (ctx->pe.coff_hdr == NULL)
		return false;
	return ctx->pe.coff_hdr->Characteristics & IMAGE_FILE_DLL ? true : false;
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

// Returns the RVA for a given offset
uint64_t pe_ofs2rva(pe_ctx_t *ctx, uint64_t ofs) {
	if (ofs == 0 || ctx->pe.sections == NULL)
		return 0;

	for (uint32_t i=0; i < ctx->pe.num_sections; i++) {
		// If offset points within this section, return its VA
		if (ofs >= ctx->pe.sections[i]->PointerToRawData &&
			ofs < (ctx->pe.sections[i]->PointerToRawData
				+ ctx->pe.sections[i]->SizeOfRawData))
			return ctx->pe.sections[i]->VirtualAddress > 0 ? ofs +
ctx->pe.sections[i]->VirtualAddress : ofs + ctx->pe.imagebase;
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
	return &ctx->pe.optional_hdr;
}

uint32_t pe_directories_count(pe_ctx_t *ctx) {
	return ctx->pe.num_directories;
}

IMAGE_DATA_DIRECTORY **pe_directories(pe_ctx_t *ctx) {
	return ctx->pe.directories;
}

IMAGE_DATA_DIRECTORY *pe_directory_by_entry(pe_ctx_t *ctx, ImageDirectoryEntry entry) {
	if (ctx->pe.directories == NULL || entry > ctx->pe.num_directories - 1)
		return NULL;

	return ctx->pe.directories[entry];
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

const char *pe_machine_type_name(MachineType type) {
	typedef struct {
		MachineType type;
		const char * const name;
	} MachineEntry;

#define LIBPE_ENTRY(v)	{ v, # v }
	static const MachineEntry names[] = {
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_UNKNOWN),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_AM33),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_AMD64),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARM),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARMV7),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_CEE),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_EBC),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_I386),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_IA64),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_M32R),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_MIPS16),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_MIPSFPU),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_MIPSFPU16),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_POWERPC),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_POWERPCFP),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_R4000),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH3),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH3DSP),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH4),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH5),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_THUMB),
		LIBPE_ENTRY(IMAGE_FILE_MACHINE_WCEMIPSV2)
	};
#undef LIBPE_ENTRY

	static const size_t max_index = LIBPE_SIZEOF_ARRAY(names);
	for (size_t i=0; i < max_index; i++) {
		if (type == names[i].type)
			return names[i].name;
	}
	return NULL;
}

const char *pe_image_characteristic_name(ImageCharacteristics characteristic) {
	typedef struct {
		ImageCharacteristics characteristic;
		const char * const name;
	} ImageCharacteristicsName;

#define LIBPE_ENTRY(v)	{ v, # v }
	static const ImageCharacteristicsName names[] = {
		LIBPE_ENTRY(IMAGE_FILE_RELOCS_STRIPPED),
		LIBPE_ENTRY(IMAGE_FILE_EXECUTABLE_IMAGE),
		LIBPE_ENTRY(IMAGE_FILE_LINE_NUMS_STRIPPED),
		LIBPE_ENTRY(IMAGE_FILE_LOCAL_SYMS_STRIPPED),
		LIBPE_ENTRY(IMAGE_FILE_AGGRESSIVE_WS_TRIM),
		LIBPE_ENTRY(IMAGE_FILE_LARGE_ADDRESS_AWARE),
		LIBPE_ENTRY(IMAGE_FILE_RESERVED),
		LIBPE_ENTRY(IMAGE_FILE_BYTES_REVERSED_LO),
		LIBPE_ENTRY(IMAGE_FILE_32BIT_MACHINE),
		LIBPE_ENTRY(IMAGE_FILE_DEBUG_STRIPPED),
		LIBPE_ENTRY(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP),
		LIBPE_ENTRY(IMAGE_FILE_NET_RUN_FROM_SWAP),
		LIBPE_ENTRY(IMAGE_FILE_SYSTEM),
		LIBPE_ENTRY(IMAGE_FILE_DLL),
		LIBPE_ENTRY(IMAGE_FILE_UP_SYSTEM_ONLY),
		LIBPE_ENTRY(IMAGE_FILE_BYTES_REVERSED_HI)
	};
#undef LIBPE_ENTRY

	static const size_t max_index = LIBPE_SIZEOF_ARRAY(names);
	for (size_t i=0; i < max_index; i++) {
		if (characteristic == names[i].characteristic)
			return names[i].name;
	}
	return NULL;
}

const char *pe_windows_subsystem_name(WindowsSubsystem subsystem) {
	typedef struct {
		WindowsSubsystem subsystem;
		const char * const name;
	} WindowsSubsystemName;

#define LIBPE_ENTRY(v)	{ v, # v }
	static const WindowsSubsystemName names[] = {
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_UNKNOWN),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_NATIVE),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_GUI),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_CUI),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_POSIX_CUI),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_APPLICATION),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_ROM),
		LIBPE_ENTRY(IMAGE_SUBSYSTEM_XBOX),
	};
#undef LIBPE_ENTRY

	static const size_t max_index = LIBPE_SIZEOF_ARRAY(names);
	for (size_t i=0; i < max_index; i++) {
		if (subsystem == names[i].subsystem)
			return names[i].name;
	}
	return NULL;
}

const char *pe_directory_name(ImageDirectoryEntry entry) {
	typedef struct {
		ImageDirectoryEntry entry;
		const char * const name;
	} ImageDirectoryEntryName;

#define LIBPE_ENTRY(v)	{ v, # v }
	static const ImageDirectoryEntryName names[] = {
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_EXPORT),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_IMPORT),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_RESOURCE),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_SECURITY),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_BASERELOC),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_DEBUG),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_GLOBALPTR),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_TLS),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_IAT),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT),
		LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
		LIBPE_ENTRY(IMAGE_DIRECTORY_RESERVED)
	};
#undef LIBPE_ENTRY

	static const size_t max_index = LIBPE_SIZEOF_ARRAY(names);
	for (size_t i=0; i < max_index; i++) {
		if (entry == names[i].entry)
			return names[i].name;
	}
	return NULL;
}

const char *pe_section_characteristic_name(SectionCharacteristics characteristic) {
	typedef struct {
		SectionCharacteristics characteristic;
		const char * const name;
	} SectionCharacteristicsName;

#define LIBPE_ENTRY(v)	{ v, # v }
	static const SectionCharacteristicsName names[] = {
		LIBPE_ENTRY(IMAGE_SCN_TYPE_NO_PAD),
		LIBPE_ENTRY(IMAGE_SCN_CNT_CODE),
		LIBPE_ENTRY(IMAGE_SCN_CNT_INITIALIZED_DATA),
		LIBPE_ENTRY(IMAGE_SCN_CNT_UNINITIALIZED_DATA),
		LIBPE_ENTRY(IMAGE_SCN_LNK_OTHER),
		LIBPE_ENTRY(IMAGE_SCN_LNK_INFO),
		LIBPE_ENTRY(IMAGE_SCN_LNK_REMOVE),
		LIBPE_ENTRY(IMAGE_SCN_LNK_COMDAT),
		LIBPE_ENTRY(IMAGE_SCN_NO_DEFER_SPEC_EXC),
		LIBPE_ENTRY(IMAGE_SCN_GPREL),
		LIBPE_ENTRY(IMAGE_SCN_MEM_PURGEABLE),
		LIBPE_ENTRY(IMAGE_SCN_MEM_LOCKED),
		LIBPE_ENTRY(IMAGE_SCN_MEM_PRELOAD),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_1BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_2BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_4BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_8BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_16BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_32BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_64BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_128BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_256BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_512BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_1024BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_2048BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_4096BYTES),
		LIBPE_ENTRY(IMAGE_SCN_ALIGN_8192BYTES),
		LIBPE_ENTRY(IMAGE_SCN_LNK_NRELOC_OVFL),
		LIBPE_ENTRY(IMAGE_SCN_MEM_DISCARDABLE),
		LIBPE_ENTRY(IMAGE_SCN_MEM_NOT_CACHED),
		LIBPE_ENTRY(IMAGE_SCN_MEM_NOT_PAGED),
		LIBPE_ENTRY(IMAGE_SCN_MEM_SHARED),
		LIBPE_ENTRY(IMAGE_SCN_MEM_EXECUTE),
		LIBPE_ENTRY(IMAGE_SCN_MEM_READ),
		LIBPE_ENTRY(IMAGE_SCN_MEM_WRITE)
	};
#undef LIBPE_ENTRY

	static const size_t max_index = LIBPE_SIZEOF_ARRAY(names);
	for (size_t i=0; i < max_index; i++) {
		if (characteristic == names[i].characteristic)
			return names[i].name;
	}
	return NULL;
}

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

#include "libpe/pe.h"
#include "libpe/macros.h"
#include "libpe/resources.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

bool pe_can_read(const pe_ctx_t *ctx, const void *ptr, size_t size)
{
    const uintptr_t start = (uintptr_t)ptr;
    const uintptr_t end = start + size;
    return start >= (uintptr_t)ctx->map_addr && end <= (uintptr_t)ctx->map_end;
}

pe_err_e pe_load_file(pe_ctx_t *ctx, const char *path)
{
    return pe_load_file_ext(ctx, path, 0);
}

pe_err_e pe_load_file_ext(pe_ctx_t *ctx, const char *path, pe_options_e options)
{
    // Cleanup the whole struct.
    memset(ctx, 0, sizeof(pe_ctx_t));

    ctx->path = strdup(path);
    if (ctx->path == NULL) {
        // perror("strdup");
        return LIBPE_E_ALLOCATION_FAILURE;
    }

    // Open the file.
    int oflag = options & LIBPE_OPT_OPEN_RW ? O_RDWR : O_RDONLY;
    const int fd = open(ctx->path, oflag);
    if (fd == -1) {
        // perror("open");
        return LIBPE_E_OPEN_FAILED;
    }

    int ret = 0;

    // Stat the fd to retrieve the file informations.
    // If file is a symlink, fstat will stat the pointed file, not the link.
    struct stat stat;
    ret = fstat(fd, &stat);
    if (ret == -1) {
        close(fd);
        // perror("fstat");
        return LIBPE_E_FSTAT_FAILED;
    }

    // Check if we're dealing with a regular file.
    if (!S_ISREG(stat.st_mode)) {
        close(fd);
        // fprintf(stderr, "%s is not a file\n", ctx->path);
        return LIBPE_E_NOT_A_FILE;
    }

    // Grab the file size.
    ctx->map_size = stat.st_size;

    // Create the virtual memory mapping.
    int mprot = options & LIBPE_OPT_OPEN_RW
                    ? PROT_READ | PROT_WRITE /* Pages may be written */
                    : PROT_READ;
    // MAP_SHARED makes updates to the mapping visible to other processes that
    // map this file. The file may not actually be updated until msync(2) or
    // munmap() is called.
    int mflags = options & LIBPE_OPT_OPEN_RW ? MAP_SHARED : MAP_PRIVATE;
    ctx->map_addr = mmap(NULL, (size_t)ctx->map_size, mprot, mflags, fd, 0);
    if (ctx->map_addr == MAP_FAILED) {
        close(fd);
        // perror("mmap");
        return LIBPE_E_MMAP_FAILED;
    }

    ctx->map_end = (uintptr_t)LIBPE_PTR_ADD(ctx->map_addr, ctx->map_size);

    if (options & LIBPE_OPT_NOCLOSE_FD) {
        // The file descriptor is not dup'ed, and will be closed when the stream
        // created by fdopen() is closed.
        FILE *fp = fdopen(fd, options & LIBPE_OPT_OPEN_RW
                                  ? "r+b"
                                  : "rb"); // NOTE: 'b' is ignored on all POSIX
                                           // conforming systems.
        if (fp == NULL) {
            // perror("fdopen");
            return LIBPE_E_FDOPEN_FAILED;
        }
        ctx->stream = fp;
    } else {
        // We can now close the fd.
        ret = close(fd);
        if (ret == -1) {
            // perror("close");
            return LIBPE_E_CLOSE_FAILED;
        }
    }

    // Give advice about how we'll use our memory mapping.
    ret = madvise(ctx->map_addr, (size_t)ctx->map_size, MADV_SEQUENTIAL);
    if (ret < 0) {
        // perror("madvise");
        //  NOTE: This is a recoverable error. Do not abort.
    }

    OpenSSL_add_all_digests();

    return LIBPE_E_OK;
}

static void cleanup_cached_data(pe_ctx_t *ctx)
{
    pe_imports_dealloc(ctx->cached_data.imports);
    pe_exports_dealloc(ctx->cached_data.exports);
    pe_hash_headers_dealloc(ctx->cached_data.hash_headers);
    pe_hash_sections_dealloc(ctx->cached_data.hash_sections);
    pe_hash_dealloc(ctx->cached_data.hash_file);
    pe_resources_dealloc(ctx->cached_data.resources);
    memset(&ctx->cached_data, 0, sizeof(pe_cached_data_t));
}

pe_err_e pe_unload(pe_ctx_t *ctx)
{
    if (ctx->stream != NULL) {
        fclose(ctx->stream);
    }

    free(ctx->path);

    // Dealloc internal pointers.
    free(ctx->pe.directories);
    free(ctx->pe.sections);

    cleanup_cached_data(ctx);

    // Dealloc the virtual mapping.
    if (ctx->map_addr != NULL) {
        int ret = munmap(ctx->map_addr, (size_t)ctx->map_size);
        if (ret != 0) {
            // perror("munmap");
            return LIBPE_E_MUNMAP_FAILED;
        }
    }

    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup(); // Clean OpenSSL_add_all_digests.

    // Cleanup the whole struct.
    memset(ctx, 0, sizeof(pe_ctx_t));

    return LIBPE_E_OK;
}

pe_err_e pe_parse(pe_ctx_t *ctx)
{
    ctx->pe.dos_hdr = ctx->map_addr;
    if (ctx->pe.dos_hdr->e_magic == MAGIC_MZ) {
        const uint32_t *signature_ptr
            = LIBPE_PTR_ADD(ctx->pe.dos_hdr, ctx->pe.dos_hdr->e_lfanew);
        if (!pe_can_read(ctx, signature_ptr,
                         LIBPE_SIZEOF_MEMBER(pe_file_t, signature))) {
            return LIBPE_E_INVALID_LFANEW;
        }

        // NT signature (PE\0\0)
        ctx->pe.signature = *signature_ptr;

        switch (ctx->pe.signature) {
        default:
            // fprintf(stderr, "Invalid signature: %x\n", ctx->pe.signature);
            return LIBPE_E_INVALID_SIGNATURE;
        case SIGNATURE_PE:
            break;
        }

        ctx->pe.coff_hdr = LIBPE_PTR_ADD(
            signature_ptr, LIBPE_SIZEOF_MEMBER(pe_file_t, signature));

    } else if (pe_machine_type_name(ctx->pe.dos_hdr->e_magic) != NULL) {
        ctx->pe.coff_hdr = (void *)ctx->pe.dos_hdr;
        ctx->pe.dos_hdr = NULL;
    } else {
        return LIBPE_E_NOT_A_PE_FILE;
    }

    if (!pe_can_read(ctx, ctx->pe.coff_hdr, sizeof(IMAGE_COFF_HEADER))) {
        return LIBPE_E_MISSING_COFF_HEADER;
    }

    ctx->pe.num_sections = ctx->pe.coff_hdr->NumberOfSections;

    if (ctx->pe.coff_hdr->SizeOfOptionalHeader > 0) {

        // Optional header points right after the COFF header.
        ctx->pe.optional_hdr_ptr
            = LIBPE_PTR_ADD(ctx->pe.coff_hdr, sizeof(IMAGE_COFF_HEADER));

        // Figure out whether it's a PE32 or PE32+.
        uint16_t *opt_type_ptr = ctx->pe.optional_hdr_ptr;
        if (!pe_can_read(ctx, opt_type_ptr,
                         LIBPE_SIZEOF_MEMBER(IMAGE_OPTIONAL_HEADER, type))) {
            return LIBPE_E_MISSING_OPTIONAL_HEADER;
        }

        ctx->pe.optional_hdr.type = *opt_type_ptr;

        switch (ctx->pe.optional_hdr.type) {
        default:
            return LIBPE_E_UNSUPPORTED_IMAGE;
        case MAGIC_ROM:
            if (ctx->pe.coff_hdr->SizeOfOptionalHeader
                != sizeof(IMAGE_ROM_OPTIONAL_HEADER)) {
                return LIBPE_E_UNSUPPORTED_IMAGE;
            }
            if (!pe_can_read(ctx, ctx->pe.optional_hdr_ptr,
                             sizeof(IMAGE_ROM_OPTIONAL_HEADER))) {
                return LIBPE_E_MISSING_OPTIONAL_HEADER;
            }
            ctx->pe.optional_hdr._rom = ctx->pe.optional_hdr_ptr;
            ctx->pe.optional_hdr.length = sizeof(IMAGE_ROM_OPTIONAL_HEADER);
            ctx->pe.entrypoint = ctx->pe.optional_hdr._rom->AddressOfEntryPoint;
            break;
        case MAGIC_PE32:
            if (ctx->pe.coff_hdr->SizeOfOptionalHeader
                < sizeof(IMAGE_OPTIONAL_HEADER_32)) {
                return LIBPE_E_UNSUPPORTED_IMAGE;
            }
            if (!pe_can_read(ctx, ctx->pe.optional_hdr_ptr,
                             sizeof(IMAGE_OPTIONAL_HEADER_32))) {
                return LIBPE_E_MISSING_OPTIONAL_HEADER;
            }
            ctx->pe.optional_hdr._32 = ctx->pe.optional_hdr_ptr;
            ctx->pe.optional_hdr.length = sizeof(IMAGE_OPTIONAL_HEADER_32);
            ctx->pe.num_directories
                = ctx->pe.optional_hdr._32->NumberOfRvaAndSizes;
            ctx->pe.entrypoint = ctx->pe.optional_hdr._32->AddressOfEntryPoint;
            ctx->pe.imagebase = ctx->pe.optional_hdr._32->ImageBase;
            break;
        case MAGIC_PE64:
            if (ctx->pe.coff_hdr->SizeOfOptionalHeader
                < sizeof(IMAGE_OPTIONAL_HEADER_64)) {
                return LIBPE_E_UNSUPPORTED_IMAGE;
            }
            if (!pe_can_read(ctx, ctx->pe.optional_hdr_ptr,
                             sizeof(IMAGE_OPTIONAL_HEADER_64))) {
                return LIBPE_E_MISSING_OPTIONAL_HEADER;
            }
            ctx->pe.optional_hdr._64 = ctx->pe.optional_hdr_ptr;
            ctx->pe.optional_hdr.length = sizeof(IMAGE_OPTIONAL_HEADER_64);
            ctx->pe.num_directories
                = ctx->pe.optional_hdr._64->NumberOfRvaAndSizes;
            ctx->pe.entrypoint = ctx->pe.optional_hdr._64->AddressOfEntryPoint;
            ctx->pe.imagebase = ctx->pe.optional_hdr._64->ImageBase;
            break;
        }
    }

    if (ctx->pe.num_directories > MAX_DIRECTORIES) {
        // fprintf(stderr, "Too many directories (%u)\n",
        // ctx->pe.num_directories);
        return LIBPE_E_TOO_MANY_DIRECTORIES;
    }

    if (ctx->pe.num_sections > MAX_SECTIONS) {
        // fprintf(stderr, "Too many sections (%u)\n", ctx->pe.num_sections);
        return LIBPE_E_TOO_MANY_SECTIONS;
    }

    if (ctx->pe.optional_hdr_ptr) {
        ctx->pe.directories_ptr = LIBPE_PTR_ADD(ctx->pe.optional_hdr_ptr,
                                                ctx->pe.optional_hdr.length);
    }

    uint32_t sections_offset
        = sizeof(IMAGE_FILE_HEADER)
          + (uint32_t)ctx->pe.coff_hdr->SizeOfOptionalHeader;
    ctx->pe.sections_ptr = LIBPE_PTR_ADD(ctx->pe.coff_hdr, sections_offset);

    if (ctx->pe.num_directories > 0) {
        ctx->pe.directories
            = malloc(ctx->pe.num_directories * sizeof(IMAGE_DATA_DIRECTORY *));
        if (ctx->pe.directories == NULL) {
            return LIBPE_E_ALLOCATION_FAILURE;
        }
        for (uint32_t i = 0; i < ctx->pe.num_directories; i++) {
            ctx->pe.directories[i] = LIBPE_PTR_ADD(
                ctx->pe.directories_ptr, i * sizeof(IMAGE_DATA_DIRECTORY));
        }
    } else {
        ctx->pe.directories_ptr = NULL;
    }

    if (ctx->pe.num_sections > 0) {
        ctx->pe.sections
            = malloc(ctx->pe.num_sections * sizeof(IMAGE_SECTION_HEADER *));
        if (ctx->pe.sections == NULL) {
            return LIBPE_E_ALLOCATION_FAILURE;
        }
        for (uint32_t i = 0; i < ctx->pe.num_sections; i++) {
            ctx->pe.sections[i] = LIBPE_PTR_ADD(
                ctx->pe.sections_ptr, i * sizeof(IMAGE_SECTION_HEADER));
        }
    } else {
        ctx->pe.sections_ptr = NULL;
    }

    if (ctx->pe.coff_hdr->PointerToSymbolTable != 0) {
        uint32_t symbols_offset = ctx->pe.coff_hdr->PointerToSymbolTable;
        if (symbols_offset < ctx->map_size) {
            ctx->pe.symbols_ptr = LIBPE_PTR_ADD(ctx->map_addr, symbols_offset);
            ctx->pe.num_symbols = ctx->pe.coff_hdr->NumberOfSymbols;
            if (symbols_offset + ctx->pe.num_symbols * 18 < ctx->map_size) {
                ctx->pe.strings_ptr = LIBPE_PTR_ADD(ctx->pe.symbols_ptr,
                                                    ctx->pe.num_symbols * 18);
                ctx->pe.strings_size = *(uint32_t *)ctx->pe.strings_ptr;
                if (ctx->pe.strings_size < 4
                    || symbols_offset + ctx->pe.num_symbols * 18
                               + ctx->pe.strings_size
                           > ctx->map_size) {
                    ctx->pe.strings_ptr = NULL;
                    ctx->pe.strings_size = 0;
                }
            }
            if (ctx->pe.num_symbols == 0) {
                ctx->pe.symbols_ptr = NULL;
            }
        }
    }

    return LIBPE_E_OK;
}

bool pe_is_loaded(const pe_ctx_t *ctx)
{
    return ctx->map_addr != NULL && ctx->map_size > 0;
}

bool pe_is_pe(const pe_ctx_t *ctx)
{
    return pe_is_exec(ctx) || pe_is_obj(ctx) || pe_is_rom(ctx);
}

bool pe_is_exec(const pe_ctx_t *ctx)
{
    // Check MZ header
    if (ctx->pe.dos_hdr == NULL || ctx->pe.dos_hdr->e_magic != MAGIC_MZ) {
        return false;
    }

    // Check PE signature
    if (ctx->pe.signature != SIGNATURE_PE) {
        return false;
    }

    return true;
}

bool pe_is_obj(const pe_ctx_t *ctx)
{
    // Object file does not have neither MZ header nor PE\0\0 signature nor
    // optional header
    if (ctx->pe.dos_hdr != NULL || ctx->pe.signature != 0
        || ctx->pe.optional_hdr_ptr != NULL) {
        return false;
    }

    return true;
}

bool pe_is_rom(const pe_ctx_t *ctx)
{
    // ROM file does not have neither MZ header nor PE\0\0 signature
    if (ctx->pe.dos_hdr != NULL || ctx->pe.signature != 0) {
        return false;
    }

    // ROM file has either MAGIC_ROM optional header (R3000, R4000, R10000,
    // ALPHA) or MAGIC_PE32 optional header (I386, MPPC_601, POWERPC, ...)
    if (ctx->pe.optional_hdr_ptr == NULL
        || (ctx->pe.optional_hdr.type != MAGIC_ROM
            && ctx->pe.optional_hdr.type != MAGIC_PE32)) {
        return false;
    }

    return true;
}

bool pe_is_dll(const pe_ctx_t *ctx)
{
    if (!pe_is_exec(ctx)) {
        return false;
    }
    if (ctx->pe.coff_hdr == NULL) {
        return false;
    }
    return ctx->pe.coff_hdr->Characteristics & IMAGE_FILE_DLL ? true : false;
}

uint64_t pe_filesize(const pe_ctx_t *ctx) { return (uint64_t)ctx->map_size; }

// return the section of given rva
IMAGE_SECTION_HEADER *pe_rva2section(pe_ctx_t *ctx, uint64_t rva)
{
    if (rva == 0 || ctx->pe.sections == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < ctx->pe.num_sections; i++) {
        const uint64_t start = ctx->pe.sections[i]->VirtualAddress;
        const uint64_t end = ctx->pe.sections[i]->VirtualAddress
                             + ctx->pe.sections[i]->Misc.VirtualSize;
        if (rva >= start && rva <= end) {
            return ctx->pe.sections[i];
        }
    }
    return NULL;
}

// Converts a RVA (Relative Virtual Address) to a raw file offset
uint64_t pe_rva2ofs(const pe_ctx_t *ctx, uint64_t rva)
{
    if (rva == 0) {
        return 0;
    }

    if (ctx->pe.sections == NULL) {
        return rva;
    }

    // Find out which section the given RVA belongs
    for (uint32_t i = 0; i < ctx->pe.num_sections; i++) {
        if (ctx->pe.sections[i] == NULL) {
            return 0;
        }

        // Use SizeOfRawData if VirtualSize == 0
        size_t section_size = ctx->pe.sections[i]->Misc.VirtualSize;
        if (section_size == 0) {
            section_size = ctx->pe.sections[i]->SizeOfRawData;
        }

        if (ctx->pe.sections[i]->VirtualAddress <= rva) {
            if ((ctx->pe.sections[i]->VirtualAddress + section_size) > rva) {
                rva -= ctx->pe.sections[i]->VirtualAddress;
                rva += ctx->pe.sections[i]->PointerToRawData;
                return rva;
            }
        }
    }

    // Handle PE with a single section
    if (ctx->pe.num_sections == 1) {
        rva -= ctx->pe.sections[0]->VirtualAddress;
        rva += ctx->pe.sections[0]->PointerToRawData;
        return rva;
    }

    return rva; // PE with no sections, return RVA
}

// Returns the RVA for a given offset
uint64_t pe_ofs2rva(const pe_ctx_t *ctx, uint64_t ofs)
{
    if (ofs == 0 || ctx->pe.sections == NULL) {
        return 0;
    }

    for (uint32_t i = 0; i < ctx->pe.num_sections; i++) {
        if (ctx->pe.sections[i] == NULL) {
            return 0;
        }

        if (ctx->pe.sections[i]->PointerToRawData <= ofs) {
            if ((ctx->pe.sections[i]->PointerToRawData
                 + ctx->pe.sections[i]->SizeOfRawData)
                > ofs) {
                ofs -= ctx->pe.sections[i]->PointerToRawData;
                ofs += ctx->pe.sections[i]->VirtualAddress;
                return ofs;
            }
        }
    }
    return 0;
}

IMAGE_DOS_HEADER *pe_dos(pe_ctx_t *ctx) { return ctx->pe.dos_hdr; }

IMAGE_COFF_HEADER *pe_coff(pe_ctx_t *ctx) { return ctx->pe.coff_hdr; }

IMAGE_OPTIONAL_HEADER *pe_optional(pe_ctx_t *ctx)
{
    if (ctx->pe.optional_hdr_ptr == NULL) {
        return NULL;
    }
    return &ctx->pe.optional_hdr;
}

uint32_t pe_directories_count(const pe_ctx_t *ctx)
{
    return ctx->pe.num_directories;
}

IMAGE_DATA_DIRECTORY **pe_directories(pe_ctx_t *ctx)
{
    return ctx->pe.directories;
}

IMAGE_DATA_DIRECTORY *pe_directory_by_entry(pe_ctx_t *ctx,
                                            ImageDirectoryEntry entry)
{
    if (ctx->pe.directories == NULL || entry > ctx->pe.num_directories - 1) {
        return NULL;
    }

    return ctx->pe.directories[entry];
}

uint16_t pe_sections_count(const pe_ctx_t *ctx) { return ctx->pe.num_sections; }

IMAGE_SECTION_HEADER **pe_sections(pe_ctx_t *ctx) { return ctx->pe.sections; }

IMAGE_SECTION_HEADER *pe_section_by_name(pe_ctx_t *ctx, const char *name)
{
    if (ctx->pe.sections == NULL || name == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < ctx->pe.num_sections; i++) {
        if (strncmp((const char *)ctx->pe.sections[i]->Name, name,
                    SECTION_NAME_SIZE)
            == 0) {
            return ctx->pe.sections[i];
        }
    }
    return NULL;
}

const char *pe_section_name(const pe_ctx_t *ctx,
                            const IMAGE_SECTION_HEADER *section_hdr,
                            char *out_name, size_t out_name_size)
{
    assert(ctx != NULL);
    assert(out_name_size >= SECTION_NAME_SIZE + 1);
    strncpy(out_name, (const char *)section_hdr->Name, SECTION_NAME_SIZE);
    out_name[SECTION_NAME_SIZE] = '\0';
    if (out_name[0] == '/' && out_name[1] >= '0' && out_name[1] <= '9'
        && ctx->pe.strings_ptr) {
        char *endptr = NULL;
        long int offset = -1;
        errno = 0;
        offset = strtol(out_name + 1, &endptr, 10);
        if (errno == 0 && *endptr == 0 && offset >= 0
            && offset < ctx->pe.strings_size) {
            return ctx->pe.strings_ptr + offset;
        }
    }
    return out_name;
}

#define LIBPE_ENTRY(v) {v, #v}

const char *pe_machine_type_name(MachineType type)
{
    typedef struct {
        MachineType type;
        const char *const name;
    } MachineEntry;

    static const MachineEntry names[]
        = {LIBPE_ENTRY(IMAGE_FILE_MACHINE_UNKNOWN),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ALPHA_OLD),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ALPHA),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ALPHA64),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_AM33),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_AMD64),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARM),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARMV7),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARM64),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARM64EC),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_ARM64X),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_CEE),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_CEF),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_CHPE_X86),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_EBC),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_I386),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_I860),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_IA64),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_LOONGARCH32),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_LOONGARCH64),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_M32R),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_M68K),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_MIPS16),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_MIPSFPU),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_MIPSFPU16),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_MPPC_601),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_OMNI),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_PARISC),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_POWERPC),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_POWERPCFP),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_POWERPCBE),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_R3000),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_R3000_BE),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_R4000),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_R10000),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_RISCV32),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_RISCV64),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_RISCV128),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH3),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH3DSP),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH3E),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH4),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_SH5),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_TRICORE),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_THUMB),
           LIBPE_ENTRY(IMAGE_FILE_MACHINE_WCEMIPSV2)};

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (type == names[i].type) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *pe_image_characteristic_name(ImageCharacteristics characteristic)
{
    typedef struct {
        ImageCharacteristics characteristic;
        const char *const name;
    } ImageCharacteristicsName;

    static const ImageCharacteristicsName names[]
        = {LIBPE_ENTRY(IMAGE_FILE_RELOCS_STRIPPED),
           LIBPE_ENTRY(IMAGE_FILE_EXECUTABLE_IMAGE),
           LIBPE_ENTRY(IMAGE_FILE_LINE_NUMS_STRIPPED),
           LIBPE_ENTRY(IMAGE_FILE_LOCAL_SYMS_STRIPPED),
           LIBPE_ENTRY(IMAGE_FILE_AGGRESSIVE_WS_TRIM),
           LIBPE_ENTRY(IMAGE_FILE_LARGE_ADDRESS_AWARE),
           LIBPE_ENTRY(IMAGE_FILE_16BIT_MACHINE),
           LIBPE_ENTRY(IMAGE_FILE_BYTES_REVERSED_LO),
           LIBPE_ENTRY(IMAGE_FILE_32BIT_MACHINE),
           LIBPE_ENTRY(IMAGE_FILE_DEBUG_STRIPPED),
           LIBPE_ENTRY(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP),
           LIBPE_ENTRY(IMAGE_FILE_NET_RUN_FROM_SWAP),
           LIBPE_ENTRY(IMAGE_FILE_SYSTEM),
           LIBPE_ENTRY(IMAGE_FILE_DLL),
           LIBPE_ENTRY(IMAGE_FILE_UP_SYSTEM_ONLY),
           LIBPE_ENTRY(IMAGE_FILE_BYTES_REVERSED_HI)};

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (characteristic == names[i].characteristic) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *
pe_image_dllcharacteristic_name(ImageDllCharacteristics characteristic)
{
    typedef struct {
        ImageDllCharacteristics characteristic;
        const char *const name;
    } ImageDllCharacteristicsName;

    static const ImageDllCharacteristicsName names[]
        = {LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_NO_SEH),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_NO_BIND),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_APPCONTAINER),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_GUARD_CF),
           LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)};

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (characteristic == names[i].characteristic) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *
pe_dll_image_dllcharacteristic_name(ImageDllCharacteristics characteristic)
{
    typedef struct {
        ImageDllCharacteristics characteristic;
        const char *const name;
    } ImageDllCharacteristicsName;

    static const ImageDllCharacteristicsName names[] = {
        LIBPE_ENTRY(IMAGE_LIBRARY_PROCESS_INIT),
        LIBPE_ENTRY(IMAGE_LIBRARY_PROCESS_TERM),
        LIBPE_ENTRY(IMAGE_LIBRARY_THREAD_INIT),
        LIBPE_ENTRY(IMAGE_LIBRARY_THREAD_TERM),
        LIBPE_ENTRY(IMAGE_DLLCHARACTERISTICS_X86_THUNK),
    };

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (characteristic == names[i].characteristic) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *pe_image_loader_flags_name(ImageLoaderFlags flags)
{
    typedef struct {
        ImageLoaderFlags flags;
        const char *const name;
    } ImageLoaderFlagsName;

    static const ImageLoaderFlagsName names[] = {
        LIBPE_ENTRY(IMAGE_LOADER_FLAGS_COMPLUS),
        LIBPE_ENTRY(IMAGE_LOADER_FLAGS_SYSTEM_GLOBAL),
    };

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (flags == names[i].flags) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *pe_dll_image_loader_flags_name(ImageLoaderFlags flags)
{
    typedef struct {
        ImageLoaderFlags flags;
        const char *const name;
    } ImageLoaderFlagsName;

    static const ImageLoaderFlagsName names[] = {
        LIBPE_ENTRY(IMAGE_LOADER_FLAGS_BREAK_ON_LOAD),
        LIBPE_ENTRY(IMAGE_LOADER_FLAGS_DEBUG_ON_LOAD),
    };

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (flags == names[i].flags) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *pe_windows_subsystem_name(WindowsSubsystem subsystem)
{
    typedef struct {
        WindowsSubsystem subsystem;
        const char *const name;
    } WindowsSubsystemName;

    static const WindowsSubsystemName names[]
        = {LIBPE_ENTRY(IMAGE_SUBSYSTEM_UNKNOWN),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_NATIVE),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_GUI),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_CUI),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_OLD_CE_GUI),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_OS2_CUI),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_POSIX_CUI),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_MMOSA),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_APPLICATION),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_EFI_ROM),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_XBOX),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION),
           LIBPE_ENTRY(IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG)};

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (subsystem == names[i].subsystem) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *pe_directory_name(ImageDirectoryEntry entry)
{
    typedef struct {
        ImageDirectoryEntry entry;
        const char *const name;
    } ImageDirectoryEntryName;

    static const ImageDirectoryEntryName names[]
        = {LIBPE_ENTRY(IMAGE_DIRECTORY_ENTRY_EXPORT),
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
           LIBPE_ENTRY(IMAGE_DIRECTORY_RESERVED)};

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (entry == names[i].entry) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *
pe_section_characteristic_name(SectionCharacteristics characteristic)
{
    typedef struct {
        SectionCharacteristics characteristic;
        const char *const name;
    } SectionCharacteristicsName;

    static const SectionCharacteristicsName names[]
        = {LIBPE_ENTRY(IMAGE_SCN_SCALE_INDEX),
           LIBPE_ENTRY(IMAGE_SCN_TYPE_NO_LOAD),
           LIBPE_ENTRY(IMAGE_SCN_TYPE_GROUPED),
           LIBPE_ENTRY(IMAGE_SCN_TYPE_NO_PAD),
           LIBPE_ENTRY(IMAGE_SCN_TYPE_COPY),
           LIBPE_ENTRY(IMAGE_SCN_CNT_CODE),
           LIBPE_ENTRY(IMAGE_SCN_CNT_INITIALIZED_DATA),
           LIBPE_ENTRY(IMAGE_SCN_CNT_UNINITIALIZED_DATA),
           LIBPE_ENTRY(IMAGE_SCN_LNK_OTHER),
           LIBPE_ENTRY(IMAGE_SCN_LNK_INFO),
           LIBPE_ENTRY(IMAGE_SCN_LNK_OVERLAY),
           LIBPE_ENTRY(IMAGE_SCN_LNK_REMOVE),
           LIBPE_ENTRY(IMAGE_SCN_LNK_COMDAT),
           LIBPE_ENTRY(IMAGE_SCN_NO_DEFER_SPEC_EXC),
           LIBPE_ENTRY(IMAGE_SCN_GPREL),
           LIBPE_ENTRY(IMAGE_SCN_MEM_16BIT),
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
           LIBPE_ENTRY(IMAGE_SCN_MEM_WRITE)};

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (characteristic == names[i].characteristic) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *
pe_m68k_section_characteristic_name(SectionCharacteristics characteristic)
{
    typedef struct {
        SectionCharacteristics characteristic;
        const char *const name;
    } SectionCharacteristicsName;

    static const SectionCharacteristicsName names[] = {
        LIBPE_ENTRY(IMAGE_SCN_MEM_PROTECTED),
        LIBPE_ENTRY(IMAGE_SCN_MEM_FARDATA),
        LIBPE_ENTRY(IMAGE_SCN_MEM_SYSHEAP),
        LIBPE_ENTRY(IMAGE_SCN_MEM_PURGEABLE),
        LIBPE_ENTRY(IMAGE_SCN_MEM_LOCKED),
        LIBPE_ENTRY(IMAGE_SCN_MEM_PRELOAD),
    };

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (characteristic == names[i].characteristic) {
            return names[i].name;
        }
    }
    return NULL;
}

const char *
pe_rom_section_characteristic_name(ROMSectionCharacteristics characteristic)
{
    typedef struct {
        ROMSectionCharacteristics characteristic;
        const char *const name;
    } ROMSectionCharacteristicsName;

    static const ROMSectionCharacteristicsName names[] = {
        LIBPE_ENTRY(STYP_DUMMY),    LIBPE_ENTRY(STYP_TEXT),
        LIBPE_ENTRY(STYP_DATA),     LIBPE_ENTRY(STYP_SBSS),
        LIBPE_ENTRY(STYP_RDATA),    LIBPE_ENTRY(STYP_SDATA),
        LIBPE_ENTRY(STYP_BSS),      LIBPE_ENTRY(STYP_UCODE),
        LIBPE_ENTRY(STYP_LIT8),     LIBPE_ENTRY(STYP_LIT4),
        LIBPE_ENTRY(S_NRELOC_OVFL), LIBPE_ENTRY(STYP_LIB),
        LIBPE_ENTRY(STYP_INIT),
    };

    for (unsigned int i = 0; i < LIBPE_SIZEOF_ARRAY(names); i++) {
        if (characteristic == names[i].characteristic) {
            return names[i].name;
        }
    }
    return NULL;
}

bool pe_use_rom_section_characteristic(pe_ctx_t *ctx)
{
    return ctx->pe.optional_hdr_ptr != NULL
           && ctx->pe.optional_hdr.type == MAGIC_ROM;
}


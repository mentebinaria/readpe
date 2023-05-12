/*
    libpe - the PE library

    Copyright (C) 2010 - 2025 libpe authors

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

#include "libpe/dir_security.h"

#include "libpe/pe.h"
#include "libpe/macros.h"

#include <stdint.h>
#include <stdlib.h>

static inline uint32_t roundBy8(uint32_t x) { return (x + 7) & 0xfffffff8; }

unsigned int pe_certificate_count(pe_ctx_t *ctx)
{
    const IMAGE_DATA_DIRECTORY *const directory
        = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (directory == NULL) {
        return 0;
    }

    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        return 0;
    }

    unsigned int certs = 0;
    // This a file pointer rather than a common RVA.
    uint32_t fileOffset = directory->VirtualAddress;

    while (fileOffset - directory->VirtualAddress < directory->Size) {
        // Read the size of this WIN_CERTIFICATE
        uint32_t *dwLength_ptr = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
        if (!pe_can_read(ctx, dwLength_ptr, sizeof(uint32_t))) {
            // TODO: Should we report something?
            return 0;
        }
        ++certs;
        // Type punning
        uint32_t dwLength = *(uint32_t *)dwLength_ptr;
        fileOffset += roundBy8(dwLength);

        if (fileOffset - directory->VirtualAddress > directory->Size) {
            LIBPE_WARNING("either the attribute certificate table or the Size "
                          "field is corrupted");
            break;
        }
    }

    return certs;
}

uint32_t pe_certificates(pe_ctx_t *ctx, WIN_CERTIFICATE ***out)
{
    uint32_t count = pe_certificate_count(ctx);

    if (count == 0) {
        return count;
    }

    WIN_CERTIFICATE **certs;
    certs = malloc(count * sizeof(WIN_CERTIFICATE *));

    const IMAGE_DATA_DIRECTORY *const directory
        = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (directory == NULL) {
        free(certs);
        return 0;
    }

    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        free(certs);
        return 0;
    }

    // This is a file pointer rather than a common RVA.
    uint32_t fileOffset = directory->VirtualAddress;

    // Doing a second round trip to not having to allocate memory in a loop
    for (uint32_t i = 0; i < count; ++i) {
        // Read the size of this WIN_CERTIFICATE
        uint32_t *dwLength_ptr = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
        if (!pe_can_read(ctx, dwLength_ptr, sizeof(uint32_t))) {
            // No warning as we already warned in pe_certificate_count
            free(certs);
            return 0;
        }
        // Type punning
        uint32_t dwLength = *(uint32_t *)dwLength_ptr;

        certs[i] = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
        if (!pe_can_read(ctx, certs[i], dwLength)) {
            free(certs);
            return 0;
        }

        // Offset to the next certificate.
        fileOffset += roundBy8(certs[i]->dwLength);

        if (fileOffset - directory->VirtualAddress > directory->Size) {
            // No warning as we already warned in pe_certificate_count
            break;
        }
    }

    *out = certs;
    return count;
}


/* vim: set ts=4 sw=4 noet: */
/*
    readpe - the PE file analyzer toolkit

    security.c - Checks for security features in PE files.

    Copyright (C) 2012 - 2025 readpe authors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.

    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#include "libpe/macros.h"
#include "libpe/pe.h"
#include "readpe/helper.h"
#include "readpe/output.h"
#include "readpe/readpe.h"

#include <stdlib.h>

/*
find stack cookies, a.k.a canary, buffer security check
option in MVS 2010
*/
// FIXME: What about other versions?
bool stack_cookies(pe_ctx_t *ctx)
{
    static const unsigned char mvs2010[]
        = {0x55, 0x8b, 0xec, 0x83, 0x33, 0xc5, 0x33, 0xcd, 0xe8, 0xc3};

    if (ctx == NULL) {
        return false;
    }

    size_t         found      = 0;
    const uint8_t *file_bytes = LIBPE_PTR_ADD(ctx->map_addr, 0);
    const uint64_t filesize   = pe_filesize(ctx);

    // FIXME: Is this right?! Seems like partial matches will be
    //          Accumulated. Example: If all these bytes are found,
    //          separatelly in the file, this function will return true.
    for (uint64_t ofs = 0; ofs < filesize; ofs++) {
        for (size_t i = 0; i < sizeof(mvs2010); i++) {
            if (file_bytes[ofs] == mvs2010[i] && found == i) {
                found++;
            }
        }
    }

    return found == sizeof(mvs2010);
}

void print_securities(pe_ctx_t *ctx)
{
    IMAGE_OPTIONAL_HEADER *optional = pe_optional(ctx);
    if (optional == NULL) {
        exit(EXIT_FAILURE); // FIXME: exit
    }

    uint16_t dllchar = 0;
    switch (optional->type) {
    default:
        exit(EXIT_FAILURE); // FIXME: exit
    case MAGIC_PE32:
        dllchar = optional->_32->DllCharacteristics;
        break;
    case MAGIC_PE64:
        dllchar = optional->_64->DllCharacteristics;
        break;
    }
    static char field[MAX_MSG];
    // aslr
    snprintf(field, MAX_MSG, "ASLR");
    output(field, (dllchar & 0x40) ? "yes" : "no");

    // dep/nx
    snprintf(field, MAX_MSG, "DEP/NX");
    output(field, (dllchar & 0x100) ? "yes" : "no");

    // seh
    snprintf(field, MAX_MSG, "SEH");
    output(field, (dllchar & 0x400) ? "no" : "yes");

    // cfg
    snprintf(field, MAX_MSG, "CFG");
    output(field, (dllchar & 0x4000) ? "yes" : "no");

    // stack cookies
    snprintf(field, MAX_MSG, "Stack cookies (EXPERIMENTAL)");
    output(field, stack_cookies(ctx) ? "yes" : "no");
}

// static void parse_certificates(pe_ctx_t *ctx) {
//
//     const IMAGE_DATA_DIRECTORY *const directory
//         = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_SECURITY);
//     if (directory == NULL) {
//         return;
//     }
//
//     if (directory->VirtualAddress == 0 || directory->Size == 0) {
//         return;
//     }
//
//     // This a file pointer rather than a common RVA.
//     uint32_t fileOffset = directory->VirtualAddress;
//
//
//     while (fileOffset - directory->VirtualAddress < directory->Size) {
//         // Read the size of this WIN_CERTIFICATE
//         uint32_t *dwLength_ptr = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
//         if (!pe_can_read(ctx, dwLength_ptr, sizeof(uint32_t))) {
//             // output_close_scope(); // certificates
//             // TODO: Should we report something?
//             return;
//         }
//         // Type punning
//         uint32_t dwLength = *(uint32_t *)dwLength_ptr;
//
//         WIN_CERTIFICATE *cert = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
//         if (!pe_can_read(ctx, cert, dwLength)) {
//             // output_close_scope(); // certificates
//             // TODO: Should we report something?
//             return;
//         }
//
//         // output_open_scope("certificate", OUTPUT_SCOPE_TYPE_OBJECT);
//
//         // static char value[MAX_MSG];
//
//         // snprintf(value, MAX_MSG, "%u bytes", cert->dwLength);
//         // output("Length", value);
//
//         // snprintf(value, MAX_MSG, "0x%x (%s)", cert->wRevision,
//         //          cert->wRevision == WIN_CERT_REVISION_1_0   ? "1"
//         //          : cert->wRevision == WIN_CERT_REVISION_2_0 ? "2"
//         //                                                     : "unknown");
//         // output("Revision", value);
//
//         // snprintf(value, MAX_MSG, "0x%x", cert->wCertificateType);
//         // switch (cert->wCertificateType) {
//         // default:
//         //     bsd_strlcat(value, " (UNKNOWN)", MAX_MSG);
//         //     break;
//         // case WIN_CERT_TYPE_X509:
//         //     bsd_strlcat(value, " (X509)", MAX_MSG);
//         //     break;
//         // case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
//         //     bsd_strlcat(value, " (PKCS_SIGNED_DATA)", MAX_MSG);
//         //     break;
//         // case WIN_CERT_TYPE_TS_STACK_SIGNED:
//         //     bsd_strlcat(value, " (TS_STACK_SIGNED)", MAX_MSG);
//         //     break;
//         // }
//         // output("Type", value);
//
//         // Offset to the next certificate.
//         fileOffset += roundBy8(cert->dwLength);
//
//         if (fileOffset - directory->VirtualAddress > directory->Size) {
//             LIBPE_WARNING("either the attribute certificate table or the Size
//             "
//                           "field is corrupted");
//             // output_close_scope(); // certificate
//             break;                // Exit the while-loop.
//         }
//
//         switch (cert->wRevision) {
//         default:
//             LIBPE_WARNING("unknown wRevision");
//             break;
//         case WIN_CERT_REVISION_1_0:
//             LIBPE_WARNING("WIN_CERT_REVISION_1_0 is not supported");
//             break;
//         case WIN_CERT_REVISION_2_0:
//             break;
//         }
//
//         // switch (cert->wCertificateType) {
//         // default:
//         //     LIBPE_WARNING("unknown wCertificateType");
//         //     break;
//         // case WIN_CERT_TYPE_X509:
//         //     LIBPE_WARNING("WIN_CERT_TYPE_X509 is not supported");
//         //     break;
//         // case WIN_CERT_TYPE_PKCS_SIGNED_DATA: {
//         //     CRYPT_DATA_BLOB p7data;
//         //     p7data.cbData
//         //         = cert->dwLength - offsetof(WIN_CERTIFICATE,
//         bCertificate);
//         //     p7data.pbData = cert->bCertificate;
//         //     print_pkcs7_data(&p7data, _format, _out, verbose);
//         //     break;
//         // }
//         // case WIN_CERT_TYPE_TS_STACK_SIGNED:
//         //     LIBPE_WARNING("WIN_CERT_TYPE_TS_STACK_SIGNED is not
//         supported");
//         //     break;
//         // case WIN_CERT_TYPE_EFI_PKCS115:
//         //     LIBPE_WARNING("WIN_CERT_TYPE_EFI_PKCS115 is not supported");
//         //     break;
//         // case WIN_CERT_TYPE_EFI_GUID:
//         //     LIBPE_WARNING("WIN_CERT_TYPE_EFI_GUID is not supported");
//         //     break;
//         // }
//         // output_close_scope(); // certificate
//     }
//
// }


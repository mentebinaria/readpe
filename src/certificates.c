/* vim: set ts=4 sw=4 noet: */
/*
    readpe - the PE file analyzer toolkit

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

#include "compat.h"
#include "libpe/macros.h"
#include "libpe/pe.h"
#include "readpe/helper.h"
#include "readpe/output.h"
#include "readpe/readpe.h"

#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

static inline uint32_t roundBy8(uint32_t x) { return (x + 7) & 0xfffffff8; }
// static unsigned int roundBy8(unsigned int n)
// {
//     unsigned int t = n & ~7U;
//     if (n & 7U) {
//         t += 8;
//     }
//     return t;
// }

static cert_format_e parse_certoutform(const char *l_optarg)
{
    cert_format_e result = CERT_FORMAT_X509;

    if (strcmp(l_optarg, "text") == 0) {
        result = CERT_FORMAT_X509;
    } else if (strcmp(l_optarg, "x509") == 0) {
        result = CERT_FORMAT_X509;
    } else if (strcmp(l_optarg, "pem") == 0) {
        result = CERT_FORMAT_PEM;
    } else if (strcmp(l_optarg, "der") == 0) {
        result = CERT_FORMAT_DER;
    } else {
        EXIT_ERROR("invalid cert_format option");
    }

    return result;
}

static BIO *parse_certout(const char *l_optarg)
{
    BIO *bio = BIO_new(BIO_s_file());
    if (bio == NULL) {
        EXIT_ERROR("could not allocate BIO");
    }

    if (strcmp(l_optarg, "stdout") == 0) {
        BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    } else if (strcmp(l_optarg, "stderr") == 0) {
        BIO_set_fp(bio, stderr, BIO_NOCLOSE);
    } else {
        int ret = BIO_write_filename(bio, (char *) l_optarg);
        if (ret == 0) {
            BIO_free(bio);
            EXIT_ERROR("failed to open file");
        }
    }

    return bio;
}

static void print_certificate(BIO *out, cert_format_e format, X509 *cert)
{
    if (out == NULL) {
        return;
    }
    switch (format) {
    default:
    case CERT_FORMAT_X509:
        X509_print(out, cert);
        break;
    case CERT_FORMAT_PEM:
        PEM_write_bio_X509(out, cert);
        break;
    case CERT_FORMAT_DER:
        LIBPE_WARNING("DER format is not yet supported for output");
        break;
    }
}

static int parse_pkcs7_data(STACK_OF(X509) * *certs,
                            const CRYPT_DATA_BLOB *blob, PKCS7 **p7)
{
    int                 result    = 0;
    const cert_format_e input_fmt = CERT_FORMAT_DER;
    // PKCS7 *p7 = NULL; /* Need to be initialized! */
    BIO                *in;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_malloc_init();
#endif
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    in = BIO_new_mem_buf(blob->pbData, (int) blob->cbData);
    if (in == NULL) {
        result = -2;
        goto error;
    }

    // FIXME: input_fmt never changed!
    switch (input_fmt) {
    default:
        LIBPE_WARNING("unhandled input format for certificate");
        break;
    case CERT_FORMAT_DER:
        *p7 = d2i_PKCS7_bio(in, NULL);
        break;
    case CERT_FORMAT_PEM:
        *p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
        break;
    }

    if (p7 == NULL) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto error;
    }

    // STACK_OF(X509) *certs = NULL;

    int type = OBJ_obj2nid((*p7)->type);
    switch (type) {
    default:
        LIBPE_WARNING("unhandled certificate type");
        break;
    case NID_pkcs7_signed: // PKCS7_type_is_signed(p7)
        *certs = (*p7)->d.sign->cert;
        break;
    case NID_pkcs7_signedAndEnveloped: // PKCS7_type_is_signedAndEnveloped(p7)
        *certs = (*p7)->d.signed_and_enveloped->cert;
        break;
    }

error:
    if (p7 != NULL) {
        // PKCS7_free(p7);
    }
    if (in != NULL) {
        BIO_free(in);
    }

    // Deallocate everything from OpenSSL_add_all_algorithms
    EVP_cleanup();
    // Deallocate everything from ERR_load_crypto_strings
    ERR_free_strings();

    return result;
}

static void print_pkcs7_data(const CRYPT_DATA_BLOB *blob, cert_format_e format,
                             BIO *out, bool verbose)
{
    PKCS7 *p7             = NULL; /* Need to be initialized! */
    STACK_OF(X509) *certs = NULL;
    int res               = parse_pkcs7_data(&certs, blob, &p7);

    if (res < 0) {
        if (p7 != NULL) {
            PKCS7_free(p7);
        }
        // explode
        return;
    }

    const int numcerts = certs != NULL ? sk_X509_num(certs) : 0;
    if (verbose) {
        for (int i = 0; i < numcerts; i++) {
            X509 *cert = sk_X509_value(certs, i);
            print_certificate(out, format, cert);
            // NOTE: Calling X509_free(cert) is unnecessary.
        }
    }

    if (numcerts > 0) {
        // Print whether certificate signature is valid
        X509     *subject       = sk_X509_value(certs, 0);
        X509     *issuer        = sk_X509_value(certs, numcerts - 1);
        EVP_PKEY *issuer_pubkey = X509_get_pubkey(issuer);
        int       valid_sig     = X509_verify(subject, issuer_pubkey);
        EVP_PKEY_free(issuer_pubkey);
        output("Signature", valid_sig == 1 ? "valid" : "invalid");

        char issuer_name[65];

        // Print signers
        output_open_scope("signers", OUTPUT_SCOPE_TYPE_ARRAY);
        for (int i = 0; i < numcerts; i++) {
            X509      *cert = sk_X509_value(certs, i);
            X509_NAME *name = X509_get_subject_name(cert);

            memset(&issuer_name, 0, 65);
            int issuer_name_len = X509_NAME_get_text_by_NID(
                name, NID_commonName, issuer_name, 64);
            if (issuer_name_len > 0) {
                output_open_scope("signer", OUTPUT_SCOPE_TYPE_OBJECT);
                output("Issuer", issuer_name);
                output_close_scope(); // signer
            }
        }
        output_close_scope(); // signers
    }

    if (p7 != NULL) {
        PKCS7_free(p7);
    }
}

void print_certificates(pe_ctx_t *ctx, const char *format, const char *out)
{
    cert_format_e out_format
        = format ? parse_certoutform(format) : CERT_FORMAT_X509;
    BIO *out_file = parse_certout(out ? out : "stdout");

    WIN_CERTIFICATE **certs      = NULL;
    uint32_t          cert_count = pe_certificates(ctx, &certs);

    for (uint32_t i = 0; i < cert_count; ++i) {
        WIN_CERTIFICATE *cert = certs[i];

        switch (cert->wRevision) {
        default:
            LIBPE_WARNING("unknown wRevision");
            break;
        case WIN_CERT_REVISION_1_0:
            LIBPE_WARNING("WIN_CERT_REVISION_1_0 is not supported");
            break;
        case WIN_CERT_REVISION_2_0:
            break;
        }

        switch (cert->wCertificateType) {
        default:
            LIBPE_WARNING("unknown wCertificateType");
            break;
        case WIN_CERT_TYPE_X509:
            LIBPE_WARNING("WIN_CERT_TYPE_X509 is not supported");
            break;
        case WIN_CERT_TYPE_PKCS_SIGNED_DATA: {
            CRYPT_DATA_BLOB p7data;
            p7data.cbData
                = (uint32_t) (cert->dwLength
                              - offsetof(WIN_CERTIFICATE, bCertificate));
            p7data.pbData = cert->bCertificate;
            STACK_OF(X509) * x509certs;
            PKCS7 *p7  = NULL; /* Need to be initialized! */
            int    res = parse_pkcs7_data(&x509certs, &p7data, &p7);
            // print_certificate(out_file, out_format, x509cert);

            if (res < 0) {
                return;
            }

            const int numcerts = certs != NULL ? sk_X509_num(x509certs) : 0;
            for (int j = 0; j < numcerts; ++j) {
                X509 *x509cert = sk_X509_value(x509certs, j);
                print_certificate(out_file, out_format, x509cert);
                // NOTE: Calling X509_free(cert) is unnecessary.
            }
            if (p7 != NULL) {
                PKCS7_free(p7);
            }
            break;
        }
        case WIN_CERT_TYPE_TS_STACK_SIGNED:
            LIBPE_WARNING("WIN_CERT_TYPE_TS_STACK_SIGNED is not supported");
            break;
        case WIN_CERT_TYPE_EFI_PKCS115:
            LIBPE_WARNING("WIN_CERT_TYPE_EFI_PKCS115 is not supported");
            break;
        case WIN_CERT_TYPE_EFI_GUID:
            LIBPE_WARNING("WIN_CERT_TYPE_EFI_GUID is not supported");
            break;
        }
    }

    if (certs != NULL) {
        free(certs);
    }
    free(out_file);

    // STACK_OF(X509) *certs = NULL;

    // int res = parse_pkcs7_data(certs, blob);
}

void print_certificates_info(pe_ctx_t *ctx, const char *format, const char *out,
                             bool verbose)
{
    cert_format_e _format
        = format ? parse_certoutform(format) : CERT_FORMAT_X509;
    BIO *_out = parse_certout(out ? out : "stdout");

    const IMAGE_DATA_DIRECTORY *const directory
        = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (directory == NULL) {
        return;
    }

    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        return;
    }

    // This a file pointer rather than a common RVA.
    uint32_t fileOffset = directory->VirtualAddress;

    // TODO(jweyrich): We should count how many certificates the file has, and
    // based on this decide whether to proceed and open the certificates scope.
    output_open_scope("certificates", OUTPUT_SCOPE_TYPE_ARRAY);
    while (fileOffset - directory->VirtualAddress < directory->Size) {
        // Read the size of this WIN_CERTIFICATE
        uint32_t *dwLength_ptr = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
        if (! pe_can_read(ctx, dwLength_ptr, sizeof(uint32_t))) {
            output_close_scope(); // certificates
            // TODO: Should we report something?
            return;
        }
        // Type punning
        uint32_t dwLength = *(uint32_t *) dwLength_ptr;

        WIN_CERTIFICATE *cert = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
        if (! pe_can_read(ctx, cert, dwLength)) {
            output_close_scope(); // certificates
            // TODO: Should we report something?
            return;
        }

        output_open_scope("certificate", OUTPUT_SCOPE_TYPE_OBJECT);

        static char value[MAX_MSG];

        snprintf(value, MAX_MSG, "%u bytes", cert->dwLength);
        output("Length", value);

        snprintf(value, MAX_MSG, "0x%x (%s)", cert->wRevision,
                 cert->wRevision == WIN_CERT_REVISION_1_0   ? "1"
                 : cert->wRevision == WIN_CERT_REVISION_2_0 ? "2"
                                                            : "unknown");
        output("Revision", value);

        snprintf(value, MAX_MSG, "0x%x", cert->wCertificateType);
        switch (cert->wCertificateType) {
        default:
            bsd_strlcat(value, " (UNKNOWN)", MAX_MSG);
            break;
        case WIN_CERT_TYPE_X509:
            bsd_strlcat(value, " (X509)", MAX_MSG);
            break;
        case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            bsd_strlcat(value, " (PKCS_SIGNED_DATA)", MAX_MSG);
            break;
        case WIN_CERT_TYPE_TS_STACK_SIGNED:
            bsd_strlcat(value, " (TS_STACK_SIGNED)", MAX_MSG);
            break;
        }
        output("Type", value);

        // Offset to the next certificate.
        fileOffset += roundBy8(cert->dwLength);

        if (fileOffset - directory->VirtualAddress > directory->Size) {
            LIBPE_WARNING("either the attribute certificate table or the Size "
                          "field is corrupted");
            output_close_scope(); // certificate
            break;                // Exit the while-loop.
        }

        switch (cert->wRevision) {
        default:
            LIBPE_WARNING("unknown wRevision");
            break;
        case WIN_CERT_REVISION_1_0:
            LIBPE_WARNING("WIN_CERT_REVISION_1_0 is not supported");
            break;
        case WIN_CERT_REVISION_2_0:
            break;
        }

        switch (cert->wCertificateType) {
        default:
            LIBPE_WARNING("unknown wCertificateType");
            break;
        case WIN_CERT_TYPE_X509:
            LIBPE_WARNING("WIN_CERT_TYPE_X509 is not supported");
            break;
        case WIN_CERT_TYPE_PKCS_SIGNED_DATA: {
            CRYPT_DATA_BLOB p7data;
            p7data.cbData
                = (uint32_t) (cert->dwLength
                              - offsetof(WIN_CERTIFICATE, bCertificate));
            p7data.pbData = cert->bCertificate;
            print_pkcs7_data(&p7data, _format, _out, verbose);
            break;
        }
        case WIN_CERT_TYPE_TS_STACK_SIGNED:
            LIBPE_WARNING("WIN_CERT_TYPE_TS_STACK_SIGNED is not supported");
            break;
        case WIN_CERT_TYPE_EFI_PKCS115:
            LIBPE_WARNING("WIN_CERT_TYPE_EFI_PKCS115 is not supported");
            break;
        case WIN_CERT_TYPE_EFI_GUID:
            LIBPE_WARNING("WIN_CERT_TYPE_EFI_GUID is not supported");
            break;
        }
        output_close_scope(); // certificate
    }
    output_close_scope(); // certificates

    free(_out);
}


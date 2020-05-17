/*
	pev - the PE file analyzer toolkit

	pesec.c - Checks for security features in PE files.

	Copyright (C) 2012 - 2020 pev authors

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

#include "common.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "compat/strlcat.h"
#include "plugins.h"

#define PROGRAM "pesec"

typedef enum {
	CERT_FORMAT_TEXT = 1,
	CERT_FORMAT_PEM = 2,
	CERT_FORMAT_DER = 3
} cert_format_e;

typedef struct {
	cert_format_e certoutform;
	BIO *certout;
} options_t;

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s [OPTIONS] FILE\n"
		"Check for security features in PE files\n"
		"\nExample: %s wordpad.exe\n"
		"\nOptions:\n"
		" -f, --format <%s>  Change output format (default: text)\n"
		" -c, --certoutform <text|pem>           Specifies the certificate output format (default: text).\n"
		" -o, --certout <filename>               Specifies the output filename to write certificates to (default: stdout).\n"
		" -V, --version                          Show version.\n"
		" --help                                 Show this help.\n",
		PROGRAM, PROGRAM, formats);
}

static cert_format_e parse_certoutform(const char *optarg)
{
	cert_format_e result;
	if (strcmp(optarg, "text") == 0)
		result = CERT_FORMAT_TEXT;
	else if (strcmp(optarg, "pem") == 0)
		result = CERT_FORMAT_PEM;
	else if (strcmp(optarg, "der") == 0)
		result = CERT_FORMAT_DER;
	else
		EXIT_ERROR("invalid cert_format option");
	return result;
}

static BIO *parse_certout(const char *optarg)
{
	BIO *bio = BIO_new(BIO_s_file());
	if (bio == NULL) {
		EXIT_ERROR("could not allocate BIO");
	}

	if (strcmp(optarg, "stdout") == 0) {
		BIO_set_fp(bio, stdout, BIO_NOCLOSE);
	} else if (strcmp(optarg, "stderr") == 0) {
		BIO_set_fp(bio, stderr, BIO_NOCLOSE);
	} else {
		int ret = BIO_write_filename(bio, (char *)optarg);
		if (ret == 0) {
			BIO_free(bio);
			EXIT_ERROR("failed to open file");
		}
	}

	return bio;
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	if (options->certout != NULL)
		BIO_free(options->certout);

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	/* Parameters for getopt_long() function */
	static const char short_options[] = "f:c:o:V";

	static const struct option long_options[] = {
		{ "format",			required_argument,	NULL,	'f' },
		{ "certoutform",	required_argument,	NULL,	'c' },
		{ "certout",		required_argument,	NULL,	'o' },
		{ "help",			no_argument,		NULL,	 1  },
		{ "version",		no_argument,		NULL,	'V' },
		{ NULL,				0,					NULL, 	 0  }
	};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1: // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				if (output_set_format_by_name(optarg) < 0)
					EXIT_ERROR("invalid format option");
				break;
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 'c':
				options->certoutform = parse_certoutform(optarg);
				break;
			case 'o':
				options->certout = parse_certout(optarg);
				break;
			case 'V':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	return options;
}

/*
find stack cookies, a.k.a canary, buffer security check
option in MVS 2010
*/
static bool stack_cookies(pe_ctx_t *ctx)
{
	static const unsigned char mvs2010[] = {
		0x55, 0x8b, 0xec, 0x83,
		0x33, 0xc5, 0x33, 0xcd,
		0xe8, 0xc3
	};

	if (ctx == NULL)
		return false;

	size_t found = 0;
	const uint8_t *file_bytes = LIBPE_PTR_ADD(ctx->map_addr, 0);
	const uint64_t filesize = pe_filesize(ctx);
	for (uint64_t ofs=0; ofs < filesize; ofs++) {
		for (size_t i=0; i < sizeof(mvs2010); i++) {
			if (file_bytes[ofs] == mvs2010[i] && found == i)
				found++;
		}
	}

	return found == sizeof(mvs2010);
}

static void print_certificate(BIO *out, cert_format_e format, X509 *cert)
{
	if (out == NULL)
		return;
	switch (format) {
		default:
		case CERT_FORMAT_TEXT:
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

static int parse_pkcs7_data(const options_t *options, const CRYPT_DATA_BLOB *blob)
{
	int result = 0;
	const cert_format_e input_fmt = CERT_FORMAT_DER;
	PKCS7 *p7 = NULL;
	BIO *in = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_malloc_init();
#endif
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	in = BIO_new_mem_buf(blob->pbData, blob->cbData);
	if (in == NULL) {
		result = -2;
		goto error;
	}

	switch (input_fmt) {
		default:
			LIBPE_WARNING("unhandled input format for certificate");
			break;
		case CERT_FORMAT_DER:
			p7 = d2i_PKCS7_bio(in, NULL);
			break;
		case CERT_FORMAT_PEM:
			p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
			break;
	}
	if (p7 == NULL) {
		ERR_print_errors_fp(stderr);
		result = -3;
		goto error;
	}

	STACK_OF(X509) *certs = NULL;

	int type = OBJ_obj2nid(p7->type);
	switch (type) {
		default: break;
		case NID_pkcs7_signed: // PKCS7_type_is_signed(p7)
			certs = p7->d.sign->cert;
			break;
		case NID_pkcs7_signedAndEnveloped: // PKCS7_type_is_signedAndEnveloped(p7)
			certs = p7->d.signed_and_enveloped->cert;
			break;
	}

	const int numcerts = certs != NULL ? sk_X509_num(certs) : 0;
	for (int i = 0; i < numcerts; i++) {
		X509 *cert = sk_X509_value(certs, i);
		print_certificate(options->certout, options->certoutform, cert);
		// NOTE: Calling X509_free(cert) is unnecessary.
	}

	// Print whether certificate signature is valid
	if (numcerts > 0) {
		X509 *subject = sk_X509_value(certs, 0);
		X509 *issuer = sk_X509_value(certs, numcerts - 1);
		EVP_PKEY *issuer_pubkey = X509_get_pubkey(issuer);
		int valid_sig = X509_verify(subject, issuer_pubkey);
		EVP_PKEY_free(issuer_pubkey);
		output("Signature", valid_sig == 1 ? "valid" : "invalid");
	}

	// Print signers
	if (numcerts > 0) {
		output_open_scope("signers", OUTPUT_SCOPE_TYPE_ARRAY);
		for (int i = 0; i < numcerts; i++) {
			X509 *cert = sk_X509_value(certs, i);
			X509_NAME *name = X509_get_subject_name(cert);

			int issuer_name_len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
			if (issuer_name_len > 0) {
				output_open_scope("signer", OUTPUT_SCOPE_TYPE_OBJECT);
				char issuer_name[issuer_name_len + 1];
				X509_NAME_get_text_by_NID(name, NID_commonName, issuer_name, issuer_name_len + 1);
				output("Issuer", issuer_name);
				output_close_scope(); // signer
			}
		}
		output_close_scope(); // signers
	}

error:
	if (p7 != NULL)
		PKCS7_free(p7);
	if (in != NULL)
		BIO_free(in);

	// Deallocate everything from OpenSSL_add_all_algorithms
	EVP_cleanup();
	// Deallocate everything from ERR_load_crypto_strings
	ERR_free_strings();

	return result;
}

static void parse_certificates(const options_t *options, pe_ctx_t *ctx)
{
	const IMAGE_DATA_DIRECTORY * const directory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_SECURITY);
	if (directory == NULL)
		return;

	if (directory->VirtualAddress == 0 || directory->Size == 0)
		return;

	uint32_t fileOffset = directory->VirtualAddress; // This a file pointer rather than a common RVA.

	// TODO(jweyrich): We should count how many certificates the file has, and based on this
	//                 decide whether to proceed and open the certificates scope.
	output_open_scope("certificates", OUTPUT_SCOPE_TYPE_ARRAY);
	while (fileOffset - directory->VirtualAddress < directory->Size)
	{
		// Read the size of this WIN_CERTIFICATE
		uint32_t *dwLength_ptr = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
		if (!pe_can_read(ctx, dwLength_ptr, sizeof(uint32_t))) {
			output_close_scope(); // certificates
			// TODO: Should we report something?
			return;
		}
		// Type punning
		uint32_t dwLength = *(uint32_t *)dwLength_ptr;

		WIN_CERTIFICATE *cert = LIBPE_PTR_ADD(ctx->map_addr, fileOffset);
		if (!pe_can_read(ctx, cert, dwLength)) {
			output_close_scope(); // certificates
			// TODO: Should we report something?
			return;
		}

		output_open_scope("certificate", OUTPUT_SCOPE_TYPE_OBJECT);

		static char value[MAX_MSG];

		snprintf(value, MAX_MSG, "%u bytes", cert->dwLength);
		output("Length", value);

		snprintf(value, MAX_MSG, "0x%x (%s)", cert->wRevision,
			cert->wRevision == WIN_CERT_REVISION_1_0 ? "1" :
			cert->wRevision == WIN_CERT_REVISION_2_0 ? "2" : "unknown");
		output("Revision", value);

		snprintf(value, MAX_MSG, "0x%x", cert->wCertificateType);
		switch (cert->wCertificateType) {
			default: bsd_strlcat(value, " (UNKNOWN)", MAX_MSG); break;
			case WIN_CERT_TYPE_X509: bsd_strlcat(value, " (X509)", MAX_MSG); break;
			case WIN_CERT_TYPE_PKCS_SIGNED_DATA: bsd_strlcat(value, " (PKCS_SIGNED_DATA)", MAX_MSG); break;
			case WIN_CERT_TYPE_TS_STACK_SIGNED: bsd_strlcat(value, " (TS_STACK_SIGNED)", MAX_MSG); break;
		}
		output("Type", value);

		fileOffset += pe_utils_round_up(cert->dwLength, 8); // Offset to the next certificate.

		if (fileOffset - directory->VirtualAddress > directory->Size) {
			LIBPE_WARNING("either the attribute certificate table or the Size field is corrupted");
			output_close_scope(); // certificate
			break; // Exit the while-loop.
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
			case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
			{
				CRYPT_DATA_BLOB p7data;
				p7data.cbData = cert->dwLength - offsetof(WIN_CERTIFICATE, bCertificate);
				p7data.pbData = cert->bCertificate;
				parse_pkcs7_data(options, &p7data);
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
}

int main(int argc, char *argv[])
{
	pev_config_t config;
	PEV_INITIALIZE(&config);

	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	output_set_cmdline(argc, argv);

	options_t *options = parse_options(argc, argv); // opcoes

	const char *path = argv[argc-1];
	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, path);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx))
		EXIT_ERROR("not a valid PE file");

	IMAGE_OPTIONAL_HEADER *optional = pe_optional(&ctx);
	if (optional == NULL)
		return EXIT_FAILURE;

	uint16_t dllchar = 0;
	switch (optional->type) {
		default:
			return EXIT_FAILURE;
		case MAGIC_PE32:
			dllchar = optional->_32->DllCharacteristics;
			break;
		case MAGIC_PE64:
			dllchar = optional->_64->DllCharacteristics;
			break;
	}

	output_open_document();

	char field[MAX_MSG];

	// aslr
	snprintf(field, MAX_MSG, "ASLR");
	output(field, (dllchar & 0x40) ? "yes" : "no");

	// dep/nx
	snprintf(field, MAX_MSG, "DEP/NX");
	output(field, (dllchar & 0x100) ? "yes" : "no");

	// seh
	snprintf(field, MAX_MSG, "SEH");
	output(field, (dllchar & 0x400) ? "no" : "yes");

	// stack cookies
	snprintf(field, MAX_MSG, "Stack cookies (EXPERIMENTAL)");
	output(field, stack_cookies(&ctx) ? "yes" : "no");

	// certificados
	parse_certificates(options, &ctx);

	output_close_document();

	// libera a memoria
	free_options(options);

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	PEV_FINALIZE(&config);

	return EXIT_SUCCESS;
}

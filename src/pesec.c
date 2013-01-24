/*
	pev - the PE file analyzer toolkit

	pesec.c - Check for security features in PE files

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

#include "pesec.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "compat/strlcat.h"

typedef enum {
	CERT_FORMAT_TEXT = 1,
	CERT_FORMAT_PEM = 2,
	CERT_FORMAT_DER = 3
} cert_format_e;

typedef struct {
	cert_format_e certoutform;
	BIO *certout;
} options_t;

static void usage()
{
	printf("Usage: %s [OPTIONS] FILE\n"
		"Check for security features in PE files\n"
		"\nExample: %s wordpad.exe\n"
		"\nOptions:\n"
		" -f, --format <text|csv|xml|html>       change output format (default: text)\n"
		" -c, --certoutform <text|pem>           specifies the certificate output format (default: text)\n"
		" -o, --certout filename                 specifies the output filename to write certificates to (default: stdout)\n"
		" -v, --version                          show version and exit\n"
		" --help                                 show this help and exit\n",
		PROGRAM, PROGRAM);
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
	options_t *options = xmalloc(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	/* Parameters for getopt_long() function */
	static const char short_options[] = "f:c:o:v";

	static const struct option long_options[] = {
		{"format",		required_argument,	NULL,	'f'},
		{"certoutform",	required_argument,	NULL,	'c'},
		{"certout",		required_argument,	NULL,	'o'},
		{"help",		no_argument,		NULL,	 1 },
		{"version",		no_argument,		NULL,	'v'},
		{ NULL,			0,					NULL, 	 0 }
	};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:		// --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				parse_format(optarg);
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
static bool stack_cookies(PE_FILE *pe)
{
	unsigned int i, found = 0;
	unsigned char buff;
	const unsigned char mvs2010[] = {
		0x55, 0x8b, 0xec, 0x83,
		0x33, 0xc5, 0x33, 0xcd,
		0xe8, 0xc3
	};

	if (!pe)
		return false;

	if (!pe->entrypoint)
		if (!pe_get_optional(pe))
			return false;

	rewind(pe->handle);

	while (fread(&buff, 1, 1, pe->handle))
	{
		for (i=0; i < sizeof(mvs2010); i++)
		{
			if (buff == mvs2010[i] && found == i)
				found++;
		}
	}

	return (found == sizeof(mvs2010));
}

static int round_up(int numToRound, int multiple)
{
	if (multiple == 0)
		return 0;
	return (numToRound + multiple - 1) / multiple * multiple;
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
			EXIT_ERROR("DER format is not yet supported for output");
			break;
	}
}

static int parse_pkcs7_data(const options_t *options, const CRYPT_DATA_BLOB *blob)
{
	int result = 0;
	const cert_format_e input_fmt = CERT_FORMAT_DER;
	PKCS7 *p7 = NULL;
	BIO *in = NULL;

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	in = BIO_new_mem_buf(blob->pbData, blob->cbData);
	if (in == NULL) {
		result = -2;
		goto error;
	}

	switch (input_fmt) {
		default: EXIT_ERROR("unhandled input format for certificate");
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
		int valid_sig = X509_verify(subject, X509_get_pubkey(issuer));
		output("Signature", valid_sig == 1 ? "valid" : "invalid");
	}

	// Print signers
	if (numcerts > 0)
		output("Signers", NULL);
	for (int i = 0; i < numcerts; i++) {
		X509 *cert = sk_X509_value(certs, i);
		X509_NAME *name = X509_get_subject_name(cert);

		int issuer_name_len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
		if (issuer_name_len > 0) {
			char issuer_name[issuer_name_len + 1];
			X509_NAME_get_text_by_NID(name, NID_commonName, issuer_name, issuer_name_len + 1);
			output(NULL, issuer_name);
		}
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

static void parse_certificates(const options_t *options, PE_FILE *pe)
{
	if (!pe_get_directories(pe))
		EXIT_ERROR("unable to read the Directories entry from Optional header");

	const IMAGE_DATA_DIRECTORY * const directory = pe_get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
	if (directory == NULL)
		return;

	if (directory->VirtualAddress == 0 || directory->Size == 0)
		return;

	DWORD fileOffset = directory->VirtualAddress; // This a file pointer rather than a common RVA.

	output("Certificates", NULL);
	while (fileOffset - directory->VirtualAddress < directory->Size)
	{
		if (fseek(pe->handle, fileOffset, SEEK_SET))
			EXIT_ERROR("unable to seek");

		DWORD dwCertLen = 0;

		// Read the size of this WIN_CERTIFICATE
		if (!fread(&dwCertLen, sizeof(DWORD), 1, pe->handle))
			EXIT_ERROR("unable to read");

		if (fseek(pe->handle, fileOffset, SEEK_SET))
			EXIT_ERROR("unable to seek");

		WIN_CERTIFICATE *cert = xmalloc(dwCertLen);

		// Read the whole WIN_CERTIFICATE based on the previously read size
		if (!fread(cert, dwCertLen, 1, pe->handle))
			EXIT_ERROR("unable to read");

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

		fileOffset += round_up(cert->dwLength, 8); // Offset to the next certificate.

		if (fileOffset - directory->VirtualAddress > directory->Size)
			EXIT_ERROR("either the attribute certificate table or the Size field is corrupted");

		switch (cert->wRevision) {
			default:
				EXIT_ERROR("unknown wRevision");
			case WIN_CERT_REVISION_1_0:
				EXIT_ERROR("WIN_CERT_REVISION_1_0 is not supported");
			case WIN_CERT_REVISION_2_0:
				break;
		}

		switch (cert->wCertificateType) {
			default:
				EXIT_ERROR("unknown wCertificateType");
			case WIN_CERT_TYPE_X509:
				EXIT_ERROR("WIN_CERT_TYPE_X509 is not supported");
			case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
			{
				CRYPT_DATA_BLOB p7data;
				p7data.cbData = cert->dwLength - offsetof(WIN_CERTIFICATE, bCertificate);
				p7data.pbData = cert->bCertificate;
				parse_pkcs7_data(options, &p7data);
				break;
			}
			case WIN_CERT_TYPE_TS_STACK_SIGNED:
				EXIT_ERROR("WIN_CERT_TYPE_TS_STACK_SIGNED is not supported");
			case WIN_CERT_TYPE_EFI_PKCS115:
				EXIT_ERROR("WIN_CERT_TYPE_EFI_PKCS115 is not supported");
			case WIN_CERT_TYPE_EFI_GUID:
				EXIT_ERROR("WIN_CERT_TYPE_EFI_GUID is not supported");
		}

		free(cert);
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		exit(1);
	}

	options_t *options = parse_options(argc, argv); // opcoes

	const char *path = argv[argc-1];

	FILE *fp = NULL;
	if ((fp = fopen(path, "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	PE_FILE pe;
	pe_init(&pe, fp); // inicializa o struct pe

	if (!is_pe(&pe))
		EXIT_ERROR("not a valid PE file");

	if (!pe_get_optional(&pe))
		return 1;

	WORD dllchar = 0;
	if (pe.architecture == PE32)
		dllchar = pe.optional_ptr->_32->DllCharacteristics;
	else if (pe.architecture == PE64)
		dllchar = pe.optional_ptr->_64->DllCharacteristics;
	else
		return 1;

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
	output(field, stack_cookies(&pe) ? "yes" : "no");

	// certificados
	parse_certificates(options, &pe);

	// libera a memoria
	pe_deinit(&pe);

	free_options(options);

	return 0;
}

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
#include <assert.h>

static int ind;

static void usage()
{
	printf("Usage: %s [OPTIONS] FILE\n"
	"Check for security features in PE files\n"
	"\nExample: %s wordpad.exe\n"
	"\nOptions:\n"
	" -f, --format <text|csv|xml|html>       change output format (default: text)\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

static void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "f:v";

	static const struct option long_options[] = {
		{"format",           required_argument, NULL, 'f'},
		{"help",             no_argument,       NULL,  1 },
		{"version",          no_argument,       NULL, 'v'},
		{ NULL,              0,                 NULL,  0 }
	};

	while ((c = getopt_long(argc, argv, short_options,
			long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:		// --help option
				usage();
				exit(EXIT_SUCCESS);

			case 'f':
				parse_format(optarg); break;

			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
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

static int roundUp(int numToRound, int multiple)
{
	if (multiple == 0)
		return 0;
	return (numToRound + multiple - 1) / multiple * multiple;
}

static int parse_pkcs7_data(const CRYPT_DATA_BLOB *blob) {
	int result = 0;
	return result;
}

static void print_certificates(PE_FILE *pe)
{
	if (!pe_get_directories(pe))
		EXIT_ERROR("unable to read the Directories entry from Optional header");

	const IMAGE_DATA_DIRECTORY * const directory = pe_get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
	if (directory == NULL) {
		printf("security directory not found\n");
		// TODO: Should we exit using EXIT_ERROR?
		return;
	}

	if (directory->VirtualAddress == 0 || directory->Size == 0)
		return;

	DWORD fileOffset = directory->VirtualAddress; // This a file pointer rather than a common RVA.

	printf("Certificates:\n");
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
		if (!fread(cert, dwCertLen, 1, pe->handle)) {
			free(cert);
			EXIT_ERROR("unable to read");
		}

		printf("  length    %u bytes\n", cert->dwLength);
		printf("  revision  0x%x (%s)\n", cert->wRevision,
			cert->wRevision == WIN_CERT_REVISION_1_0 ? "1" :
			cert->wRevision == WIN_CERT_REVISION_2_0 ? "2" : "unknown");
		printf("  type      0x%x", cert->wCertificateType);
		switch (cert->wCertificateType)
		{
			default: printf(" (UNKNOWN)"); break;
			case WIN_CERT_TYPE_X509: printf(" (X509)"); break;
			case WIN_CERT_TYPE_PKCS_SIGNED_DATA: printf(" (PKCS_SIGNED_DATA)"); break;
			case WIN_CERT_TYPE_TS_STACK_SIGNED: printf(" (TS_STACK_SIGNED)"); break;
		}
		printf("\n");

		fileOffset += roundUp(cert->dwLength, 8); // Offset to next certificate.

		if (fileOffset - directory->VirtualAddress > directory->Size)
			EXIT_ERROR("Either the attribute certificate table or the Size field is corrupted");

		switch (cert->wRevision) {
			default:
				EXIT_ERROR("Unknown wRevision");
			case WIN_CERT_REVISION_1_0:
				EXIT_ERROR("WIN_CERT_REVISION_1_0 is not supported");
			case WIN_CERT_REVISION_2_0:
				break;
		}

		switch (cert->wCertificateType) {
			default:
				EXIT_ERROR("Unknown wCertificateType");
			case WIN_CERT_TYPE_X509:
				EXIT_ERROR("WIN_CERT_TYPE_X509 is not supported");
			case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
			{
				CRYPT_DATA_BLOB p7data;
				p7data.cbData = cert->dwLength - (3 * sizeof(DWORD));
				p7data.pbData = cert->bCertificate;
				parse_pkcs7_data(&p7data);
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
	printf("\n");
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	WORD dllchar = 0;
	char field[MAX_MSG];

	if (argc < 2)
	{
		usage();
		exit(1);
	}

	parse_options(argc, argv); // opcoes

	const char *path = argv[argc-1];

	if ((fp = fopen(path, "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!is_pe(&pe))
		EXIT_ERROR("not a valid PE file");

	if (!pe_get_optional(&pe))
		return 1;

	if (pe.architecture == PE32)
		dllchar = pe.optional_ptr->_32->DllCharacteristics;
	else if (pe.architecture == PE64)
		dllchar = pe.optional_ptr->_64->DllCharacteristics;
	else
		return 1;

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

	// certificates
	print_certificates(&pe);

	// libera a memoria
	pe_deinit(&pe);

	return 0;
}

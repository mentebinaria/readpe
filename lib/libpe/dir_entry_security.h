#ifndef LIBPE_DIR_ENTRY_SECURITY_H
#define LIBPE_DIR_ENTRY_SECURITY_H

#include "types.h"

#define ANYSIZE_ARRAY 1

// #define WIN_TRUST_MAJOR_REVISION_MASK	0xFFFF0000
// #define WIN_TRUST_MINOR_REVISION_MASK	0x0000FFFF
// #define WIN_TRUST_REVISION_1_0			0x00010000

typedef enum {
	// Version 1, legacy version of the Win_Certificate
	// structure. It is supported only for purposes of
	// verifying legacy Authenticode signatures
	WIN_CERT_REVISION_1_0 = 0x0100,
	// Version 2 is the current version of the Win_Certificate structure.
	WIN_CERT_REVISION_2_0 = 0x0200
} CertRevision;

typedef enum {
	WIN_CERT_TYPE_X509				= 0x0001, // bCertificate contains an X.509 (Certificate)
	WIN_CERT_TYPE_PKCS_SIGNED_DATA	= 0x0002, // bCertificate contains a PKCS#7 (SignedData structure)
	WIN_CERT_TYPE_RESERVED_1		= 0x0003, // Reserved
	WIN_CERT_TYPE_TS_STACK_SIGNED	= 0x0004, // Terminal Server Protocol Stack (Certificate signing)
	WIN_CERT_TYPE_EFI_PKCS115		= 0x0EF0,
	WIN_CERT_TYPE_EFI_GUID			= 0x0EF1
} CertType;

#pragma pack(4)

// Originally declared in Wintrust.h
typedef struct {
	// Specified the size, in bytes, of the WIN_CERTIFICATE structure,
	// including the data in bCertificate.
	DWORD dwLength;
	// Indicates the revision of the structure.
	WORD wRevision;
	// Specifies the type of certificate.
	// This member can be one of the following values:
	//   Value								Meaning
	//   ----------------------------------------------------------------------------------------
	//   WIN_CERT_TYPE_X509 				The certificate contains an X.509 Certificate.
	//   WIN_CERT_TYPE_PKCS_SIGNED_DATA		The certificate contains a PKCS SignedData structure.
	//   WIN_CERT_TYPE_RESERVED_1			Reserved.
	//	 WIN_CERT_TYPE_TS_STACK_SIGNED
	WORD wCertificateType;
	// A variable-sized array of bytes that contains the certificate data.
	BYTE bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE;

typedef struct {
	DWORD cbData;
	BYTE *pbData;
} CRYPT_DATA_BLOB;

#pragma pack()

#endif

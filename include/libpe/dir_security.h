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

#ifndef LIBPE_DIR_SECURITY_H
#define LIBPE_DIR_SECURITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#pragma pack(push, 4)

// Originally declared in Wintrust.h
typedef struct {
	// Specified the size, in bytes, of the WIN_CERTIFICATE structure,
	// including the data in bCertificate.
	uint32_t dwLength;
	// Indicates the revision of the structure.
	uint16_t wRevision;
	// Specifies the type of certificate.
	// This member can be one of the following values:
	//   Value								Meaning
	//   ----------------------------------------------------------------------------------------
	//   WIN_CERT_TYPE_X509 				The certificate contains an X.509 Certificate.
	//   WIN_CERT_TYPE_PKCS_SIGNED_DATA		The certificate contains a PKCS SignedData structure.
	//   WIN_CERT_TYPE_RESERVED_1			Reserved.
	//	 WIN_CERT_TYPE_TS_STACK_SIGNED
	uint16_t wCertificateType;
	// A variable-sized array of bytes that contains the certificate data.
	uint8_t bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE;

typedef struct {
	uint32_t cbData;
	uint8_t *pbData;
} CRYPT_DATA_BLOB;

#pragma pack(pop)

#ifdef __cplusplus
} // extern "C"
#endif

#endif

/* vim: set ts=4 sw=4 noet: */
/*
        readpe - the PE file analyzer toolkit

        Copyright (C) 2023 readpe authors

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

#pragma once

#include "common.h"
#include <libpe/pe.h>
#include <openssl/pem.h>

typedef enum {
    CERT_FORMAT_X509 = 1,
    CERT_FORMAT_PEM = 2,
    CERT_FORMAT_DER = 3
} cert_format_e;

// typedef struct {
// 	cert_format_e certoutform;
// 	BIO *certout;
// } certificate_settings;

typedef struct {
    const char *certoutform;
    const char *certout;
} certificate_settings;

bool stack_cookies(pe_ctx_t *ctx);
void print_securities(pe_ctx_t *ctx);
void print_certificates(pe_ctx_t *ctx, const char *format, const char *out);


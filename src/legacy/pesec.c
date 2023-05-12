/* vim: set ts=4 sw=4 noet: */
/*
    readpe - the PE file analyzer toolkit

    pesec.c - Checks for security features in PE files.

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

#include "../legacy.h"
#include "common.h"
#include "readpe.h"

#include <libpe/context.h>
#include <libpe/dir_security.h>
#include <libpe/macros.h>
#include <libpe/pe.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <stdint.h>

#define PROGRAM "pesec"

static struct readpe_settings g_settings;

static void                   usage(void)
{
    static char formats[255];
    output_available_formats(formats, sizeof(formats), '|');
    printf("Usage: %s [OPTIONS] FILE\n"
           "Check for security features in PE files\n"
           "\nExample: %s wordpad.exe\n"
           "\nOptions:\n"
           " -f, --format <%s>  Change output format (default: text)\n"
           " -c, --certoutform <text|pem>			 Specifies the certificate "
           "output format (default: text).\n"
           " -o, --certout <filename>				 Specifies the output "
           "filename to write certificates to (default: stdout).\n"
           " -V, --version							 Show version.\n"
           " --help								 Show this help.\n",
           PROGRAM, PROGRAM, formats);
}

static void parse_options(int argc, char *argv[])
{
    /* Parameters for getopt_long() function */
    static const char          short_options[] = "f:c:o:V";

    static const struct option long_options[]  = {
        {"format",      required_argument, NULL, 'f'},
        {"certoutform", required_argument, NULL, 'c'},
        {"certout",     required_argument, NULL, 'o'},
        {"help",        no_argument,       NULL, 1  },
        {"version",     no_argument,       NULL, 'V'},
        {NULL,          0,                 NULL, 0  }
    };

    int c, ind;

    while ((c = getopt_long(argc, argv, short_options, long_options, &ind))) {
        if (c < 0) {
            break;
        }

        switch (c) {
        case 1: // --help option
            usage();
            exit(EXIT_SUCCESS);
        case 'f':
            if (output_set_format_by_name(optarg) < 0) {
                EXIT_ERROR("invalid format option");
            }
            break;
        case 'v':
            printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
            exit(EXIT_SUCCESS);
        case 'c':
            g_settings.cert_format = optarg;
            break;
        case 'o':
            g_settings.cert_out = optarg;
            break;
        case 'V':
            printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
            exit(EXIT_FAILURE);
        }
    }

    return;
}

int pesec(int argc, char *argv[])
{
    struct readpe_config config;
    readpe_initialize(&config);

    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    parse_options(argc, argv);

    output_set_cmdline(argc, argv);

    const char *path = argv[argc - 1];
    pe_ctx_t    ctx;

    pe_err_e    err = pe_load_file(&ctx, path);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    if (! pe_is_pe(&ctx)) {
        EXIT_ERROR("not a valid PE file");
    }

    print_securities(&ctx);

    // certificados
    print_certificates_info(&ctx, g_settings.cert_format, g_settings.cert_out,
                            false);

    output_close_document();

    // free
    err = pe_unload(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    readpe_finalize(&config);

    return EXIT_SUCCESS;
}

#ifdef STANDALONE
int main(int argc, char **argv) { return pesec(argc, argv); }
#endif


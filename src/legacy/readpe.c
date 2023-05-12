/*
        readpe - the PE file analyzer toolkit

        src/legacy/readpe.c - collection of pre 1.0 main functions

        Copyright (C) 2025 readpe authors

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

#include "readpe.h"

#include "../legacy.h"
#include "common.h"
#include "config.h"

#include <libpe/macros.h>

#define PROGRAM "readpe"

typedef struct {
    bool all;
    bool dos;
    bool coff;
    bool opt;
    bool dirs;
    bool imports;
    bool exports;
    bool all_headers;
    bool all_sections;
} options_t;

static void parse_headers(options_t *options, const char *l_optarg)
{
    if (! strcmp(l_optarg, "dos")) {
        options->dos = true;
    } else if (! strcmp(l_optarg, "coff")) {
        options->coff = true;
    } else if (! strcmp(l_optarg, "optional")) {
        options->opt = true;
    } else {
        EXIT_ERROR("invalid header option");
    }
}

static void free_options(options_t *options) { free(options); }

static void usage(void)
{
    static char formats[255];
    output_available_formats(formats, sizeof(formats), '|');
    printf("Usage: %s OPTIONS FILE\n"
           "Show PE file headers\n"
           "\nExample: %s --header optional winzip.exe\n"
           "\nOptions:\n"
           " -A, --all								 Full output (default).\n"
           " -H, --all-headers						 Show all PE headers.\n"
           " -S, --all-sections					 Show PE section headers.\n"
           " -f, --format <%s>  Change output format (default: text).\n"
           " -d, --dirs							 Show data directories.\n"
           " -h, --header <dos|coff|optional>		 Show specific header. It "
           "can be used multiple times.\n"
           " -i, --imports							 Show imported functions.\n"
           " -e, --exports							 Show exported functions.\n"
           " -V, --version							 Show version.\n"
           " --help								 Show this help.\n",
           PROGRAM, PROGRAM, formats);
}

static options_t *parse_options(int argc, char *argv[])
{
    options_t                 *options         = calloc_s(1, sizeof(options_t));

    /* Parameters for getopt_long() function */
    static const char          short_options[] = "AHSh:dief:V";

    static const struct option long_options[]  = {
        {"help",         no_argument,       NULL, 1  },
        {"all",          no_argument,       NULL, 'A'},
        {"all-headers",  no_argument,       NULL, 'H'},
        {"all-sections", no_argument,       NULL, 'S'},
        {"header",       required_argument, NULL, 'h'},
        {"imports",      no_argument,       NULL, 'i'},
        {"exports",      no_argument,       NULL, 'e'},
        {"dirs",         no_argument,       NULL, 'd'},
        {"format",       required_argument, NULL, 'f'},
        {"version",      no_argument,       NULL, 'V'},
        {NULL,           0,                 NULL, 0  }
    };

    options->all = true;

    int c, ind;

    while ((c = getopt_long(argc, argv, short_options, long_options, &ind))) {
        if (c < 0) {
            break;
        }

        switch (c) {
        case 1: // --help option
            usage();
            exit(EXIT_SUCCESS);
        case 'A':
            options->all = true;
            break;
        case 'H':
            options->all         = false;
            options->all_headers = true;
            break;
        case 'd':
            options->all  = false;
            options->dirs = true;
            break;
        case 'S':
            options->all          = false;
            options->all_sections = true;
            break;
        case 'V':
            printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
            exit(EXIT_SUCCESS);
        case 'h':
            options->all = false;
            parse_headers(options, optarg);
            break;
        case 'i':
            options->all     = false;
            options->imports = true;
            break;
        case 'e':
            options->all     = false;
            options->exports = true;
            break;
        case 'f':
            if (output_set_format_by_name(optarg) < 0) {
                EXIT_ERROR("invalid format option");
            }
            break;
        default:
            fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
            exit(EXIT_FAILURE);
        }
    }

    return options;
}

int readpe(int argc, char *argv[])
{
    struct readpe_config config;
    readpe_initialize(&config);

    if (argc < 2) {
        usage();
        return EXIT_FAILURE;
    }

    output_set_cmdline(argc, argv);

    options_t *options = parse_options(argc, argv); // opcoes

    pe_ctx_t   ctx;

    pe_err_e   err = pe_load_file(&ctx, argv[argc - 1]);
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

    output_open_document();

    // dos header
    if (options->dos || options->all_headers || options->all) {
        print_dos_header(&ctx);
    }

    // coff/file header
    if (options->coff || options->all_headers || options->all) {
        print_coff_header(&ctx);
    }

    // optional header
    if (options->opt || options->all_headers || options->all) {
        print_optional_header(&ctx);
    }

    IMAGE_DATA_DIRECTORY **directories        = get_pe_directories(&ctx);

    bool                   directories_warned = false;
    // directories
    if (options->dirs || options->all) {
        if (directories != NULL) {
            print_directories(&ctx);
        } else if (pe_is_exec(&ctx) && ! directories_warned) {
            LIBPE_WARNING("directories not found");
            directories_warned = true;
        }
    }

    // imports
    if (options->imports || options->all) {
        if (directories != NULL) {
            print_imports(&ctx);
        } else if (pe_is_exec(&ctx) && ! directories_warned) {
            LIBPE_WARNING("directories not found");
            directories_warned = true;
        }
    }

    // exports
    if (options->exports || options->all) {
        if (directories != NULL) {
            print_exports(&ctx);
        } else if (pe_is_exec(&ctx) && ! directories_warned) {
            LIBPE_WARNING("directories not found");
            directories_warned = true;
        }
    }

    // sections
    if (options->all_sections || options->all) {
        if (pe_sections(&ctx) != NULL) {
            print_sections(&ctx);
        } else {
            LIBPE_WARNING("unable to read sections");
        }
    }

    output_close_document();

    // libera a memoria
    free_options(options);

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
int main(int argc, char **argv) { return readpe(argc, argv); }
#endif


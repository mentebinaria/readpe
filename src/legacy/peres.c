/* vim :set ts=4 sw=4 sts=4 et : */
/*
    pev - the PE file analyzer toolkit

    peres.c - retrive informations and binary data of resources

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

#include "../legacy.h"
#include "common.h"
#include "readpe.h"

#include <assert.h>
#include <libpe/macros.h>
#include <libpe/utils.h>
#include <libpe/utlist.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROGRAM "peres"

typedef struct {
    bool all;
    bool extract;
    bool namedExtract;
    bool info;
    bool statistics;
    bool list;
    bool version;
    bool help;
} options_t;

static void usage(void)
{
    static char formats[255];
    output_available_formats(formats, sizeof(formats), '|');
    printf("Usage: %s OPTIONS FILE\n"
           "Show information about resource section and extract it\n"
           "\nExample: %s -a putty.exe\n"
           "\nOptions:\n"
           " -a, --all                             Show all information, "
           "statistics and extract resources\n"
           " -f, --format <%s> Change output format (default: text)\n"
           " -i, --info                            Show resources information\n"
           " -l, --list                            Show list view\n"
           " -s, --statistics                      Show resources statistics\n"
           " -x, --extract                         Extract resources\n"
           " -X, --named-extract                   Extract resources with path "
           "names\n"
           " -v, --file-version                    Show File Version from PE "
           "resource directory\n"
           " -V, --version                         Show version and exit\n"
           " --help                                Show this help and exit\n",
           PROGRAM, PROGRAM, formats);
}

static void free_options(options_t *options)
{
    // FIX: Don't need to test for NULL pointer.
    // if (options == NULL)
    //  return;

    free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
    options_t                 *options         = calloc_s(1, sizeof *options);

    /* Parameters for getopt_long() function */
    static const char          short_options[] = "a:f:ilsxXvV";

    static const struct option long_options[]  = {
        {"all",           required_argument, NULL, 'a'},
        {"format",        required_argument, NULL, 'f'},
        {"info",          no_argument,       NULL, 'i'},
        {"list",          no_argument,       NULL, 'l'},
        {"statistics",    no_argument,       NULL, 's'},
        {"extract",       no_argument,       NULL, 'x'},
        {"named-extract", no_argument,       NULL, 'X'},
        {"file-version",  no_argument,       NULL, 'v'},
        {"version",       no_argument,       NULL, 'V'},
        {"help",          no_argument,       NULL, 1  },
        {NULL,            0,                 NULL, 0  }
    };

    int c, ind;

    while ((c = getopt_long(argc, argv, short_options, long_options, &ind))) {
        if (c < 0) {
            break;
        }

        switch (c) {
        case 'a':
            options->all = true;
            break;
        case 'f':
            if (output_set_format_by_name(optarg) < 0) {
                EXIT_ERROR("invalid format option");
            }
            break;
        case 'i':
            options->info = true;
            break;
        case 'l':
            options->list = true;
            break;
        case 's':
            options->statistics = true;
            break;
        case 'x':
            options->extract = true;
            break;
        case 'X':
            options->extract      = true;
            options->namedExtract = true;
            break;
        case 'v':
            options->version = true;
            break;
        case 'V':
            printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
            exit(EXIT_SUCCESS);
        case 1: // --help option
            usage();
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
            exit(EXIT_FAILURE);
        }
    }

    return options;
}

int peres(int argc, char **argv)
{
    struct readpe_config config;
    readpe_initialize(&config);

    if (argc < 3) {
        usage();
        exit(EXIT_FAILURE);
    }

    output_set_cmdline(argc, argv);

    options_t  *options = parse_options(argc, argv); // opcoes

    const char *path    = argv[argc - 1];
    pe_ctx_t    ctx;

    pe_err_e    err = pe_load_file(&ctx, path);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        free_options(options);
        return EXIT_FAILURE;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        free_options(options);
        return EXIT_FAILURE;
    }

    if (! pe_is_pe(&ctx)) {
        free_options(options);
        EXIT_ERROR("not a valid PE file");
    }

    output_open_document();

    if (options->all) {
        print_resources(&ctx);
        print_resources_stats(&ctx);
        print_resources_list(&ctx);
        extract_all_resources(&ctx, options->namedExtract);
        print_file_version(&ctx);
    } else {
        if (options->extract) {
            extract_all_resources(&ctx, options->namedExtract);
        }
        if (options->info) {
            print_resources(&ctx);
        }
        if (options->list) {
            print_resources_list(&ctx);
        }
        if (options->statistics) {
            print_resources_stats(&ctx);
        }
        if (options->version) {
            print_file_version(&ctx);
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
int main(int argc, char **argv) { return peres(argc, argv); }
#endif


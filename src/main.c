/* vim: set ts=4 sw=4 noet: */
/*
        readpe - the PE file analyzer toolkit

        main.c - main executable entry

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

#include "common.h"
#include "config.h"
#include "modes.h"
#include "output.h"
#include "readpe.h"

#ifdef READPE_LEGACY
#include "legacy.h"
#endif

#include <getopt.h>
#include <libpe/context.h>
#include <libpe/error.h>
#include <libpe/macros.h>
#include <libpe/pe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __GNUC__
#define ATTRIBUTE_NORETURN __attribute__((noreturn))
#else
#define ATTRIBUTE_NORETURN
#endif

static struct readpe_settings g_settings;
static struct readpe_config   g_config;

// ------------------------------------------------------------------------- //

struct mode_option {
    const char *const name;
    const int         value;
};

static int getopt_mode(int argc, char *const argv[], const char *optstring,
                       const struct option      *longopts,
                       const struct mode_option *modeopts, int *restrict index)
{
    // static int nextchar;
    if (optind >= argc) {
        return -1;
    }
    const char *const arg = argv[optind];

    if (arg[0] == '-') {
        if (arg[1] == '-') {
            if (arg[2] == '\0') {
                // -- force end scan
                return -1;
            }
            // long option
            return getopt_long(argc, argv, optstring, longopts, index);
        } else {
            // short option
            return getopt(argc, argv, optstring);
        }
    } else {
        // mode option
        if (modeopts == NULL) {
            return -1;
        }

        for (int i = 0; (modeopts)[i].name != NULL; ++i) {
            struct mode_option opt = (modeopts)[i];

            if (strcmp(opt.name, arg) == 0) {
                optind++;
                return opt.value;
            }
        }
    }

    return -1;
}

// ------------------------------------------------------------------------- //

// GNU compliant version output
ATTRIBUTE_NORETURN static void version(void)
{
    printf("readpe %s\n"
           "Copyright (C) 2023 readpe authors\n"
           "License GPLv2+: GNU GPL version 2 or later "
           "<https://www.gnu.org/licenses/gpl-2.0.txt>.\n"
           "This is free software: "
           "you are free to change and redistribute it.\n"
           "There is NO WARRANTY, to the extent permitted by law.\n",
           VERSION);
    exit(EXIT_SUCCESS);
}

// GNU compliant help output
ATTRIBUTE_NORETURN static void help(void)
{
    const char *helptext
        = "Usage:   readpe [<mode> | <command> | <arguments> ] [<pe-file>]\n"
          "Example: readpe header coff explorer.exe\n"
          "\nModes:\n"
          "  header             Output information on PE headers\n"
          "                         Supports submodes:\n"
          "                         dos, coff and optional\n"
          "  section            Output information on PE sections\n"
          "                         Supported submodes are section names\n"
          "                         and section indexes\n"
          "  directories        Output list of available PE directories\n"
          "  exports            Output exported symbols\n"
          "  imports            Output imported libraries and symbols\n"
          "  resources          Output information or extract resources\n"
          "  certificates       Output information or extract certificates\n"
          "  features           Output PE features\n"
          "  security           Output PE security features\n"
          "\nCommands:\n"
          "  hash               Output various hashes of file or mode\n"
          "                         Supports header and section\n"
          "                         and their submodes\n"
          "  scan               Search for suspicious things in PE files\n"
          "\nArguments:\n"
          "-f, --format=FORMAT  Set what which output plugin to use\n"
          "    --file-version   Display resource specified file version\n"
          "-h, --help           Display this help and exit\n"
          "-V, --version        Display version information and exit\n";

    printf("%s", helptext);
    printf("\nReport bugs to: https://github.com/mentebinaria/readpe/issues\n");
    exit(EXIT_SUCCESS);
}

// ------------------------------------------------------------------------- //

static const char          scan_shortopts[] = "vf:hV";
static const struct option scan_longopts[]  = {
    {"verbose", no_argument,       NULL, 'v'},
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char          res_shortopts[] = "ltvsf:hV";
static const struct option res_longopts[]  = {
    {"list",         no_argument,       NULL, 'l'},
    {"tree",         no_argument,       NULL, 't'},
    {"verbose",      no_argument,       NULL, 'v'},
    {"file-version", no_argument,       NULL, 2  },
    {"statistics",   no_argument,       NULL, 's'},
    {"format",       required_argument, NULL, 'f'},
    {"help",         no_argument,       NULL, 'h'},
    {"version",      no_argument,       NULL, 'V'},
    {NULL,           0,                 NULL, 0  }
};

static const char          ext_shortopts[] = "nhV";
static const struct option ext_longopts[]  = {
    {"named",   no_argument, NULL, 'n'},
    {"help",    no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL,      0,           NULL, 0  }
};

static const char          cert_shortopts[] = "of:hV";
static const struct option cert_longopts[]  = {
    {"out",     required_argument, NULL, 'o'},
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char          section_short[] = "ali:n:f:hV";
static const struct option section_long[]  = {
    {"all",     no_argument,       NULL, 'a'},
    {"list",    no_argument,       NULL, 'l'},
    {"index",   required_argument, NULL, 'i'},
    {"name",    required_argument, NULL, 'n'},
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char          dir_shortopts[] = "lvf:hV";
static const struct option dir_longopts[]  = {
    {"list",    no_argument,       NULL, 'l'},
    {"verbose", no_argument,       NULL, 'v'},
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char          default_shortopts[] = "f:hV";
static const struct option default_longopts[]  = {
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char          extended_shortopts[] = "alf:hV";
static const struct option extended_longopts[]  = {
    {"all",     no_argument,       NULL, 'a'},
    {"list",    no_argument,       NULL, 'l'},
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char          base_shortopts[] = "f:hV";
static const struct option base_longopts[]  = {
    {"file-version",       no_argument,       NULL, 2  },
    {"get-output-plugins", no_argument,       NULL, 3  },
    {"format",             required_argument, NULL, 'f'},
    {"help",               no_argument,       NULL, 'h'},
    {"version",            no_argument,       NULL, 'V'},
    {NULL,                 0,                 NULL, 0  }
};

// ------------------------------------------------------------------------- //

static const struct mode_option header_mode[] = {
    {"dos",      MODE_HEADERS_DOS     },
    {"coff",     MODE_HEADERS_COFF    },
    {"optional", MODE_HEADERS_OPTIONAL},
    {"hash",     COMMAND_HASH         },
    {NULL,       0                    }
};

static const struct mode_option hash_mode[] = {
    {"hash", COMMAND_HASH},
    {NULL,   0           }
};

static const struct mode_option hashstr_mode[] = {
    {"hash",    COMMAND_HASH   },
    {"strings", COMMAND_STRINGS},
    {NULL,      0              }
};

static const struct mode_option resource_mode[] = {
    {"extract", COMMAND_EXTRACT},
    {NULL,      0              }
};

static const struct mode_option base_mode[] = {
    {"header",       MODE_HEADERS     },
    {"section",      MODE_SECTIONS    },
    {"directories",  MODE_DIRECTORIES },
    {"exports",      MODE_EXPORTS     },
    {"imports",      MODE_IMPORTS     },
    {"resources",    MODE_RESOURCES   },
    {"certificates", MODE_CERTIFICATES},
    {"features",     MODE_SECURITY    },
    {"security",     MODE_SECURITY    },
    {"strings",      COMMAND_STRINGS  },
    {"scan",         COMMAND_SCAN     },
    {"hash",         COMMAND_HASH     },
    {NULL,           0                }
};

// ------------------------------------------------------------------------- //

#ifdef READPE_LEGACY
static void legacy(int argc, char *argv[])
{
    const char *bin_name = strrchr(argv[0], '/');
    // If no '/' in caller (called from env) we set it to the original caller
    // This obviously does not work for CP/M style pathing
    bin_name             = bin_name ? bin_name + 1 : argv[0];
    const size_t len     = strlen(bin_name);
    if (len < 5) {
        return;
    }

    if (strstr(bin_name, "peldd") == bin_name) {
        exit(rva2ofs(argc, argv));
    } else if (strstr(bin_name, "pesec") == bin_name) {
        exit(ofs2rva(argc, argv));
    } else if (strstr(bin_name, "pestr") == bin_name) {
        exit(ofs2rva(argc, argv));
    } else if (strstr(bin_name, "peres") == bin_name) {
        exit(ofs2rva(argc, argv));
    }
#ifdef READPE_DISASSEMBLER
    else if (strstr(bin_name, "pedis") == bin_name) {
        exit(ofs2rva(argc, argv));
    }
#endif // READPE_DISASSEMBLER
    else if (strstr(bin_name, "pescan") == bin_name) {
        exit(ofs2rva(argc, argv));
    } else if (strstr(bin_name, "pehash") == bin_name) {
        exit(ofs2rva(argc, argv));
    } else if (strstr(bin_name, "pepack") == bin_name) {
        exit(rva2ofs(argc, argv));
    }
#if 0
    else if (strstr(bin_name, "ofs2rva") == bin_name) {
        exit(ofs2rva(argc, argv));
    } else if (strstr(bin_name, "rva2ofs") == bin_name) {
        exit(rva2ofs(argc, argv));
    }
#endif
}
#endif // READPE_LEGACY

// ------------------------------------------------------------------------- //

static int handle_file(const char *filename)
{
    pe_ctx_t ctx;
    pe_err_e err = pe_load_file(&ctx, filename);
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

    switch (g_settings.mode) {
    case MODE_BASE:
        if (g_settings.file_version) {
            print_file_version(&ctx);
            break;
        }
        print_dos_header(&ctx);
        print_coff_header(&ctx);
        print_optional_header(&ctx);
        print_directories(&ctx);
        print_imports(&ctx);
        print_exports(&ctx);
        print_sections(&ctx);
        break;
    case MODE_HEADERS:
        if (g_settings.list) {
            // TODO:
            printf("dos\ncoff\noptional\n");
            break;
        }
        print_dos_header(&ctx);
        print_coff_header(&ctx);
        print_optional_header(&ctx);
        break;
    case MODE_HEADERS_DOS:
        print_dos_header(&ctx);
        break;
    case MODE_HEADERS_COFF:
        print_coff_header(&ctx);
        break;
    case MODE_HEADERS_OPTIONAL:
        print_optional_header(&ctx);
        break;
    case MODE_DIRECTORIES:
        print_directory_list(&ctx, g_settings.verbose);
        break;
    case MODE_EXPORTS:
        print_exports(&ctx);
        break;
    case MODE_IMPORTS:
        if (g_settings.verbose) {
            print_imports(&ctx);
            break;
        }
        print_dependencies(&ctx);
        break;

    case MODE_RESOURCES: {
        bool printed = false;

        if (g_settings.verbose) {
            print_resources(&ctx);
            printed = true;
        }

        if (g_settings.list && ! g_settings.verbose) {
            print_resources_list(&ctx);
            printed = true;
        }

        if (g_settings.res_tree) {
            print_resources_tree(&ctx);
            printed = true;
        }

        if (g_settings.res_statistics) {
            print_resources_stats(&ctx);
            printed = true;
        }

        if (g_settings.file_version) {
            print_file_version(&ctx);
            printed = true;
        }

        // If we haven't printed anything yet
        if (! printed) {
            print_resources_list(&ctx);
            // peres_save_all_resources(&ctx, root_node,
            // options->namedExtract);
            print_resources_stats(&ctx);
            print_file_version(&ctx);
        }
        break;
    }

        // case MODE_EXCEPTIONS:

    case MODE_SECURITY:
        print_securities(&ctx);
        break;
        // fall through
    case MODE_CERTIFICATES:
        print_certificates(&ctx, g_settings.cert_format, g_settings.cert_out);
        break;

        // case MODE_BASE_RELOCATIONS:
        // case MODE_DEBUG:
        // case MODE_ARCHITECTURE:
        // case MODE_GLOBAL_PTR:
        // case MODE_TLS:
        // case MODE_LOAD_CONFIGS:
        // case MODE_BOUND_IMPORT:
        // case MODE_IAT:
        // case MODE_DELAY_IMPORT_DESCRIPTOR:
        // case MODE_CLR_RUNTIME_HEADER:

    case MODE_SECTIONS:
        if (g_settings.all) {
            print_sections(&ctx);
            break;
        }
        print_sections_list(&ctx);
        break;

    case MODE_SECTION:
        print_section_by_name(&ctx, g_settings.section_name);
        break;

    case COMMAND_STRINGS:
        // print_strings(&ctx, &CONFIG.string);
        break;

    case COMMAND_HASH:
        // TODO
        // case COMMAND_HASH_MD5:
        // case COMMAND_HASH_SHA1:
        // case COMMAND_HASH_SHA256:
        // case COMMAND_HASH_SSDEEP:
        // case COMMAND_HASH_IMPHASH:
        print_hash(&ctx, &g_settings);
        break;

    case COMMAND_SCAN: {
        pe_scan(&ctx, g_settings.verbose);
        break;
    }

    case COMMAND_EXTRACT: {
        extract_all_resources(&ctx, g_settings.res_named);
        break;
    }

    default:
        printf("Unknown Argument: %d\n", g_settings.mode);
        exit(-1);
    }

    output_close_document();

    // free
    err = pe_unload(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// ------------------------------------------------------------------------- //

static const char *parse_options(int argc, char *argv[])
{

    const char               *shortargs = base_shortopts;
    const struct option      *longargs  = base_longopts;
    const struct mode_option *modeargs  = base_mode;

    int c, file_arg = 0, mode = 0, mode_context = 0, index = 1;

    if (access(argv[1], F_OK) == 0) {
        optind++;
        file_arg = 1;
    }

    while (
        (c = getopt_mode(argc, argv, shortargs, longargs, modeargs, &index))) {
        if (c < 0) {
            break;
        }

        if (c >= MODE_START) {
            mode = c;
        }

        if (mode < COMMAND_START) {
            mode_context = mode;
        }

        switch (c) {
        // ARGUMENTS
        case 2:
            g_settings.file_version = true;
            modeargs                = NULL;
            break;
        case 'a':
            if (mode == MODE_HEADERS || mode == MODE_SECTIONS) {
                g_settings.all = true;
                modeargs       = NULL;
            }
            break;
        case 'V':
            version();
            break;
        case 'h':
            if (mode == MODE_RESOURCES) {
                // TODO: print readpe-resources help
                printf("readpe-resources --help:\n");
                exit(EXIT_SUCCESS);
            }
            help();
            break;
        case 'f':
            if (mode == MODE_CERTIFICATES) {
                g_settings.cert_format = optarg;
                break;
            }
            if (output_set_format_by_name(optarg) < 0) {
                // static char formats[255];
                // output_available_formats(formats, sizeof(formats), '|');
                // printf("Format: %s\nAvailable: %s\n", optarg, formats);
                EXIT_ERROR("invalid format option");
            }
            break;
        case 'l':
            if (mode == MODE_HEADERS || mode == MODE_SECTIONS
                || mode == MODE_DIRECTORIES || mode == MODE_RESOURCES
                || mode == MODE_IMPORTS) {
                g_settings.list = true;
                modeargs        = NULL;
            }
            break;
        case 'n':
            if (mode == COMMAND_EXTRACT && mode_context == MODE_RESOURCES) {
                g_settings.res_named = true;
            }
            break;
        case 'p':
            /* Note: Declaration after label is an extension*/;
            char buffer[255];
            output_available_formats(buffer, sizeof(buffer), '\n');
            printf("%s\n", buffer);
            exit(EXIT_SUCCESS);
            break;
        case 's':
            if (mode == MODE_RESOURCES) {
                g_settings.res_statistics = true;
                modeargs                  = NULL;
            }
            break;
        case 't':
            if (mode == MODE_RESOURCES) {
                g_settings.res_tree = true;
                modeargs            = NULL;
            }
            break;
        case 'v':
            if (mode == MODE_DIRECTORIES || mode == MODE_RESOURCES
                || mode == COMMAND_SCAN || mode == MODE_IMPORTS) {
                g_settings.verbose = true;
                modeargs           = NULL;
            }
            break;

        // MODES
        case MODE_HEADERS:
            shortargs = extended_shortopts;
            longargs  = extended_longopts;
            modeargs  = header_mode;
            break;
        case MODE_HEADERS_DOS:
        case MODE_HEADERS_COFF:
        case MODE_HEADERS_OPTIONAL:
        case MODE_SECTION:
            shortargs = default_shortopts;
            longargs  = default_longopts;
            modeargs  = hash_mode;
            break;
        case MODE_SECTIONS:
            if ((optind < argc - 1) && (*argv[optind] != '-')
                && ! ! strcmp(argv[optind], "hash")) {
                mode                    = MODE_SECTION;
                mode_context            = MODE_SECTION;
                g_settings.section_name = argv[optind];
                ++optind;
            }
            shortargs = section_short;
            longargs  = section_long;
            modeargs  = hashstr_mode;
            break;
        case MODE_DIRECTORIES:
        case MODE_IMPORTS:
            shortargs = dir_shortopts;
            longargs  = dir_longopts;
            modeargs  = NULL;
            break;
        case MODE_RESOURCES:
            shortargs = res_shortopts;
            longargs  = res_longopts;
            modeargs  = resource_mode;
            break;
        case MODE_CERTIFICATES:
            shortargs = cert_shortopts;
            longargs  = cert_longopts;
            modeargs  = NULL;
            break;
        case MODE_SECURITY:
        case MODE_EXPORTS:
            shortargs = default_shortopts;
            longargs  = default_longopts;
            modeargs  = NULL;
            break;

        // COMMANDS
        case COMMAND_EXTRACT:
            shortargs = ext_shortopts;
            longargs  = ext_longopts;
            modeargs  = NULL;
            break;
        case COMMAND_SCAN:
            shortargs = scan_shortopts;
            longargs  = scan_longopts;
            modeargs  = NULL;
            break;
        case COMMAND_STRINGS:
        case COMMAND_HASH:
            shortargs = default_shortopts;
            longargs  = default_longopts;
            modeargs  = NULL;
            break;
        }
    }

    if (access(argv[argc - 1], F_OK) == 0) {
        file_arg = argc - 1;
    }
    if (file_arg == 0) {
        help();
    }

    g_settings.mode    = mode;
    g_settings.context = mode_context;

    return argv[file_arg];
}

// ------------------------------------------------------------------------- //

int main(int argc, char *argv[])
{
#ifdef READPE_LEGACY
    legacy(argc, argv);
#endif // READPE_LEGACY

    // Print help when no arguments are given
    if (argc < 2) {
        help();
    }

    readpe_initialize(&g_config);

    const char *filename     = parse_options(argc, argv);
    int         return_value = handle_file(filename);

    readpe_finalize(&g_config);

    return return_value;
}


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

#include "main.h"
#include "common.h"
#include "output.h"
#include "peldd.h"
#include "peres.h"
#include "pescan.h"
#include "pesec.h"
#include "pestr.h"
#include "readpe.h"

#include <libpe/hdr_optional.h>
#include <libpe/macros.h>

#include <bits/getopt_core.h>
#include <bits/getopt_ext.h>
#include <bits/stdint-uintn.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * --format
 * --version
 * --help
 *
 * readpe [--all]
 * 	=> readpe
 * readpe --all-header
 * 	=> readpe header --all
 * readpe --all-sections
 * 	=> readpe section --all
 * readpe --dirs
 * 	=> readpe directory [--list] --verbose
 * readpe --header <dos|coff|optional>
 * 	=> readpe header <dos|coff|optional>
 * readpe --imports # TODO: Implement --verbose/--list
 * 	=> readpe imports
 * readpe --exports
 * 	=> readpe exports
 *
 * peres
 * 	=> readpe resources --help
 * peres --all
 * 	=> ----
 * peres --info
 * 	=> readpe resources [--list] --verbose
 * 	=> readpe resources --tree
 * peres --list
 * 	=> readpe resources [--list]
 * peres --statistics
 * 	=> readpe resources --statistics
 * peres --extract
 * 	=> readpe resources extract
 * peres --named-extract
 * 	=> readpe resources extract --name
 * peres --file-version
 * => readpe [resources] --file-version
 *
 * pescan
 * 	=> readpe <scan|lint>
 * pescan --verbose
 * 	=> readpe scan --verbose
 *
 * peldd
 * 	=> readpe libraries
 *
 * pesec
 * 	=> readpe [features|security]
 * pesec --certout /dev/stdout
 * 	=> readpe certificates
 * pesec --certout <filename>
 * 	=> readpe certificates --out <filename>
 * pesec --certoutform <text|pem>
 * 	=> readpe certificates --format <text|x509|pem>
 *
 * pehash [--all|--content]
 * 	=> readpe hash
 * pehash --header
 * 	=> readpe header <dos|coff|optional> hash
 * pehash --section <section_name>
 * 	=> readpe section {section_name} hash
 * pehash --section_index <section_index>
 * 	=> readpe section @<section_index> hash
 *
 * pestr
 * 	=> readpe strings
 * pestr --min-length
 * 	=> readpe [...] strings --min-length
 * pestr --offset
 * 	=> readpe [...] strings --offset
 * pestr --section
 * 	=> readpe section {section_name} strings
 *
 */

enum MODES {
    MODE_BASE = 0,

    MODE_START = 1000,
    MODE_HEADERS,
    MODE_HEADERS_DOS,
    MODE_HEADERS_COFF,
    MODE_HEADERS_OPTIONAL,
    MODE_DIRECTORIES,
    MODE_EXPORTS,
    MODE_IMPORTS,
    MODE_RESOURCES, // -- peres
    // MODE_EXCEPTIONS,
    MODE_CERTIFICATES, // not part of image / -- pesec
    // MODE_BASE_RELOCATIONS,
    // MODE_DEBUG,
    // MODE_ARCHITECTURE,
    // MODE_GLOBAL_PTR,
    // MODE_TLS,
    // MODE_LOAD_CONFIGS,
    // MODE_BOUND_IMPORT,
    // MODE_IAT,
    // MODE_DELAY_IMPORT_DESCRIPTOR,
    // MODE_CLR_RUNTIME_HEADER,
    MODE_SECURITY, // Duplicate of MODE_CERTIFICATES,
    MODE_SECTIONS,
    MODE_SECTION,
    MODE_LIBRARIES, // -- peldd

    COMMAND_START = 2000,
    COMMAND_LIST,
    COMMAND_SCAN, // -- pescan
    COMMAND_EXTRACT,
    COMMAND_HASH,    // -- pehash
                     // COMMAND_HASH_MD5,
                     // COMMAND_HASH_SHA1,
                     // COMMAND_HASH_SHA256,
                     // COMMAND_HASH_SSDEEP,
                     // COMMAND_HASH_IMPHASH,
    COMMAND_STRINGS, // -- pestr
    // MODE_STRINGS_ASCII,
    // MODE_STRINGS_UNICODE,

    // COMMAND_DISASSAMBLE = 100000, // -- pedis
    // COMMAND_PACK,                 // -- pepack
    // COMMAND_ADDRESSING_RELATIVE, // -- ofs2rva
    // COMMAND_ADDRESSING_OFFSET,   // -- rva2ofs
};

enum HASH_ALGO {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SSDEEP,
    HASH_IMPHASH,
    HASH_ALL
};

enum ARG_VARIABLE_TYPE {
    VAR_BOOL = 1,
    VAR_CSTRING,
    VAR_UINT16
};

static readpe_settings_t g_settings;

static struct _conf_t {
    unsigned int list : 1;
    unsigned int all : 1;
    char *format;
    char *section;
    certificate_settings certificate;
    string_settings string;
} CONFIG;

typedef struct {
    const char *const name;
    const int has_arg;
    const int *flag;
    int val;
} option;

typedef struct {
    const char *const name;
    const int value;
} exoption;

bool str2bool(const char *const str)
{
    if (str == NULL) {
        EXIT_ERROR("Internal error (str2bool)");
    } else if (*str == '0') {
        return false;
    } else if (*str == '1') {
        return true;
    } else if (strcmp(str, "false") == 0) {
        return false;
    } else if (strcmp(str, "true") == 0) {
        return true;
    } else {
        EXIT_ERROR("Bad bool variable");
    }

    return false;
}

int optmod;

int getopt_mode(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, const exoption *modeopts,
                int *restrict index)
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
            exoption opt = (modeopts)[i];

            if (strcmp(opt.name, arg) == 0) {
                optind++;
                return opt.value;
            }
        }
    }

    return -1;
}

// GNU compliant version output
__attribute__((noreturn)) void version(void)
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
__attribute__((noreturn)) void help(void)
{
    printf("Usage: readpe [<pe-file>] [<mode>] [<command>] [<pe-file>]\n");

    printf("\nReport bugs to: https://github.com/mentebinaria/readpe/issues\n");
    exit(EXIT_SUCCESS);
}

void complete(const exoption *opts)
{
    size_t i = 0;
    const exoption *c;
    while ((c = &opts[i])) {
        if (c->name == NULL) {
            break;
        }
        printf("%s ", c->name);
        ++i;
    }
    printf("\n");
    exit(EXIT_SUCCESS);
}

void usage(void) { }

static const char readpe_short_options[] = "AHSh:dief:V";
static const struct option readpe_long_options[] = {
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

// static const char pedis_short_options[] = "em:i:n:o:r:s:f:V";
// static const struct option pedis_long_options[] = {
//     {"help",       no_argument,       NULL, 1  },
//     {"att",        no_argument,       NULL, 2  },
//     {"",           required_argument, NULL, 'n'},
//     {"entrypoint", no_argument,       NULL, 'e'},
//     {"mode",       required_argument, NULL, 'm'},
//     {"offset",     required_argument, NULL, 'o'},
//     {"rva",        required_argument, NULL, 'r'},
//     {"section",    required_argument, NULL, 's'},
//     {"format",     required_argument, NULL, 'f'},
//     {"version",    no_argument,       NULL, 'V'},
//     {NULL,         0,                 NULL, 0  }
// };

static const char pehash_short_options[] = "f:a:c:h:s:V";
static const struct option pehash_long_options[] = {
    {"help",          no_argument,       NULL, 1  },
    {"format",        required_argument, NULL, 'f'},
    {"all",           no_argument,       NULL, 'a'},
    {"content",       no_argument,       NULL, 'c'},
    {"header",        required_argument, NULL, 'h'},
    {"section-name",  required_argument, NULL, 's'},
    {"section-index", required_argument, NULL, 2  },
    {"version",       no_argument,       NULL, 'V'},
    {NULL,            0,                 NULL, 0  }
};

static const char peres_short_options[] = "a:f:ilsxXvV";
static const struct option peres_long_options[] = {
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

static const char scan_shortopts[] = "f:v";
static const struct option scan_longopts[] = {
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 1  },
    {"verbose", no_argument,       NULL, 'v'},
    // {"version",       no_argument,       NULL, 'V'},
    {NULL,      0,                 NULL, 0  }
};

static const char pesec_short_options[] = "f:c:o:V";
static const struct option pesec_long_options[] = {
    {"format",      required_argument, NULL, 'f'},
    {"certoutform", required_argument, NULL, 'c'},
    {"certout",     required_argument, NULL, 'o'},
    {"help",        no_argument,       NULL, 1  },
    {"version",     no_argument,       NULL, 'V'},
    {NULL,          0,                 NULL, 0  }
};

static const char pestr_short_options[] = "osn:V";
static const struct option pestr_long_options[] = {
    {"offset",     no_argument,       NULL, 'o'},
    {"section",    no_argument,       NULL, 's'},
    {"min-length", required_argument, NULL, 'n'},
    {"help",       no_argument,       NULL, 1  },
    {"version",    no_argument,       NULL, 'V'},
    {NULL,         0,                 NULL, 0  }
};

static const char res_shortopts[] = "lvhf:";
static const struct option res_longopts[] = {
    {"format",       required_argument, NULL, 'f'},
    {"help",         no_argument,       NULL, 'h'},
    {"list",         no_argument,       NULL, 'l'},
    {"statistics",   no_argument,       NULL, 's'},
    {"tree",         no_argument,       NULL, 't'},
    {"verbose",      no_argument,       NULL, 'v'},
    {"file-version", no_argument,       NULL, 2  },
    {NULL,           0,                 NULL, 0  }
};

static const char cert_shortopts[] = "o:c:hf:";
static const struct option cert_longopts[] = {
    {"certout",   required_argument, NULL, 'o'},
    {"outformat", required_argument, NULL, 'c'},
    {"format",    required_argument, NULL, 'f'},
    {"help",      no_argument,       NULL, 'h'},
    {NULL,        0,                 NULL, 0  }
};

static const char section_short[] = "Ali:n:hf:";
static const struct option section_long[] = {
    {"all",    no_argument,       NULL, 'A'},
    {"list",   no_argument,       NULL, 'l'},
    {"index",  required_argument, NULL, 'i'},
    {"name",   required_argument, NULL, 'n'},
    {"format", required_argument, NULL, 'f'},
    {"help",   no_argument,       NULL, 'h'},
    {NULL,     0,                 NULL, 0  }
};

static const char dir_shortopts[] = "lvhf:";
static const struct option dir_longopts[] = {
    {"list",    no_argument,       NULL, 'l'},
    {"verbose", no_argument,       NULL, 'v'},
    {"format",  required_argument, NULL, 'f'},
    {"help",    no_argument,       NULL, 'h'},
    {NULL,      0,                 NULL, 0  }
};

static const char default_shortopts[] = "hf:";
static const struct option default_longopts[] = {
    {"format", required_argument, NULL, 'f'},
    {"help",   no_argument,       NULL, 'h'},
    {NULL,     0,                 NULL, 0  }
};

static const char extended_shortopts[] = "Alhf:";
static const struct option extended_longopts[] = {
    {"all",    no_argument,       NULL, 'A'},
    {"list",   no_argument,       NULL, 'l'},
    {"format", required_argument, NULL, 'f'},
    {"help",   no_argument,       NULL, 'h'},
    {NULL,     0,                 NULL, 0  }
};

static const char base_shortopts[] = "hf:";
static const struct option base_longopts[] = {
    {"get-output-plugins", no_argument,       NULL, 'p'},
    {"file-version",       no_argument,       NULL, 2  },
    {"format",             required_argument, NULL, 'f'},
    {"help",               no_argument,       NULL, 'h'},
    {NULL,                 0,                 NULL, 0  }
};

//------------------------------------------------------------------------//

static const exoption end_mode[] = {
    {NULL, 0}
};

static const exoption header_mode[] = {
    {"dos",      MODE_HEADERS_DOS     },
    {"coff",     MODE_HEADERS_COFF    },
    {"optional", MODE_HEADERS_OPTIONAL},
    {"hash",     COMMAND_HASH         },
    {NULL,       0                    }
};

static const exoption hash_mode[] = {
    {"hash", COMMAND_HASH},
    {NULL,   0           }
};

static const exoption hashstr_mode[] = {
    {"hash",    COMMAND_HASH   },
    {"strings", COMMAND_STRINGS},
    {NULL,      0              }
};

static const exoption resource_mode[] = {
    {"extract", COMMAND_EXTRACT},
    {NULL,      0              }
};

static const exoption base_mode[] = {
    {"header",       MODE_HEADERS     },
    {"section",      MODE_SECTIONS    },
    {"directory",    MODE_DIRECTORIES },
    {"exports",      MODE_EXPORTS     },
    {"imports",      MODE_IMPORTS     },
    {"resources",    MODE_RESOURCES   },
    {"certificates", MODE_CERTIFICATES},
    {"features",     MODE_SECURITY    },
    {"security",     MODE_SECURITY    },
    {"libraries",    MODE_LIBRARIES   },
    {"strings",      COMMAND_STRINGS  },
    {"scan",         COMMAND_SCAN     },
    {"hash",         COMMAND_HASH     },
    {NULL,           0                }
};

//------------------------------------------------------------------------//

//------------------------------------------------------------------------//

void legacy(int argc, char *argv[])
{
    const char *bin_name = strrchr(argv[0], '/');
    // If no '/' in caller (called from env) we set it to the original caller
    // This obviously does not work for CP/M style pathing
    bin_name = bin_name ? bin_name + 1 : argv[0];

    // Legacy executables
    if (strstr(bin_name, "peldd") == bin_name) {
        exit(peldd(argc, argv));
    }
    if (strstr(bin_name, "pestr") == bin_name) {
        exit(pestr(argc, argv));
    }
    if (strstr(bin_name, "pescan") == bin_name) {
        exit(pescan(argc, argv));
    }
    if (strstr(bin_name, "pehash") == bin_name) {
        exit(pehash(argc, argv));
    }
    if (strstr(bin_name, "pesec") == bin_name) {
        exit(pesec(argc, argv));
    }
    if (strstr(bin_name, "peres") == bin_name) {
        exit(peres(argc, argv));
    }
    if (strstr(bin_name, "pedis") == bin_name) {
        exit(pedis(argc, argv));
    }
    if (strstr(bin_name, "pepack") == bin_name) {
        exit(pepack(argc, argv));
    }
    // if (strstr(bin_name, "ofs2rva") == bin_name) {
    //     exit(ofs2rva(argc, argv));
    // }
    // if (strstr(bin_name, "rva2ofs") == bin_name) {
    //     exit(rva2ofs(argc, argv));
    // }
}

int main(int argc, char *argv[])
{
    legacy(argc, argv);

    pev_config_t config;
    PEV_INITIALIZE(&config);

    // Print help when no arguments are given
    if (argc < 2) {
        help();
    }

    const char *shortargs = base_shortopts;
    const struct option *longargs = base_longopts;
    const exoption *modeargs = base_mode;

    int c, file_arg = 0, mode = 0, mode_context = 0, index = 1;

    // if (access(argv[index], F_OK) == 0) {
    //     file_arg = index;
    //     ++index;
    // }

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
        case 1:
            help();
            break;
        case 2:
            g_settings.file_version = true;
            modeargs = NULL;
            break;
        case 'A':
            if (mode == MODE_HEADERS || mode == MODE_SECTIONS) {
                g_settings.all = true;
                modeargs = NULL;
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
                || mode == MODE_DIRECTORIES || mode == MODE_RESOURCES) {
                g_settings.list = true;
                modeargs = NULL;
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
                modeargs = NULL;
            }
            break;
        case 't':
            if (mode == MODE_RESOURCES) {
                g_settings.res_tree = true;
                modeargs = NULL;
            }
            break;
        case 'v':
            if (mode == MODE_DIRECTORIES || mode == MODE_RESOURCES
                || mode == COMMAND_SCAN) {
                g_settings.verbose = true;
                modeargs = NULL;
            }
            break;

        // MODES
        case MODE_HEADERS:
            shortargs = extended_shortopts;
            longargs = extended_longopts;
            modeargs = header_mode;
            break;
        case MODE_HEADERS_DOS:
        case MODE_HEADERS_COFF:
        case MODE_HEADERS_OPTIONAL:
        case MODE_SECTION:
            shortargs = default_shortopts;
            longargs = default_longopts;
            modeargs = hash_mode;
            break;
        case MODE_SECTIONS:
            if ((optind < argc - 1) && (*argv[optind] != '-')) {
                mode = MODE_SECTION;
                g_settings.section_name = argv[optind];
                ++optind;
            }
            shortargs = section_short;
            longargs = section_long;
            modeargs = hashstr_mode;
            break;
        case MODE_DIRECTORIES:
            shortargs = dir_shortopts;
            longargs = dir_longopts;
            modeargs = NULL;
            break;
        case MODE_RESOURCES:
            shortargs = res_shortopts;
            longargs = res_longopts;
            modeargs = resource_mode;
            break;
        case MODE_CERTIFICATES:
            shortargs = cert_shortopts;
            longargs = cert_longopts;
            modeargs = NULL;
            break;

        // COMMANDS
        case COMMAND_EXTRACT:
            shortargs = default_shortopts;
            longargs = default_longopts;
            modeargs = NULL;
            break;
        case COMMAND_SCAN:
            shortargs = scan_shortopts;
            longargs = scan_longopts;
            modeargs = NULL;
            break;
        case MODE_SECURITY:
        case MODE_EXPORTS:
        case MODE_IMPORTS:
        case MODE_LIBRARIES:
            shortargs = default_shortopts;
            longargs = default_longopts;
            modeargs = NULL;
            break;
        case COMMAND_STRINGS:
        case COMMAND_HASH:
            shortargs = default_shortopts;
            longargs = default_longopts;
            modeargs = NULL;
            break;
        }

        // switch (mode) {
        // case MODE_BASE:
        //     break;
        // case MODE_HEADERS:
        // case MODE_HEADERS_DOS:
        // case MODE_HEADERS_COFF:
        // case MODE_HEADERS_OPTIONAL:
        // case MODE_SECTION:
        // case MODE_DIRECTORIES:
        // case MODE_EXPORTS:
        // case MODE_IMPORTS:
        // case MODE_CERTIFICATES:
        // case MODE_SECURITY:
        // case MODE_LIBRARIES:
        // case COMMAND_STRINGS:
        // case COMMAND_LIST:
        // case COMMAND_SCAN:
        // case COMMAND_EXTRACT:
        // case COMMAND_HASH:
        //     break;
        // case MODE_RESOURCES:
        //     switch (c) {
        //     case 'i': // index
        //     case 's': // statistics
        //     case 'v': // file-version
        //               // extract
        //               // named-extract
        //         break;
        //     }
        //     break;
        // case MODE_SECTIONS:
        //     switch (c) {
        //     case 'i':
        //         // TODO: index
        //         break;
        //     case 'n':
        //         // TODO: name
        //         break;
        //     }
        //     break;
        // }

        // printf("Arg: %i:%c \n", c, (c < 256 && isprint(c) ? c : '?'));
    }

    // printf("\nMode: %i\nContext: %i\n\n", mode, mode_context);
    // exit(1);

    if (access(argv[argc - 1], F_OK) == 0) {
        file_arg = argc - 1;
    }
    if (file_arg == 0) {
        help();
    }

    // printf("%i\n", file);

    pe_ctx_t ctx;
    pe_err_e err = pe_load_file(&ctx, argv[file_arg]);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    if (!pe_is_pe(&ctx)) {
        EXIT_ERROR("not a valid PE file");
    }

    output_open_document();

    switch (mode) {
    case MODE_BASE:
        if (g_settings.file_version) {
            pe_resources_t *resources = pe_resources(&ctx);
            if (resources == NULL || resources->err != LIBPE_E_OK) {
                LIBPE_WARNING("This file has no version");
                return EXIT_SUCCESS;
            }

            pe_resource_node_t *root_node = resources->root_node;
            peres_show_version(&ctx, root_node);
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
            printf("dos\ncoff\noptional\n");
            break;
        }
        // --all
        // TODO: --list, --all
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
        if (g_settings.verbose) {
            print_directories(&ctx);
            break;
        }
        printf("Not Implemented\n");
        break;
    case MODE_EXPORTS:
        print_exports(&ctx);
        break;
    case MODE_IMPORTS:
        print_imports(&ctx);
        break;

    case MODE_RESOURCES: {
        // TODO This has to be redone
        pe_resources_t *resources = pe_resources(&ctx);
        if (resources == NULL || resources->err != LIBPE_E_OK) {
            LIBPE_WARNING("This file has no resources");
            return EXIT_SUCCESS;
        }

        bool printed = false;

        pe_resource_node_t *root_node = resources->root_node;
        if (g_settings.verbose) {
            peres_show_nodes(&ctx, root_node);
            printed = true;
        }

        if (g_settings.list && !g_settings.verbose) {
            peres_show_list(&ctx, root_node);
            printed = true;
        }

        if (g_settings.res_tree) {
            printf("Not Implemented\n");
            printed = true;
        }

        if (g_settings.res_statistics) {
            peres_show_stats(root_node);
            printed = true;
        }

        if (g_settings.file_version) {
            peres_show_version(&ctx, root_node);
            printed = true;
        }

        // If we haven't printed anything yet
        if (!printed) {
            // peres_show_nodes(&ctx, root_node);
            peres_show_list(&ctx, root_node);
            // peres_save_all_resources(&ctx, root_node,
            // options->namedExtract);
            peres_show_stats(root_node);
            peres_show_version(&ctx, root_node);
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

    case MODE_LIBRARIES: {
        IMAGE_DATA_DIRECTORY **directories = pe_directories(&ctx);
        if (directories == NULL) {
            LIBPE_WARNING("directories not found");
        } else {
            print_dependencies(&ctx);
        }

        break;
    }

    case COMMAND_STRINGS:
        print_strings(&ctx, &CONFIG.string);
        break;

    case COMMAND_HASH:
        // case COMMAND_HASH_MD5:
        // case COMMAND_HASH_SHA1:
        // case COMMAND_HASH_SHA256:
        // case COMMAND_HASH_SSDEEP:
        // case COMMAND_HASH_IMPHASH:
        // TODO
        printf("Not Implemented\n");
        break;

    case COMMAND_SCAN: {
        pe_scan(&ctx, g_settings.verbose);
        break;
    }

    default:
        printf("Unknown Argument: %d\n", mode);
        exit(-1);
    }

    output_close_document();

    // free
    err = pe_unload(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    PEV_FINALIZE(&config);

    return EXIT_SUCCESS;
}


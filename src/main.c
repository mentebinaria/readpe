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
#include "pesec.h"
#include "pestr.h"
#include "readpe.h"
#include <bits/getopt_ext.h>
#include <bits/stdint-uintn.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum ARGUMENTS {
    ARG_NONE = 0,

    ARG_HELP = 1,
    ARG_COMPLETE = 2,
    ARG_VERSION = 'V',

    MODE_START = 1000,
    MODE_HEADER = 1000,
    MODE_HEADER_DOS,
    MODE_HEADER_COFF,
    MODE_HEADER_OPTIONAL,
    MODE_DIRECTORY = 1100,
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
    MODE_SECTION = 1200,
    MODE_LIBRARY = 1300, // -- peldd
    MODE_STRINGS = 1400, // -- pestr
    // MODE_STRINGS_ASCII,
    // MODE_STRINGS_UNICODE,
    MODE_END,

    COMMAND_SCAN = 2000, // -- pescan
    COMMAND_EXTRACT,
    COMMAND_HASH = 2100, // -- pehash
    // COMMAND_HASH_MD5,
    // COMMAND_HASH_SHA1,
    // COMMAND_HASH_SHA256,
    // COMMAND_HASH_SSDEEP,
    // COMMAND_HASH_IMPHASH,

    COMMAND_DISASSAMBLE = 100000, // -- pedis
    COMMAND_PACK,                 // -- pepack
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

static struct _conf_t {
    unsigned int list : 1;
    unsigned int all : 1;
    char *format;
    certificate_settings certificate;
    string_settings string;
} conf;

typedef struct {
    const char *const name;
    const void *const sub;
    const int value;
    const int has_arg;
    const void *variable;
    const enum ARG_VARIABLE_TYPE type;
} mode_option;

bool str2bool(const char *const str)
{
    if (str == NULL)
	{
		// TODO Do this better
		EXIT_ERROR("Internal error (str2bool)");
	}
    else if (*str == '0')
        return false;
    else if (*str == '1')
        return true;
    else if (strcmp(str, "false") == 0)
        return false;
    else if (strcmp(str, "true") == 0)
        return true;
    else
        EXIT_ERROR("Bad bool variable");
}

int getopt_mode(int argc, char *const argv[],
                const mode_option **const mode_options, int *restrict select,
                int *restrict index)
{
    if (*index >= argc)
        return -1;
    char *const arg = argv[*index];
    *index += 1;

    int val = 0;

    for (int i = 0; (*mode_options)[i].name != NULL; ++i) {
        mode_option opt = (*mode_options)[i];
		char *eq = strchr(arg, '=');

		if(eq != NULL) {
			*eq = '\0';
		}
        // printf("%s %s\n", arg, opt.name);
        if (strcmp(opt.name, arg) == 0) {
            val = opt.value;

            if (opt.variable != NULL) {
                char *var;
                if (opt.has_arg) {
                    if (eq == NULL) {
                        if (*index < argc) {
                            var = argv[*index];
                            *index += 1;
                        } else {
							EXIT_ERROR("NO NEXT VAL ERROR");
						}
                    } else {
                        var = eq+1;
                    }
                }

                switch (opt.type) {
                case VAR_BOOL:
                    if (opt.has_arg)
                        *(bool *)opt.variable = str2bool(var);
                    else
                        *(bool *)opt.variable = true;
                    break;
                case VAR_UINT16:
                    if (!opt.has_arg)
                        *(uint16_t *)opt.variable = 99;
                    break;
                }
            }

            if (opt.sub != NULL) {
                *mode_options = opt.sub;
            }

            if (val >= MODE_START) {
                *select = val;
            }

            break;
        }
    }

    return val;
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

    printf(
        "\nReport bugs to: https://github.com/mentebinaria/readpe/issues\n");
    exit(EXIT_SUCCESS);
}

void complete(const mode_option *opts)
{
    size_t i = 0;
    const mode_option *c;
    while ((c = &opts[i])) {
        if (c->name == NULL)
            break;
        printf("%s ", c->name);
        ++i;
    }
    printf("\n");
    exit(EXIT_SUCCESS);
}

void usage(void) {}

int main(int argc, char *argv[])
{
    const char *tmp_name = strrchr(argv[0], '/');
    // If no '/' in caller (called from env) we set it to the original caller
    const char *bin_name = tmp_name ? tmp_name + 1 : argv[0];

    // Legacy executables
    if (strstr(bin_name, "peldd") == bin_name)
        exit(peldd(argc, argv));
    if (strstr(bin_name, "pestr") == bin_name)
        exit(pestr(argc, argv));
    if (strstr(bin_name, "pescan") == bin_name)
        exit(pescan(argc, argv));
    if (strstr(bin_name, "pehash") == bin_name)
        exit(pehash(argc, argv));
    if (strstr(bin_name, "pesec") == bin_name)
        exit(pesec(argc, argv));
    if (strstr(bin_name, "peres") == bin_name)
        exit(peres(argc, argv));
    if (strstr(bin_name, "pedis") == bin_name)
        exit(pedis(argc, argv));
    if (strstr(bin_name, "pepack") == bin_name)
        exit(pepack(argc, argv));
    if (strstr(bin_name, "ofs2rva") == bin_name)
        exit(ofs2rva(argc, argv));
    if (strstr(bin_name, "rva2ofs") == bin_name)
        exit(rva2ofs(argc, argv));

    //------------------------------------------------------------------------//

    static const struct option readpe_options[] = {
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

    static const struct option pedis_options[] = {
        {"help",       no_argument,       NULL, 1  },
        {"att",        no_argument,       NULL, 2  },
        {"",           required_argument, NULL, 'n'},
        {"entrypoint", no_argument,       NULL, 'e'},
        {"mode",       required_argument, NULL, 'm'},
        {"offset",     required_argument, NULL, 'o'},
        {"rva",        required_argument, NULL, 'r'},
        {"section",    required_argument, NULL, 's'},
        {"format",     required_argument, NULL, 'f'},
        {"version",    no_argument,       NULL, 'V'},
        {NULL,         0,                 NULL, 0  }
    };

    static const struct option pehash_options[] = {
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

    static const struct option peres_options[] = {
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

    static const struct option pescan_options[] = {
        {"format",  required_argument, NULL, 'f'},
        {"help",    no_argument,       NULL, 1  },
        {"verbose", no_argument,       NULL, 'v'},
        {"version", no_argument,       NULL, 'V'},
        {NULL,      0,                 NULL, 0  }
    };

    static const struct option pesec_options[] = {
        {"format",      required_argument, NULL, 'f'},
        {"certoutform", required_argument, NULL, 'c'},
        {"certout",     required_argument, NULL, 'o'},
        {"help",        no_argument,       NULL, 1  },
        {"version",     no_argument,       NULL, 'V'},
        {NULL,          0,                 NULL, 0  }
    };

    static const struct option pestr_options[] = {
        {"offset",     no_argument,       NULL, 'o'},
        {"section",    no_argument,       NULL, 's'},
        {"min-length", required_argument, NULL, 'n'},
        {"help",       no_argument,       NULL, 1  },
        {"version",    no_argument,       NULL, 'V'},
        {NULL,         0,                 NULL, 0  }
    };

    //------------------------------------------------------------------------//

    static const mode_option default_mode[] = {
        {"--list", NULL, 'l', 0, NULL, 0},
        {"--help", NULL, 1,   0, NULL, 0},
        {NULL,     NULL, 0,   0, NULL, 0}
    };

    static const mode_option header_mode[] = {
        {"dos",      NULL, MODE_HEADER_DOS,      0, NULL, 0},
        {"coff",     NULL, MODE_HEADER_COFF,     0, NULL, 0},
        {"optional", NULL, MODE_HEADER_OPTIONAL, 0, NULL, 0},
        {"--list",   NULL, 'l',                  0, NULL, 0},
        {"--help",   NULL, 1,                    0, NULL, 0},
        {NULL,       NULL, 0,                    0, NULL, 0}
    };

    static const mode_option directory_mode[] = {
        {"--list", NULL, 'l', 0, NULL, 0},
        {"--help", NULL, 1,   0, NULL, 0},
        {NULL,     NULL, 0,   0, NULL, 0}
    };

    static const mode_option resource_mode[] = {
        {"extract",        NULL, COMMAND_EXTRACT, 0, NULL, 0},
        {"--info",         NULL, 'i',             0, NULL, 0},
        {"--statistics",   NULL, 's',             0, NULL, 0},
        {"--name-extract", NULL, 'n',             0, NULL, 0},
        {"--file-version", NULL, 'v',             0, NULL, 0},
        {"--list",         NULL, 'l',             0, NULL, 0},
        {"--help",         NULL, 1,               0, NULL, 0},
        {NULL,             NULL, 0,               0, NULL, 0}
    };

    static const mode_option certificate_mode[] = {
        {"--list",        NULL, 'l', 0,                 NULL, 0},
        {"--certoutform", NULL, 'c', required_argument, NULL, 0},
        {"--certout",     NULL, 'o', required_argument, NULL, 0},
        {"--help",        NULL, 1,   0,                 NULL, 0},
        {NULL,            NULL, 0,   0,                 NULL, 0}
    };

    static const mode_option security_mode[] = {
        {"--list", NULL, 'l', 0, NULL, 0},
        {"--help", NULL, 1,   0, NULL, 0},
        {NULL,     NULL, 0,   0, NULL, 0}
    };

    static const mode_option section_mode[] = {
        {"--list", NULL, 'l', 0, NULL, 0},
        {"--help", NULL, 1,   0, NULL, 0},
        {NULL,     NULL, 0,   0, NULL, 0}
    };

    static const mode_option strings_mode[] = {
        {"--offset",     NULL, 'o', true,  &conf.string.offset,  VAR_BOOL  },
        {"--section",    NULL, 's', false, &conf.string.section, VAR_BOOL  },
        {"--min-length", NULL, 'n', true,  &conf.string.strsize, VAR_UINT16},
        {"--help",       NULL, 1,   false, NULL,                 0         },
        {NULL,           NULL, 0,   0,     NULL,                 0         }
    };

    // static const mode_option hash_mode[] = {
    //     {"md5",    NULL, 0, NULL, COMMAND_HASH_MD5    },
    //     {"sha1",   NULL, 0, NULL, COMMAND_HASH_SHA1   },
    //     {"sha256", NULL, 0, NULL, COMMAND_HASH_SHA256 },
    //     {"ssdeep", NULL, 0, NULL, COMMAND_HASH_SSDEEP },
    //     {"impash", NULL, 0, NULL, COMMAND_HASH_IMPHASH},
    //     {"--list", NULL, 0, NULL, 'l'                 },
    //     {"--help", NULL, 0, NULL, 1                   },
    //     {NULL,     NULL, 0, NULL, 0                   },
    // };

    static const mode_option base_mode[] = {
        {"headers",      header_mode,      MODE_HEADER,       0, NULL, 0},
        {"directories",  directory_mode,   MODE_DIRECTORY,    0, NULL, 0},
        {"exports",      default_mode,     MODE_EXPORTS,      0, NULL, 0},
        {"imports",      default_mode,     MODE_IMPORTS,      0, NULL, 0},
        {"resources",    resource_mode,    MODE_RESOURCES,    0, NULL, 0},
        {"certificates", certificate_mode, MODE_CERTIFICATES, 0, NULL, 0},
        {"security",     security_mode,    MODE_SECURITY,     0, NULL, 0},
        {"sections",     section_mode,     MODE_SECTION,      0, NULL, 0},
        {"libraries",    default_mode,     MODE_LIBRARY,      0, NULL, 0},
        {"strings",      strings_mode,     MODE_STRINGS,      0, NULL, 0},
        {"scan",         NULL,             COMMAND_SCAN,      0, NULL, 0},
        {"hash",         NULL,             COMMAND_HASH,      0, NULL, 0},
        {"--format",     NULL,             'f',               0, NULL, 0},
        {"--version",    NULL,             'V',               0, NULL, 0},
        {"--help",       NULL,             1,                 0, NULL, 0},
        {NULL,           NULL,             0,                 0, NULL, 0}
    };

    //------------------------------------------------------------------------//
    /*
    static const struct option common_options[] = {
        {"format",  required_argument, NULL, 'f'},
        {"version", no_argument,       NULL, 'V'},
        {"help",    no_argument,       NULL, 1  },
        {NULL,      0,                 NULL, 0  }
    };

    static const struct option legacy_options[] = {
        {"all",          no_argument,       NULL, 'A'},
        {"all-headers",  no_argument,       NULL, 'H'},
        {"all-sections", no_argument,       NULL, 'S'},
        {"header",       required_argument, NULL, 'h'},
        {"imports",      no_argument,       NULL, 'i'},
        {"exports",      no_argument,       NULL, 'e'},
        {"dirs",         no_argument,       NULL, 'd'},
        {NULL,           0,                 NULL, 0  }
    };
    */

    if (argc < 2)
        help();

    const mode_option *mode = base_mode;
    int c, f_arg = 0, select = 0, index = 1;

    if (access(argv[index], F_OK) == 0) {
        f_arg = index;
        ++index;
    }

    while ((c = getopt_mode(argc, argv, &mode, &select, &index))) {
        if (c < 0)
            break;
        // printf("%i\n", c);

        switch (c) {
        case 1:
            help();
            break;
        case 2:
            complete(mode);
            break;
        case 'V':
            version();
            break;
        case 'a':
            conf.all = true;
            break;
        case 'f':
            conf.format = "text";
            break;
        case 'l':
            conf.list = true;
            break;
        default:
            break;
            // exit(EXIT_FAILURE);
        }
    }

    if ((f_arg == 0) && (access(argv[argc - 1], F_OK) == 0)) {
        f_arg = argc - 1;
    }
    if (f_arg == 0)
        help();

    // printf("%i\n", file);

    pe_ctx_t ctx;
    pe_err_e err = pe_load_file(&ctx, argv[f_arg]);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    if (!pe_is_pe(&ctx))
        EXIT_ERROR("not a valid PE file");

    pev_config_t config;
    PEV_INITIALIZE(&config);

    output_open_document();

    switch (select) {
    case ARG_NONE:
        print_dos_header(&ctx);
        print_coff_header(&ctx);
        print_optional_header(&ctx);
        print_directories(&ctx);
        print_imports(&ctx);
        print_exports(&ctx);
        print_sections(&ctx);
        break;
    case MODE_HEADER:
        // TODO: --list, --all
        print_dos_header(&ctx);
        print_coff_header(&ctx);
        print_optional_header(&ctx);
        break;
    case MODE_HEADER_DOS:
        print_dos_header(&ctx);
        break;
    case MODE_HEADER_COFF:
        print_coff_header(&ctx);
        break;
    case MODE_HEADER_OPTIONAL:
        print_optional_header(&ctx);
        break;
    case MODE_DIRECTORY:
        print_directories(&ctx);
        break;
    case MODE_EXPORTS:
        print_exports(&ctx);
        break;
    case MODE_IMPORTS:
        print_imports(&ctx);
        break;

    case MODE_RESOURCES: {
        // TODO
        pe_resources_t *resources = pe_resources(&ctx);
        if (resources == NULL || resources->err != LIBPE_E_OK) {
            LIBPE_WARNING("This file has no resources");
            return EXIT_SUCCESS;
        }

        pe_resource_node_t *root_node = resources->root_node;

        peres_show_nodes(&ctx, root_node);
        peres_show_stats(root_node);
        peres_show_list(&ctx, root_node);
        // peres_save_all_resources(&ctx, root_node,
        // options->namedExtract);
        peres_show_version(&ctx, root_node);
        break;
    }

        // case MODE_EXCEPTIONS:

    case MODE_SECURITY:
        print_securities(&ctx);
        // fall through
    case MODE_CERTIFICATES:
        parse_certificates(&conf.certificate, &ctx);
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

    case MODE_SECTION:
        print_sections(&ctx);
        break;

    case MODE_LIBRARY: {
        IMAGE_DATA_DIRECTORY **directories = pe_directories(&ctx);
        if (directories == NULL) {
            LIBPE_WARNING("directories not found");
        } else {
            print_dependencies(&ctx);
        }

        break;
    }

    case MODE_STRINGS:
        print_strings(&ctx, &conf.string);
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
        // TODO
        printf("Not Implemented\n");
        break;
    }

    case COMMAND_DISASSAMBLE:
    case COMMAND_PACK:
        // case COMMAND_ADDRESSING_RELATIVE:
        // case COMMAND_ADDRESSING_OFFSET:
        printf("Not Implemented\n");
        break;
        // default:
        //     // printf("Unknown Argument: %d\n", select);
        //     break;
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


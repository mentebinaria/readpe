/*
	pedis - PE section disassembler

	Copyright (C) 2010 - 2012 Fernando Mercês

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

#include "pedis.h"

extern struct options config;
static int ind;

void usage()
{
	printf("Usage: %s OPTIONS FILE\n\n", PROGRAM);
	
	printf(
	"--att                                  set AT&T syntax (Intel default)\n"
	"-f, --function <address>               disassembly function\n"
	"-s, --section <section name>           disassembly specific section\n"
	"-f, --format <text|csv|xml|html>       change output format (default text)\n"
	"-v, --version                          show version and exit\n"
	"--help                                 show this help and exit\n"
	);

}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "F:s:f:v";

	static const struct option long_options[] = {
		{"help",             no_argument,       NULL,  1 },
		{"att",              no_argument,       NULL,  2 },
		{"function",         required_argument, NULL, 'F'},
		{"section",          required_argument, NULL, 's'},
		{"format",           required_argument, NULL, 'f'},
		{"version",          no_argument,       NULL, 'v'},
		{ NULL,              0,                 NULL,  0 }
	};

	// setting all fields to false
	memset(&config, false, sizeof(config));
	config.syntax = SYN_INTEL;

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
				
			case 2:
				config.syntax = SYN_ATT;

			case 'F':
				config.function = strtol(optarg, NULL, 0);
				
			case 's':
				config.section = optarg; break;

			case 'v':
				printf("%s %s\n", PROGRAM, VERSION);
				exit(EXIT_SUCCESS);

			case 'f':
				parse_format(optarg); break;

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

void print_section_disasm(PE_FILE *pe, IMAGE_SECTION_HEADER *section)
{
	// libuds86
	ud_t ud_obj;
	BYTE *buff;
	char *ofstr;

	// allocate a buffer with same section size
	buff = (BYTE *) xmalloc(section->SizeOfRawData);
	if (!buff)
		exit(-1);

	ud_init(&ud_obj);

	// set handle to section start
	fseek(pe->handle, section->PointerToRawData, SEEK_SET);

	if (!fread(buff, section->SizeOfRawData, 1, pe->handle))
		EXIT_ERROR("error seeking through file");

	// pass entire section to libudis86
	ud_set_input_buffer(&ud_obj, buff, section->SizeOfRawData);

	if (!pe->optional_ptr->_32 && !pe->optional_ptr->_64)
		pe_get_optional(pe);

	if (pe->architecture == PE32)
	{
		ud_set_mode(&ud_obj, 32);
		ofstr = "%08"PRIx64;
	}
	else if (pe->architecture == PE64)
	{
		ud_set_mode(&ud_obj, 64);
		ofstr = "%016"PRIx64;
	}
	else
		EXIT_ERROR("unable to detect PE architecture");

	// intel syntax
	ud_set_syntax(&ud_obj, config.syntax ? UD_SYN_ATT : UD_SYN_INTEL);

	while (ud_disassemble(&ud_obj))
	{
		char ofs[MAX_MSG], s[MAX_MSG];

		snprintf(ofs, MAX_MSG, ofstr, pe->imagebase + section->VirtualAddress + ud_insn_off(&ud_obj));
		snprintf(s, MAX_MSG, "%s", ud_insn_asm(&ud_obj));
		output(ofs, s);
	}

	free(buff);
}

void print_function_disasm(PE_FILE *pe, QWORD function_addr)
{
	ud_t ud_obj;

	if (!pe->architecture)
	{
		IMAGE_COFF_HEADER coff;
		pe_get_coff(pe, &coff);
	}

	ud_set_mode(&ud_obj, pe->architecture == PE64 ? 64 : 32);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	fseek(pe->handle, rva2ofs(function_addr - pe->imagebase, pe), SEEK_SET);
	ud_set_input_file(&ud_obj, pe->handle);

	if (!pe->imagebase)
		pe_get_optional(pe);

	ud_input_skip(&ud_obj, rva2ofs(function_addr - pe->imagebase, pe));

	while (ud_disassemble(&ud_obj))
	{
		char ofs[MAX_MSG], s[MAX_MSG];
		uint8_t* opcodes = ud_insn_ptr(&ud_obj); 

		snprintf(ofs, MAX_MSG, "%#lx", function_addr + ud_insn_off(&ud_obj));
		snprintf(s, MAX_MSG, "%s", ud_insn_asm(&ud_obj));
		output(ofs, s);

		// leave or ret opcodes
		for (unsigned i=0; i<ud_insn_len(&ud_obj); i++)
		{
			if (opcodes[i] == 0xc9 || opcodes[i] == 0xc3)
				return;
		}
	}
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	if (config.function)
		print_function_disasm(&pe, config.function); // not working yet!
	else if (config.section)
	{
		IMAGE_SECTION_HEADER *section;

		// search for section name
			
		section = pe_get_section(&pe, config.section);

		if (section) // section found
			print_section_disasm(&pe, section);
		else { EXIT_ERROR("invalid section name"); }
	}

	// libera a memoria
	pe_deinit(&pe);
	return 0;
}

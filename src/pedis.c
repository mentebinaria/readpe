/*
	pev - the PE file analyzer toolkit
	
	pedis.c - PE disassembler

	Copyright (C) 2012 pev authors

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
	printf("Usage: %s OPTIONS FILE\n"
	"Disassemble PE sections and functions (by default, until found a RET or LEAVE instruction)\n"
	"\nExample: %s -r 0x4c4df putty.exe\n"
	"\nOptions:\n"
	" --att                                  set AT&T syntax\n"
	" -e, --entrypoint                       disassemble entrypoint\n"
	" -f, --format <text|csv|xml|html>       change output format (default text)\n"
	" -m, --mode <16|32|64>                  disassembly mode (default: auto)\n"
	" -i, <number>                           number of instructions to be disassembled\n"
	" -n, <number>                           number of bytes to be disassembled\n"
	" -o, --offset <offset>                  disassemble at specified file offset\n"
	" -r, --rva <rva>                        disassemble at specified RVA\n"
	" -s, --section <section name>           disassemble entire section given\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "em:i:n:o:r:s:f:v";

	static const struct option long_options[] = {
		{"help",             no_argument,       NULL,  1 },
		{"att",              no_argument,       NULL,  2 },
		{"",                 required_argument, NULL, 'n'},
		{"entrypoint",       no_argument,       NULL, 'e'},
		{"mode",             required_argument, NULL, 'm'},
		{"offset",           required_argument, NULL, 'o'},
		{"rva",              required_argument, NULL, 'r'},
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
				config.syntax = SYN_ATT; break;
				
			case 'e':
				config.entrypoint = true; break;
				
			case 'm':
				config.mode = strtol(optarg, NULL, 10); break;

			case 'i':
				config.ninstructions = strtol(optarg, NULL, 0); break;

			case 'n':
				config.nbytes = strtol(optarg, NULL, 0); break;

			case 'o':
				config.offset = strtol(optarg, NULL, 0);
				config.offset_is_rva = false; break;
				
			case 'r':
				config.offset = strtol(optarg, NULL, 0);
				config.offset_is_rva = true; break;

			case 's':
				config.section = optarg; break;

			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			case 'f':
				parse_format(optarg); break;

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

char *insert_spaces(char *s) 
{
	size_t size;
	char *new; 

	size = strlen(s);

	if (!size)
		return NULL;

	size = size + (size/2);

	new = (char *) xmalloc(size+1);
	memset(new, 0, size+1);

	for (unsigned int i=0, j=0, pos=0; i < size; i++)
	{   
		if (pos==2)
		{   
			new[i] = ' ';
			pos=0;
		}   
		else
		{   
			new[i] = s[j++];
			pos++;
		}   
	}   
	return new;
}

bool is_ret_instruction(unsigned char opcode)
{
	switch (opcode)
	{
		case 0xc9: // leave
		//case 0xc2: // ret
		case 0xc3: // ret
		case 0xca: // retf
		//case 0xcb: // retf
			return true;
		
		default:
			return false;
	}
}

void disassemble_offset(PE_FILE *pe, ud_t *ud_obj, QWORD offset)
{
	QWORD c = 0; // counter for disassembled instructions
	QWORD b = 0; // counter for disassembled bytes
	
	if (!pe || !offset)
		return;

	while (ud_disassemble(ud_obj))
	{
		char ofs[MAX_MSG], value[MAX_MSG], *bytes;
		unsigned char *opcode = ud_insn_ptr(ud_obj);
		unsigned int mnic, op_t;

		c++; // increment instruction counter
		b += ud_insn_len(ud_obj);

		if (config.nbytes && b >= config.nbytes)
			return;

		mnic = ud_obj->mnemonic;
		op_t = ud_obj->operand ? ud_obj->operand[0].type : 0;
		
		snprintf(ofs, MAX_MSG, "%"PRIx64, (config.offset_is_rva ? pe->imagebase : 0) + offset + ud_insn_off(ud_obj));
		bytes = insert_spaces(ud_insn_hex(ud_obj));

		if (!bytes)
			return;

		// correct near operand addresses for calls and jumps
		if (op_t && (op_t != UD_OP_MEM) && (mnic == UD_Icall || (mnic >= UD_Ijo && mnic <= UD_Ijmp)))
		{
			char *ins = strtok(ud_insn_asm(ud_obj), "0x");

			snprintf(value, MAX_MSG, "%s%*c%s%#"PRIx64, bytes, SPACES - (int) strlen(bytes), ' ', ins ? ins : "",
			pe->imagebase + offset + ud_insn_off(ud_obj) + ud_obj->operand[0].lval.sdword + ud_insn_len(ud_obj));
		}
		else
			snprintf(value, MAX_MSG, "%s%*c%s", bytes, SPACES - (int) strlen(bytes), ' ', ud_insn_asm(ud_obj));

		free(bytes);
		output(ofs, value);

		// for sections, we stop at end of section
		if (config.section && c >= config.ninstructions)
			break;
		else if (c >= config.ninstructions && config.ninstructions)
			break;
		else if (config.entrypoint)
		{
		// search for LEAVE or RET insrtuctions
		for (unsigned int i=0; i < ud_insn_len(ud_obj); i++)
			if (is_ret_instruction(opcode[i]))
				return;
		}
	}
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	ud_t ud_obj;              // libudis86 object
	QWORD offset = 0;         // offset to start disassembly

	if (argc < 2)
	{
		usage();
		exit(1);
	}

	parse_options(argc, argv);
	
	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp);
	ud_init(&ud_obj);

	if (!is_pe(&pe))
		EXIT_ERROR("not a valid PE file");
	
	// get entrypoint and architecture
	if (!pe_get_optional(&pe))
		EXIT_ERROR("unable to retrieve Optional header");
	
	// set disassembly mode according with PE architecture
	ud_set_mode(&ud_obj, config.mode ? config.mode : (pe.architecture == PE64 ? 64 : 32));

	rewind(pe.handle);
	
	if (config.entrypoint)
		offset = rva2ofs(&pe, pe.entrypoint);
	else if (config.offset)
		offset = config.offset_is_rva ? rva2ofs(&pe, config.offset) : config.offset;
	else if (config.section)
	{
		IMAGE_SECTION_HEADER *section;

		section = pe_get_section(&pe, config.section);

		if (section) // section found
		{
			offset = section->PointerToRawData;
			if (!config.ninstructions)
				config.ninstructions = section->SizeOfRawData;
		}
		else
			EXIT_ERROR("invalid section name");
	}
	else
	{
		usage();
		exit(1);
	}
	
	if (!offset)
		EXIT_ERROR("unable to reach file offset");

	ud_set_syntax(&ud_obj, config.syntax ? UD_SYN_ATT : UD_SYN_INTEL);
	ud_set_input_file(&ud_obj, pe.handle);
	ud_input_skip(&ud_obj, offset);
	disassemble_offset(&pe, &ud_obj, offset);

	// free
	pe_deinit(&pe);
	return 0;
}

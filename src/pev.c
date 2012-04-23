/*
	pev - the PE file analyzer

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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <udis86.h>

#include "include/libpe.h"
#include "include/output.h"
#include "include/parser.h"

#define MAX_MSG 50

extern struct options config;

char *dec2bin(unsigned int dec, char *bin, int bits)
{
	int i;
	for(i=0; i<bits; i++)
		bin[bits - i - 1] = (dec & (0x1 << i)) ? '1' : '0';

	bin[bits] = '\0';

	return bin;
}

void print_disassembler(PE_FILE *pe,IMAGE_SECTION_HEADER *section){
    ud_t ud_obj;
    WORD *buff;


    //inicializa um buffer com o tamanho da section
    buff = (WORD *) malloc(section->SizeOfRawData);

    //inicializa objeto do disassembly
    ud_init(&ud_obj);

    //seta o handle para o início da section
    fseek(pe->handle, section->PointerToRawData, SEEK_SET);

    if (!fread(buff, section->SizeOfRawData, 1, pe->handle))
    	EXIT_WITH_ERROR("Erro ao executar fread --> função print_disassembler!");

    //função utilizada para realizar o disassembler e armazenas em ud_obj
    ud_set_input_buffer(&ud_obj, buff, section->SizeOfRawData);

	if (!pe->optional_ptr->_32 && !pe->optional_ptr->_64)
		pe_get_optional(pe);

	//seta o arquivo para 32 ou 64 bits
	if (!pe->optional_ptr->_32){
		ud_set_mode(&ud_obj, 32);
	}
	else if (!pe->optional_ptr->_64)
	{
		ud_set_mode(&ud_obj, 32);
	}

	//seleciona a saída no padrão Assembly Intel
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);


	while (ud_disassemble(&ud_obj)) {
		printf("%016x\t%s\n",ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj));
	}

	//libera o buffer
    free(buff);
}

void print_sections(PE_FILE *pe)
{
	char s[MAX_MSG];
	int i;
	unsigned int j;

	char *flags[] = {
   "contains executable code",
   "contains initialized data",
   "contains uninitialized data",
   "contains data referenced through the GP",
   "contains extended relocations",
   "can be discarded as needed",
   "cannot be cached",
   "is not pageable",
   "can be shared in memory",
   "is executable",
   "is readable",
   "is writable" };

   // valid flags only for executables referenced in pecoffv8
   unsigned int valid_flags[] =
   { 0x20, 0x40, 0x80, 0x8000, 0x1000000, 0x2000000, 0x4000000,
     0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000 };

	output("Sections", NULL);

	for (i=0; i < pe->num_sections; i++)
	{
		snprintf(s, MAX_MSG, "%s", pe->sections_ptr[i]->Name);
		output("Name", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->VirtualAddress);
		output("Virtual Address", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->Misc.PhysicalAddress);
		output("Physical Address", s);

		snprintf(s, MAX_MSG, "%#x (%d bytes)", pe->sections_ptr[i]->SizeOfRawData,
		pe->sections_ptr[i]->SizeOfRawData);
		output("Size", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->PointerToRawData);
		output("Pointer To Data", s);

		snprintf(s, MAX_MSG, "%d", pe->sections_ptr[i]->NumberOfRelocations);
		output("Relocations", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->Characteristics);
		output("Characteristics", s);

		for (j=0; j < sizeof(valid_flags) / sizeof(unsigned int); j++)
		{
			if (pe->sections_ptr[i]->Characteristics & valid_flags[j])
			{
					snprintf(s, MAX_MSG, "%s", flags[j]);
					output(NULL, s);
			}
		}
	}
}

void print_directories(PE_FILE *pe)
{
	char s[MAX_MSG];
	int i;

	static const char *directory_names[] =
	{
		"Export Table", // 0
		"Import Table",
		"Resource Table",
		"Exception Table",
		"Certificate Table",
		"Base Relocation Table",
		"Debug",
		"Architecture",
		"Global Ptr",
		"Thread Local Storage (TLS) Table", // 9
		"Load Config Table",
		"Bound Import",
		"Import Address Table (IAT)",
		"Delay Import Descriptor",
		"CLR Runtime Header", "" // 15
	};


	output("Data directories", NULL);

	if (! pe->directories_ptr)
		return;

	for (i=0; i < pe->num_directories && i < 16; i++)
	{
		if (pe->directories_ptr[i]->Size)
		{
			snprintf(s, MAX_MSG, "%#x (%d bytes)",
					pe->directories_ptr[i]->VirtualAddress,
					pe->directories_ptr[i]->Size);
			output((char *) directory_names[i], s);
		}
	}
}

void print_optional_header(PE_FILE *pe)
{
	char s[MAX_MSG];
	int subsystem;

	static const char *subs_desc[] = {
	"Unknown subsystem",
	"System native",
	"Windows GUI",
	"Windows CLI",
	"Posix CLI",
	"Windows CE GUI",
	"EFI application",
	"EFI driver with boot",
	"EFI run-time driver",
	"EFI ROM",
	"XBOX"};

	output("Optional/Image header", NULL);

	if (pe->optional_ptr->_32)
	{
		snprintf(s, MAX_MSG, "%#x (%s)", pe->optional_ptr->_32->Magic, "PE32");
		output("Magic number", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorLinkerVersion);
		output("Linker major version", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorLinkerVersion);
		output("Linker minor version", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfCode);
		output("Size of .text secion", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfInitializedData);
		output("Size of .data secion", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfUninitializedData);
		output("Size of .bss secion", s);

		IMAGE_SECTION_HEADER *sec_fake_ep = pe_check_fake_entrypoint(pe);

		if (sec_fake_ep)
		{
			snprintf(s, MAX_MSG, "%#x (%s) --> outside of code section",
			         pe->optional_ptr->_32->AddressOfEntryPoint,
						sec_fake_ep->Name);
		}
		else
			snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->AddressOfEntryPoint);

		output("Entrypoint", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->BaseOfCode);
		output("Address of .text section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->BaseOfData);
		output("Address of .data section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->ImageBase);
		output("ImageBase", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SectionAlignment);
		output("Alignment of sections", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->FileAlignment);
		output("Alignment factor", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorOperatingSystemVersion);
		output("Major version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorOperatingSystemVersion);
		output("Minor version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorImageVersion);
		output("Major version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorImageVersion);
		output("Minor version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorSubsystemVersion);
		output("Major version of subsystem", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorSubsystemVersion);
		output("Minor version of subsystem", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfImage);
		output("Size of image", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfHeaders);
		output("Size of headers", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->CheckSum);
		output("Checksum", s);

		subsystem = pe->optional_ptr->_32->Subsystem;
		snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem <= 10 ? subs_desc[subsystem] : "Unknown");
		output("Subsystem required", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->DllCharacteristics);
		output("DLL characteristics", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfStackReserve);
		output("Size of stack to reserve", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfStackCommit);
		output("Size of stack to commit", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	}
	else if (pe->optional_ptr->_64)
	{
		snprintf(s, MAX_MSG, "%#x (%s)", pe->optional_ptr->_64->Magic, "PE32+");
		output("Magic number", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorLinkerVersion);
		output("Linker major version", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorLinkerVersion);
		output("Linker minor version", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfCode);
		output("Size of .text secion", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfInitializedData);
		output("Size of .data secion", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfUninitializedData);
		output("Size of .bss secion", s);

		IMAGE_SECTION_HEADER *sec_fake_ep = pe_check_fake_entrypoint(pe);

		if (sec_fake_ep)
		{
			snprintf(s, MAX_MSG, "%#x --> entrypoint outside of code section %s",
			         pe->optional_ptr->_64->AddressOfEntryPoint,
						sec_fake_ep->Name);
		}
		else
			snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->AddressOfEntryPoint);

		output("Entrypoint", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->BaseOfCode);
		output("Address of .text section", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->ImageBase);
		output("ImageBase", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SectionAlignment);
		output("Alignment of sections", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->FileAlignment);
		output("Alignment factor", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorOperatingSystemVersion);
		output("Major version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorOperatingSystemVersion);
		output("Minor version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorImageVersion);
		output("Major version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorImageVersion);
		output("Minor version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorSubsystemVersion);
		output("Major version of subsystem", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorSubsystemVersion);
		output("Minor version of subsystem", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfImage);
		output("Size of image", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfHeaders);
		output("Size of headers", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->CheckSum);
		output("Checksum", s);

		subsystem = pe->optional_ptr->_64->Subsystem;
		snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem <= 10 ? subs_desc[subsystem] : "Unknown");
		output("Subsystem required", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->DllCharacteristics);
		output("DLL characteristics", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfStackReserve);
		output("Size of stack to reserve", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfStackCommit);
		output("Size of stack to commit", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	}
}

void print_coff_header(IMAGE_COFF_HEADER *header)
{
	char s[MAX_MSG];
	char time[40];
	register unsigned int i, j;
	char *machine = "Unknown machine type";

	static const char *flags[] =
	{
		"base relocations stripped",
		"executable image",
		"line numbers removed (deprecated)",
		"local symbols removed (deprecated)",
		"aggressively trim (deprecated for Windows 2000 and later)",
		"can handle more than 2 GB addresses", "",
		"little-endian (deprecated)",
		"32-bit machine",
		"debugging information removed",
		"copy to swap if it's on removable media",
		"copy to swap if it's on network media",
		"system file",
		"DLL image",
		"uniprocessor machine",
		"big-endian (deprecated)"
	};

	static const MACHINE_ENTRY arch[] =
	{
		{"Any machine type", 0x0},
		{"Matsushita AM33", 0x1d3},
		{"x86-64 (64-bits)", 0x8664},
		{"ARM little endian", 0x1c0},
		{"ARMv7 (or higher) Thumb mode only", 0x1c4},
		{"EFI byte code", 0xebc},
		{"Intel 386 and compatible (32-bits)", 0x14c},
		{"Intel Itanium", 0x200},
		{"Mitsubishi M32R little endian", 0x9041},
		{"MIPS16", 0x266},
		{"MIPS with FPU", 0x366},
		{"MIPS16 with FPU", 0x466},
		{"Power PC little endian", 0x1f0},
		{"Power PC with floating point support", 0x1f1},
		{"MIPS little endian", 0x166},
		{"Hitachi SH3", 0x1a2},
		{"Hitachi SH3 DSP", 0x1a3},
		{"Hitachi SH4", 0x1a6},
		{"Hitachi SH5",  0x1a8},
		{"ARM or Thumb (\"interworking\")", 0x1c2},
		{"MIPS little-endian WCE v2", 0x169}
	};

	output("COFF/File header", NULL);

	for(i=0; i<(sizeof(arch)/sizeof(MACHINE_ENTRY)); i++)
	{
		if(header->Machine == arch[i].code)
			machine = (char*)arch[i].name;
	}

	snprintf(s, MAX_MSG, "%#x %s", header->Machine, machine);
	output("Machine", s);

	snprintf(s, MAX_MSG, "%d", header->NumberOfSections);
	output("Number of sections", s);

	strftime(time, 40, "%a - %d %b %Y %H:%M:%S UTC", gmtime((time_t *) & header->TimeDateStamp));
	snprintf(s, MAX_MSG, "%d (%s)", header->TimeDateStamp, time);
	output("Date/time stamp", s);

	snprintf(s, MAX_MSG, "%#x", header->PointerToSymbolTable);
	output("Symbol Table offset", s);

	snprintf(s, MAX_MSG, "%d", header->NumberOfSymbols);
	output("Number of symbols", s);

	snprintf(s, MAX_MSG, "%#x", header->SizeOfOptionalHeader);
	output("Size of optional header", s);

	snprintf(s, MAX_MSG, "%#x", header->Characteristics);
	output("Characteristics", s);

	for (i=1, j=0; i<0x8000; i<<=1, j++)
	{
		if (header->Characteristics & i)
			output(NULL, (char*) flags[j]);
	}
}

void print_dos_header(IMAGE_DOS_HEADER *header)
{
	char s[MAX_MSG];

	output("DOS Header", NULL);

	snprintf(s, MAX_MSG, "%#x (MZ)", header->e_magic);
	output("Magic number", s);

	snprintf(s, MAX_MSG, "%d", header->e_cblp);
	output("Bytes in last page", s);

	snprintf(s, MAX_MSG, "%d", header->e_cp);
	output("Pages in file", s);

	snprintf(s, MAX_MSG, "%d", header->e_crlc);
	output("Relocations", s);

	snprintf(s, MAX_MSG, "%d", header->e_cparhdr);
	output("Size of header in paragraphs", s);

	snprintf(s, MAX_MSG, "%d", header->e_minalloc);
	output("Minimum extra paragraphs", s);

	snprintf(s, MAX_MSG, "%d", header->e_maxalloc);
	output("Maximum extra paragraphs", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ss);
	output("Initial (relative) SS value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_sp);
	output("Initial SP value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ip);
	output("Initial IP value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_cs);
	output("Initial (relative) CS value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_lfarlc);
	output("Address of relocation table", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ovno);
	output("Overlay number", s);

	snprintf(s, MAX_MSG, "%#x", header->e_oemid);
	output("OEM identifier", s);

	snprintf(s, MAX_MSG, "%#x", header->e_oeminfo);
	output("OEM information", s);

	snprintf(s, MAX_MSG, "%#x", header->e_lfanew);
	output("PE header offset", s);
}

void print_resources(PE_FILE *pe)
{
	char s[MAX_MSG];
	int i;
	unsigned int j;
	static const RESOURCE_ENTRY r[] = 
		{   
			{"RT_CURSOR", 1}, 
			{"RT_BITMAP", 2}, 
			{"RT_ICON", 3}, 
			{"RT_MENU", 4}, 
			{"RT_DIALOG", 5}, 
			{"RT_STRING", 6}, 
			{"RT_FONTDIR", 7}, 
			{"RT_FONT", 8}, 
			{"RT_ACCELERATOR", 9}, 
			{"RT_RCDATA", 10},
			{"RT_MESSAGETABLE", 11},
			{"RT_GROUP_CURSOR", 12},
			{"RT_GROUP_ICON", 14},
			{"RT_VERSION", 16},
			{"RT_DLGINCLUDE", 17},
			{"RT_PLUGPLAY", 19},
			{"RT_VXD", 20},
			{"RT_ANICURSOR", 21},
			{"RT_ANIICON", 22},
			{"RT_HTML", 23},
			{"RT_MANIFEST", 24},
			{"RT_DLGINIT", 240},
			{"RT_TOOLBAR", 241}
		};
	
		output("Resources", NULL);
		for (i=0; i<pe->num_rsrc_entries;i++)
		{
			for (j=0; j<sizeof(r) / sizeof(r[0]); j++)
			{
				if (pe->rsrc_entries_ptr[i]->u1.Name == r[j].code)
				{
					snprintf(s, MAX_MSG, "%s", r[j].name);
					output("Type", s);
					snprintf(s, MAX_MSG, "%#x\n", pe->rsrc_entries_ptr[i]->u2.s2.OffsetToDirectory);
					output("OffsetToDirectory", s);
					break;
				}
			}
		}
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;

	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_WITH_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_WITH_ERROR("not a valid PE file");

	// dos header
	if (config.dos || config.all_headers || config.all)
	{
		IMAGE_DOS_HEADER dos;

		if (pe_get_dos(&pe, &dos))
			print_dos_header(&dos);
		else { EXIT_WITH_ERROR("unable to read DOS header"); }
	}

	// coff/file header
	if (config.coff || config.all_headers || config.all)
	{
		IMAGE_COFF_HEADER coff;

		if (pe_get_coff(&pe, &coff))
			print_coff_header(&coff);
		else { EXIT_WITH_ERROR("unable to read COFF file header"); }
	}

	// optional header
	if (config.opt || config.all_headers || config.all)
	{
		if (pe_get_optional(&pe))
			print_optional_header(&pe);
		else { EXIT_WITH_ERROR("unable to read Optional (Image) file header"); }
	}

	// directories
	if (config.dirs || config.all)
	{
		if (pe_get_directories(&pe))
			print_directories(&pe);
		else { EXIT_WITH_ERROR("unable to read the Directories entry from Optional header"); }
	}

	// sections
	if (config.all_sections || config.all)
	{
		if (pe_get_sections(&pe))
			print_sections(&pe);
		else { EXIT_WITH_ERROR("unable to read Section header"); }
	}

	// imports
	/*
	if (config.imports || config.all)
	{
		if ((pe.num_directories || pe_get_directories(&pe)) && (pe.num_sections || pe_get_sections(&pe)))
			//print_imports(&pe);
			printf("imports will be here soon!\n");
		else { EXIT_WITH_ERROR("unable to read Imports"); }
	}
	*/

	// resources
	if (config.resources || config.all)
	{
		if (pe_get_resource_entries(&pe))
			print_resources(&pe);
		else if (config.resources)
		{
			EXIT_WITH_ERROR("unable to read resources");
		}
	}

	//disassembler
	if (config.disasm_section != NULL){
		IMAGE_SECTION_HEADER *section;

		//setando a seção que o usuário desaja realizar o disassembler
		section = pe_get_section(&pe, config.disasm_section);


		if (section != NULL)
		{
			//encontrou a seção que o usuário deseja realizar o disassembler
			//e irá chamar a função para realizar o disassembler
			print_disassembler(&pe,section);

		}else
		{
			//não encontrou a seção que o usuário deseja realizar o disassembler
			//logo é enviado uma mensagem de erro na tela.
			EXIT_WITH_ERROR("Section inexistente!");
		}

	}

	// libera a memoria
	pe_deinit(&pe);
	return 0;
}

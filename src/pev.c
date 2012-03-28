#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

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

void print_sections(PE_FILE *pe)
{
	char s[MAX_MSG];
	int i;
	
	char *v[] = {
   "contains executable code",
   "contains initialized data",
   "contains uninitialized data",
   "contains comments/info",
   "contains data referenced through the GP",
   "contains extended relocations",
   "can be discarded as needed",
   "cannot be cached",
   "is not pageable",
   "can be shared in memory",
   "is executable",
   "is readable",
   "is writable" };
	
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
		
		if (pe->sections_ptr[i]->Characteristics & 0x20)
		{
				snprintf(s, MAX_MSG, "%s", v[0]);
				output(NULL, s);
		}

		if (pe->sections_ptr[i]->Characteristics & 0x40)
		{
				snprintf(s, MAX_MSG, "%s,", v[1]);
				output(NULL, s);
		}
		
		if (pe->sections_ptr[i]->Characteristics & 0x80)
		{
				snprintf(s, MAX_MSG, "%s,", v[2]);
				output(NULL, s);
		}
						
		if (pe->sections_ptr[i]->Characteristics & 0x200)
		{
				snprintf(s, MAX_MSG, "%s,", v[3]);
				output(NULL, s);
		}
						
		if (pe->sections_ptr[i]->Characteristics & 0x8000)
		{
				snprintf(s, MAX_MSG, "%s,", v[4]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x1000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[5]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x2000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[6]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x4000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[7]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x8000000)
		{
				snprintf(s, MAX_MSG, "%s", v[8]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x10000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[9]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x20000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[10]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x40000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[11]);
				output(NULL, s);
		}
				
		if (pe->sections_ptr[i]->Characteristics & 0x80000000)
		{
				snprintf(s, MAX_MSG, "%s,", v[12]);
				output(NULL, s);
		}
	}
}

void print_directories(PE_FILE *pe)
{
	char s[MAX_MSG];
	int i;
	
	output("Data directories", NULL);
	
	if (! pe->directories_ptr)
		return;
	
	for (i=0; i < pe->num_directories; i++)
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
				
		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->AddressOfEntryPoint);
		output("Entrypoint", s);
				
		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->BaseOfCode);
		output("Address of .text section", s);
				
		snprintf(s, MAX_MSG, "%#lx", pe->optional_ptr->_64->ImageBase);
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
		
		snprintf(s, MAX_MSG, "%#lx", pe->optional_ptr->_64->SizeOfStackReserve);
		output("Size of stack to reserve", s);
		
		snprintf(s, MAX_MSG, "%#lx", pe->optional_ptr->_64->SizeOfStackCommit);
		output("Size of stack to commit", s);
		
		snprintf(s, MAX_MSG, "%#lx", pe->optional_ptr->_64->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);
		
		snprintf(s, MAX_MSG, "%#lx", pe->optional_ptr->_64->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	}
}

void print_coff_header(IMAGE_COFF_HEADER *header)
{
	char s[MAX_MSG];
	char time[40];
	register int i, j;
	
	static const char *flags[] = {
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
	
	output("COFF/File header", NULL);
	
	snprintf(s, MAX_MSG, "%#x %s", header->Machine, "INTEL");
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
			output(NULL, (char*)flags[j]);
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

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	
	parse_options(argc, argv); // opções
	
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

	// libera a memória
	pe_deinit(&pe);
	return 0;
}

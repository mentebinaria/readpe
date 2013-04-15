#include "common.h"

typedef struct pe_t {
	FILE *fd;
	char *content;
	size_t size;
	bool isdll;
	uint16_t e_lfanew;
	uint16_t architecture;
	uint64_t entrypoint;
	uint64_t imagebase;

	uint16_t num_sections;
	uint16_t num_directories;
	uint16_t num_rsrc_entries;

	uint16_t addr_sections;
	uint16_t addr_directories;
	uint16_t addr_dos;
	uint16_t addr_optional;
	uint16_t addr_coff;
	uint16_t addr_rsrc_sec;
	uint16_t addr_rsrc_dir;

	// pointers (will be freed if needed)
	header_optional *optional_ptr;
} pe_t;

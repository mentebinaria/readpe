#include "new_pe.h"

int main(int argc, char *argv[])
{
	pe_t pe;
	FILE *f = fopen(argv[1], "rb");

	if (!pe_init(&pe, f))
		return 1;

	printf("header: %c%c\nsize: %d\n", pe.content[0], pe.content[1], pe.size);
	printf(is_pe(&pe) ? "valid pe\n" : "not a pe file\n");
	fclose(f);
	return 0;
}

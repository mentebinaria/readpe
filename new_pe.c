#include "new_pe.h"

// the first function you should call
bool pe_init(pe_t *pe, FILE *fp)
{
	if (!pe || !fp)
		return false;

	memset(pe, 0, sizeof(pe));

	if (fseek(fp, 0, SEEK_END))
		return false;

	size_t siz = ftell(fp);

	if (siz < 1 || siz > MAXFILESIZE)
		return false;

	rewind(fp);

	char content[siz];
	size_t read = fread(&content, 1, siz, fp);

	if (read != siz)
		return false;

	pe->size = siz;
	pe->content = (char *) &content;
	return true;
}

bool is_pe(pe_t *pe)
{
	if (!pe->content)
		return false;

	// check MZ header
	if (pe->content[0] != 'M' || pe->content[1] != 'Z')
		return false;

	// check PE signature
	int32_t lfanew;
	memcpy(&lfanew, pe->content + sizeof(header_dos) - sizeof(lfanew), sizeof(lfanew));

	uint32_t pesig;
	memcpy(&pesig, pe->content + lfanew, sizeof(pesig));

	return (pesig == 0x4550); // PE\0\0
}

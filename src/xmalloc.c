#include <stdio.h>
#include <stdlib.h>

extern void *malloc();

void *xmalloc(unsigned int size)
{
	void *new_mem=malloc(size);	

	if (new_mem == NULL) {
		fprintf(stderr, "fatal: memory exhausted (xmalloc of %u bytes)\n", size);
		exit(-1);
	}

	return new_mem;
}

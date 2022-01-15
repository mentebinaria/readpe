/* vim: set ts=4 sw=4 noet: */
#include <stdio.h>
#include <stdlib.h>

void *malloc_s(size_t size) {
	if (!size)
		return NULL;

	void *new_mem = malloc(size);

	if (!new_mem) {
		fprintf(stderr, "fatal: memory exhausted (malloc of %zu bytes)\n", size);
		exit(EXIT_FAILURE);
	}

	return new_mem;
}

void *calloc_s( size_t nmemb, size_t size )
{
  void *p = NULL;

  if ( size && nmemb )
	if ( ! ( p = calloc( nmemb, size ) ) )
	{
	  fprintf( stderr, "fatal: unable to calloc (%zu elements of %zu bytes)\n",
		nmemb, size );
	  exit( EXIT_FAILURE );
	}

  return p;
}

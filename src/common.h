#ifndef COMMON_H
#define COMMON_H 1

#include <stdlib.h>
#include <stdio.h>

#ifdef __DEBUG_MODE__
	#define EXIT_ERROR(msg) \
			{ \
				fprintf(stderr, "%s, %d: %s\n", __FILE__, __LINE__, msg); \
				exit(EXIT_FAILURE); \
			}
#else
	#define EXIT_ERROR(msg) \
			{ \
				fprintf(stderr, "%s\n", msg); \
				exit(EXIT_FAILURE); \
			}
#endif

#endif

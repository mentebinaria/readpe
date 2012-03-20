#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>

#define PACKAGE "pev"
#define VERSION "0.50"

#define TEXT 1
#define HTML 2
#define XML  3
#define CSV  4

#ifdef __DEBUG_MODE__
	#define EXIT_WITH_ERROR(msg) \
			{ \
				fprintf(stderr, "%s, %d: %s\n", __FILE__, __LINE__, msg); \
				exit(EXIT_FAILURE); \
			}
#else
	#define EXIT_WITH_ERROR(msg) \
			{ \
				fprintf(stderr, "%s: %s\n", PACKAGE, msg); \
				exit(EXIT_FAILURE); \
			}
#endif

#endif // COMMON_H

#ifndef COMMON_H
#define COMMON_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include <pe.h>
#include "output.h"

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

#define MAX_MSG 50
#define VERSION "0.50"

#endif

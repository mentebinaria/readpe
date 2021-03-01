#ifndef PEV_ERROR_HANDLING_H
#define PEV_ERROR_HANDLING_H

#include <stdio.h>
#include <stdlib.h>

#define PEV_WARN_IO_HANDLE  stderr
#define PEV_FATAL_IO_HANDLE stderr
#define PEV_INFO_IO_HANDLE  stdout

#define PEV_FATAL(...)														    \
	do																			\
	{																			\
		fprintf(PEV_FATAL_IO_HANDLE, "[FATAL][%s:%d]: ", __FILE__, __LINE__);   \
		fprintf(PEV_FATAL_IO_HANDLE, __VA_ARGS__);							    \
		fputc('\n', PEV_FATAL_IO_HANDLE);									    \
		exit(EXIT_FAILURE);													    \
	} while (0)

#define PEV_WARN(...)															\
	do																			\
	{																			\
		fprintf(PEV_WARN_IO_HANDLE, "[WARNING][%s:%d]: ", __FILE__, __LINE__);	\
		fprintf(PEV_WARN_IO_HANDLE, __VA_ARGS__);								\
		fputc('\n', PEV_WARN_IO_HANDLE);										\
	} while (0)

#define PEV_INFO(...)															\
	do																			\
	{																			\
		fprintf(PEV_INFO_IO_HANDLE, "[INFO][%s:%d]: ", __FILE__, __LINE__);		\
		fprintf(PEV_INFO_IO_HANDLE, __VA_ARGS__);								\
		fputc('\n', PEV_INFO_IO_HANDLE);										\
	} while (0)

#define PEV_FATAL_IF(cond, ...) \
	do { if ((cond)) PEV_FATAL(__VA_ARGS__); } while (0)

#define GLUE(cond) #cond

#ifndef NDEBUG
	#define PEV_ASSERT(cond) if (!(cond)) PEV_FATAL("Assertion \"%s\" failed", GLUE((cond)))
#else
	#define PEV_ASSERT(cond)
#endif

#endif
#ifndef LIBPE_IMPORTS
#define LIBPE_IMPORTS

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include "pe.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "error.h"

typedef struct {
	pe_err_e err;
	char **functions; // array of function names
	int count;
}function_t;

typedef struct {
	pe_err_e err;
	char **dllNames;	// array of DLLNames
	int dll_count;
	function_t *functions; //array of function_t
}pe_import_t;

/*
 * we have array of names and array of functions.
 * functions[i] has functions corresponding to names[i]
 * "Imports": [
 *		{
 *			"DllName": "SHELL32.dll",
 *				"Functions": [
 *						"ShellExecuteA",
 *						"FindExecutableA"
 *				]
 *		}
 *	 ]
 */

pe_import_t get_imports(pe_ctx_t *ctx);
// Deallocation functions
void dealloc_imports(pe_import_t imports);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

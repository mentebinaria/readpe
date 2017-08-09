#ifndef LIBPE_IMPORTS
#define LIBPE_IMPORTS

#include <stdint.h>
#include "pe.h"
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	pe_err_e err;
	uint32_t count;
	char **names; // array of function names
} pe_imported_function_t;

typedef struct {
	pe_err_e err;
	uint32_t dll_count;
	char **dll_names; // array of DLL names
	pe_imported_function_t *functions; // array of imported functions
} pe_import_t;

/*
 * We have an array of names and an array of functions.
 *
 * functions[i] has functions corresponding to names[i]
 *
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

pe_import_t pe_get_imports(pe_ctx_t *ctx);
void pe_dealloc_imports(pe_import_t imports);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

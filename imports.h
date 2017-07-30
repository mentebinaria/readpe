#include <stdint.h>
#include <stdio.h>
#include "pe.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif


	// related to Imports

typedef struct {
	pe_err_e err;
	char **functions; // array of function names
	int count;
}function_t;

typedef struct {
	pe_err_e err;
	char **dllNames;  // array of DLLNames
	int dll_count;
	function_t *functions; //array of function_t
}import_t;

/*
 * we have array of names and array of functions.
 * functions[i] has functions corresponding to names[i]
"Imports": [
		{
			"DllName": "SHELL32.dll",
				"Functions": [
						"ShellExecuteA",
						"FindExecutableA"
				]
		}
]
*/

// Function to return imports
function_t get_imported_functions(pe_ctx_t *ctx, uint64_t offset, int functions_count, char *hint_str, size_t size_hint_str, char *fname, size_t size_fname);
import_t get_imports(pe_ctx_t *ctx);
int get_dll_count(pe_ctx_t *ctx);
int get_functions_count(pe_ctx_t *ctx, uint64_t offset);
void dealloc_imports(import_t imports);
#ifdef __cplusplus
} 
#endif


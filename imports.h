#include <stdint.h>
#include <stdio.h>
#include "pe.h"
#include <openssl/evp.h>
#include <openssl/md5.h>

#ifdef __cplusplus
extern "C" {
#endif


	// related to Imports

typedef struct {
	char **functions;
	int count;
}function;

typedef struct {
	char **names;
	int dll_count;
	function *functions;
}import;

	// Function to return imports
function get_imported_functions(pe_ctx_t *ctx, uint64_t offset, int functions_count, char *hint_str, size_t size_hint_str, char *fname, size_t size_fname);
import get_imports(pe_ctx_t *ctx);
int get_dll_count(pe_ctx_t *ctx);
int get_functions_count(pe_ctx_t *ctx, uint64_t offset);

#ifdef __cplusplus
} 
#endif


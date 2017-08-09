#ifndef LIBPE_MISC
#define LIBPE_MISC

#include "pe.h"

#ifdef __cplusplus
extern "C" {
#endif

double pe_calculate_entropy_file(pe_ctx_t *ctx);
bool pe_fpu_trick(pe_ctx_t *ctx);
int pe_get_cpl_analysis(pe_ctx_t *ctx);
int pe_has_fake_entrypoint(pe_ctx_t *ctx);

// TLS Functions
int pe_get_tls_callback(pe_ctx_t *ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

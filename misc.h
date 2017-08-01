#ifndef LIBPE_MISC
#define LIBPE_MISC

#ifdef __cplusplus
extern "C" {
#endif

#include "pe.h"

double calculate_entropy_file(pe_ctx_t *ctx);
bool fpu_trick(pe_ctx_t *ctx);
int get_cpl_analysis(pe_ctx_t *ctx);
int pe_has_fake_entrypoint(pe_ctx_t *ctx);

// TLS Functions
int get_tls_callback(pe_ctx_t *ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

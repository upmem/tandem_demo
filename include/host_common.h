#ifndef HOST_COMMON_H
#define HOST_COMMON_H
#include "dpu_common.h"

#define DPU_CLUSTER_MEMORY_SIZE (64U<<20)
#define DER_FORMAT_MAX_SIZE (72)

void der_to_sig (uint8_t *der, uint8_t *sig);
void print_secure(int fdpim);

#define POLL_DPU (1)
#define DO_NOT_POLL_DPU (0)
int dpu_pair_run (int fdpim, const char *dpu_bin, void *dpu0_code_ptr, void *dpu1_code_ptr, int polling);
void load_sign_data(mram_t *area, const char *pub_key, const char *der_sig, const char *enc_app_text, const char *app_data);
int result_sanity_checks(mram_t *area, const char *app_text, const char *hash);
#endif

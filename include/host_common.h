#ifndef HOST_COMMON_H
#define HOST_COMMON_H

#define DPU_CLUSTER_MEMORY_SIZE (64U<<20)
#define DER_FORMAT_MAX_SIZE (72)

void der_to_sig (uint8_t *der, uint8_t *sig);
void print_secure(int fdpim);

#define POLL_DPU (1)
#define DO_NOT_POLL_DPU (0)
int dpu_pair_run (int fdpim, const char *dpu_bin, void *dpu0_code_ptr, void *dpu1_code_ptr, int polling);
#endif

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "host_common.h"

#define PILOT_DPU_BINARY_AES "../pilot/dpu_aes_pilot"
#define PILOT_DPU_BINARY_ECDSA "../pilot/dpu_ecdsa_pilot"
#define PILOT_DPU_BINARY_HASH "../pilot/dpu_hash_pilot"

int pilot_secure_reset (int fdpim, void *dpu0_code_ptr, void *dpu1_code_ptr) {
    /* In this demo the Host is also playing the role of Pilot */
    int ret = -1;
    do {
        /* Push AES decryption application to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_AES, dpu0_code_ptr, dpu1_code_ptr, POLL_DPU) != 0) {
            break;
        }

        /* Push SHA256 calculation to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_HASH, dpu0_code_ptr, dpu1_code_ptr, POLL_DPU) != 0) {
            break;
        }

        /* Push ECDSA P-256 signature verification to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_ECDSA, dpu0_code_ptr, dpu1_code_ptr, DO_NOT_POLL_DPU) != 0) {
            break;
        }

        ret = 0;
    } while (0);

    return ret;
}

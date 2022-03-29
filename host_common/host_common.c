#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "host_common.h"
#include "pim.h"
#include "dpu_common.h"

extern int usleep (__useconds_t __useconds);

void der_to_sig (uint8_t *der, uint8_t *sig) {
    uint8_t *r_hdr = NULL;
    uint8_t *r = NULL;
    uint8_t *s_hdr = NULL;
    uint8_t *s = NULL;

    r_hdr = &der[3];
    switch (*r_hdr) {
        case 0x21:
            /* skip the leading 0x0 */
            r = r_hdr + 2;
            break;
        case 0x20:
            r = r_hdr + 1;
            break;
        default:
            printf("unexpected value 0x%x\n", *r_hdr);
            break;
    }
    s_hdr = r_hdr + *r_hdr + 2;
    switch (*s_hdr) {
        case 0x21:
            s = s_hdr + 2;
            break;
        case 0x20:
            s = s_hdr + 1;
            break;
        default:
            printf("unexpected value 0x%x\n", *s_hdr);
            break;
    }

    memcpy(sig, r, P256_SIG_SIZE/2);
    memcpy(&sig[P256_SIG_SIZE/2], s, P256_SIG_SIZE/2);
#if 0
    for (uint8_t i =0; i< P256_SIG_SIZE ; i++){
        if (i%16 ==0) {
            printf("\n");
        }
        printf ("0x%x ", sig[i]);
    }
    printf("\n");
#endif
}

void print_secure(int fdpim)
{
    printf("======================= Display secure memory =======================\n");
    fflush(stdout);
    usleep(20000);
    if (ioctl(fdpim, PIM_IOCTL_SHOW_S_MRAM, NULL) != 0) {
        printf("Failed to call TEE\n");
    }
    printf("=====================================================================\n");
    fflush(stdout);
}

int dpu_pair_run (int fdpim, const char *dpu_bin, void *dpu0_code_ptr, void *dpu1_code_ptr, int polling) {
    int fdbin, byte_num;
    pim_params_t params;
    int status = -1;
    do {
        /* Copy DPU application elf to MRAM */
        fdbin = open(dpu_bin, O_RDONLY);
        if (fdbin < 0) {
            perror("Failed to open DPU_BINARY");
            break;
        }
        byte_num = read(fdbin, dpu0_code_ptr, (DPU_CLUSTER_MEMORY_SIZE/2));
        if (byte_num == 0) {
            perror("DPU_BINARY is empty");
            break;
        }
        lseek(fdbin, 0, SEEK_SET);
        read(fdbin, dpu1_code_ptr, byte_num);
        close(fdbin);

        /* Load and run DPU program */
        params.arg1 = (uint64_t)(dpu0_code_ptr);
        params.arg2 = (uint64_t)(dpu1_code_ptr);
        if (ioctl(fdpim, PIM_IOCTL_LOAD_DPU, &params) < 0 ) {
            perror("Failed to control pim");
            break;
        }

        if (polling != DO_NOT_POLL_DPU) {
            /* Poll DPU0 */
            do {
                params.arg1 = (uint64_t)dpu0_code_ptr;
                if (ioctl(fdpim, PIM_IOCTL_GET_DPU_STATUS, &params) !=0 ) {
                    perror("Failed to poll pim");
                    break;
                }
            } while (params.ret1 == 1);
            if (params.ret1 != 0) {
                printf("Polling returned %ld %ld\n", params.ret0, params.ret1);
                break;
            }

            /* Poll DPU1 */
            do {
                params.arg1 = (uint64_t)dpu1_code_ptr;
                if (ioctl(fdpim, PIM_IOCTL_GET_DPU_STATUS, &params) != 0 ) {
                    perror("Failed to poll pim");
                    break;
                }
            } while (params.ret1 == 1);
            if (params.ret1 != 0) {
                printf("Polling returned %ld %ld\n", params.ret0, params.ret1);
                break;
            }
        }

        status = 0;

    } while (0);
    return status;
}

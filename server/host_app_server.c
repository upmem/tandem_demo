#include <assert.h>
#include <stdio.h>

#include <dpu.h>
#include <dpu_management.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <alloca.h>
#include "pim.h"
#define __dma_aligned __attribute__((aligned(8)))
#include "dpu_def.h"


#define DPU_CLUSTER_MEMORY_SIZE (64U<<20)
#define DER_FORMAT_MAX_SIZE (72)
/* In this demostrator the Host is also playing the role of Pilot */
#define PILOT_DPU_BINARY_ECDSA "../pilot/dpu_ecdsa_pilot"
#define PILOT_DPU_BINARY_HASH "../pilot/dpu_hash_pilot"

#define APP_TEXT_BINARY "./dpu_app_server.text"
#define APP_DATA_BINARY "./dpu_app_server.data"
#define APP_PUBKEY_BINARY "./public_key.bin"
#define APP_HASH_BINARY "./dpu_app_server.sha256"
#define APP_SIGNATURE_BINARY "./dpu_app_server.sig"


extern int usleep (__useconds_t __useconds);


static void der_to_sig (uint8_t *der, uint8_t *sig) {
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

static void load_sign_data(mram_t *area)
{
    int fdbin;
    /* DER format max signature size */
    uint8_t der_signature [DER_FORMAT_MAX_SIZE];

#ifdef VERIFY_ONLY
    area->dpu_policy = DPU_POLICY_VERIFY_ONLY;
#else
    area->dpu_policy = DPU_POLICY_VERIFY_AND_JUMP;
#endif
    fdbin = open(APP_PUBKEY_BINARY,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open APP_PUBKEY_BINARY\n");
        return;
    }
    read(fdbin, area->pub_key, P256_PUB_KEY_SIZE);
    close(fdbin);
    fdbin = open(APP_SIGNATURE_BINARY,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open APP_SIGNATURE_BINARY\n");
        return;
    }
    read(fdbin, der_signature, DER_FORMAT_MAX_SIZE);
    close(fdbin);

    der_to_sig (der_signature, area->signature);

#ifdef SIG_KO
    memset(area->signature, 0, 1);
#endif

    /* Copying user application code */
    fdbin = open(APP_TEXT_BINARY,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open APP_TEXT_BINARY");
        return;
    }
    area->app_text_size = read(fdbin, area->app_text, APP_MAX_SIZE);
    close(fdbin);
    /* Copying user application (Hello World) data */
    fdbin = open(APP_DATA_BINARY,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open APP_DATA_BINARY");
        return;
    }
    area->app_data_size = read(fdbin, area->app_data, APP_MAX_SIZE);
    close(fdbin);
}

static void print_secure(int fdpim)
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

static int dpu_pair_run (int fdpim, const char *dpu_bin, void *dpu0_code_ptr, void *dpu1_code_ptr) {
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

        /* Poll DPU0 */
        do {
            params.arg1 = (uint64_t)dpu0_code_ptr;
            if (ioctl(fdpim, PIM_IOCTL_GET_DPU_STATUS, &params) !=0 ) {
                perror("Failed to poll pim");
                break;
            }
        } while (params.ret1 == 1);
        if (params.ret1 != 0) {
            printf("Polling returned %ld %ld", params.ret0, params.ret1);
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
            printf("Polling returned %ld %ld", params.ret0, params.ret1);
            break;
        }

        status = 0;

    } while (0);
    return status;
}

int main(void)
{
    mram_t *dpu0_mram, *dpu1_mram;
    int fdpim, fdbin;
    int status = EXIT_FAILURE;
    uint8_t expected_hash[SHA256_SIZE];
    /* Open pim node */
    fdpim = open("/dev/pim", O_RDWR);
    do {
        if (fdpim < 0) {
            perror("Failed to open /dev/pim device node");
            break;
        }

        /* Try to get magic memory */
        void *va = mmap(NULL, DPU_CLUSTER_MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fdpim, 0);
        if (va == MAP_FAILED ) {
            perror("Failed to get DPU memory");
            break;
        }

        dpu0_mram = (mram_t*)(va);
        dpu1_mram = (mram_t*)((unsigned long)va+(DPU_CLUSTER_MEMORY_SIZE/2));
        /* load signature and public key in MRAM */
        load_sign_data(dpu0_mram);
        load_sign_data(dpu1_mram);

        /* Offload SHA256 calculation to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_HASH, dpu0_mram->code, dpu1_mram->code) != 0) {
            break;
        }
        /* Check hash value against expected value */
        /* Hash is calculated and copied by the dedicated DPU application */
        fdbin = open(APP_HASH_BINARY,O_RDONLY);
        if (fdbin < 0) {
            perror("Failed to open APP_HASH_BINARY");
            break;
        }
        read(fdbin, expected_hash, SHA256_SIZE);
        close(fdbin);
        if (
            (memcmp(dpu0_mram->hash, expected_hash, sizeof(expected_hash)) !=0) ||
            (memcmp(dpu1_mram->hash, expected_hash, sizeof(expected_hash)) !=0)
        ) {
            printf("#### Error DPU hash doesn't match the expected value\n");
            break;
        }
        printf("#### SHA256 all good!\n");


        /* Offload ECDSA P-256 signature verification to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_ECDSA, dpu0_mram->code, dpu1_mram->code) != 0) {
            break;
        }
        /* check verification status */
        if (
            (dpu0_mram->verification_status != 0) ||
            (dpu1_mram->verification_status != 0)
        ) {
            printf("#### ECDSA P-256 signature verification failed, %ld %ld\n", dpu0_mram->verification_status, dpu1_mram->verification_status);
            break;
        }
        printf("#### ECDSA P-256 signature verification all good!\n");

        /* print secure MRAM content */
        print_secure(fdpim);
        status = EXIT_SUCCESS;

    } while(0);

    /* Exit gracefully */
    close(fdpim);
    exit(status);
}

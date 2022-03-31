#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "pim.h"
#include "dpu_common.h"
#include "host_common.h"

/* In this demostrator the Host is also playing the role of Pilot */
#define PILOT_DPU_BINARY_AES "../pilot/dpu_aes_pilot"
#define PILOT_DPU_BINARY_ECDSA "../pilot/dpu_ecdsa_pilot"
#define PILOT_DPU_BINARY_HASH "../pilot/dpu_hash_pilot"

/* DPU application run on server */
#define DEVICE_DPU_APP_TEXT "./dpu_app_device.text.pad"
#define DEVICE_DPU_APP_TEXT_ENC "./dpu_app_device.text.enc"
#define DEVICE_DPU_APP_DATA "./dpu_app_device.data"
#define DEVICE_DPU_APP_PUBKEY "./public_key.bin"
#define DEVICE_DPU_APP_HASH "./dpu_app_device.sha256"
#define DEVICE_DPU_APP_SIG "./dpu_app_device.sig"
#define PSEUDO_RANDOM "/dev/urandom"


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
    fdbin = open(DEVICE_DPU_APP_PUBKEY,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open SERVER_DPU_APP_PUBKEY\n");
        return;
    }
    read(fdbin, area->pub_key, P256_PUB_KEY_SIZE);
    close(fdbin);
    fdbin = open(DEVICE_DPU_APP_SIG,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open SERVER_DPU_APP_SIG\n");
        return;
    }
    read(fdbin, der_signature, DER_FORMAT_MAX_SIZE);
    close(fdbin);

    der_to_sig (der_signature, area->signature);

#ifdef SIG_KO
    memset(area->signature, 0, 1);
#endif

    /* Copying encrypted user application code */
    fdbin = open(DEVICE_DPU_APP_TEXT_ENC,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open SERVER_DPU_APP_TEXT_ENC");
        return;
    }
    area->app_text_size = read(fdbin, area->app_text, APP_MAX_SIZE);
    close(fdbin);
    /* Copying user application (Hello World) data */
    fdbin = open(DEVICE_DPU_APP_DATA,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open SERVER_DPU_APP_DATA");
        return;
    }
    area->app_data_size = read(fdbin, area->app_data, APP_MAX_SIZE);
    close(fdbin);
    /* Copy pseudo random in MRAM */
    fdbin = open(PSEUDO_RANDOM,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open PSEUDO_RANDOM");
        return;
    }
    read(fdbin, (void *)&area->dpu_temperature_value, sizeof(area->dpu_temperature_value));
    close(fdbin);
    area->verification_status = -1;
}

int main(void)
{
    mram_t *dpu0_mram, *dpu1_mram;
    int fdpim, fdbin;
    int status = EXIT_FAILURE;
    uint8_t expected_hash[SHA256_SIZE];
    uint8_t expected_app_text[APP_MAX_SIZE];

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

        /* Offload AES decryption to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_AES, dpu0_mram->code, dpu1_mram->code, POLL_DPU) != 0) {
            break;
        }
        /* Offload SHA256 calculation to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_HASH, dpu0_mram->code, dpu1_mram->code, POLL_DPU) != 0) {
            break;
        }

        /* Check plaintext against expected value */
        fdbin = open(DEVICE_DPU_APP_TEXT,O_RDONLY);
        if (fdbin < 0) {
            perror("Failed to open SERVER_DPU_APP_TEXT");
            break;
        }
        read(fdbin, expected_app_text, dpu0_mram->app_text_size);
        close(fdbin);

        if (memcmp(dpu1_mram->app_text, expected_app_text, dpu1_mram->app_text_size) !=0)
        {
            printf("#### Error app plaintext doesn't match the expected value\n");
            break;
        }
        printf("#### AES decryption all good!\n");

        /* Check hash value against expected value */
        /* Hash is calculated and copied by the dedicated DPU application */
        fdbin = open(DEVICE_DPU_APP_HASH,O_RDONLY);
        if (fdbin < 0) {
            perror("Failed to open SERVER_DPU_APP_HASH");
            break;
        }
        read(fdbin, expected_hash, SHA256_SIZE);
        close(fdbin);
        if (memcmp(dpu1_mram->hash, expected_hash, sizeof(expected_hash)) !=0)
        {
            printf("#### Error DPU hash doesn't match the expected value\n");
            break;
        }
        printf("#### SHA256 all good!\n");

        /* Offload ECDSA P-256 signature verification to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_ECDSA, dpu0_mram->code, dpu1_mram->code, DO_NOT_POLL_DPU) != 0) {
            break;
        }

        /* check verification status */
        while (dpu1_mram->verification_status != 0){ }
        printf("#### ECDSA P-256 signature verification all good!\n");
        print_secure(fdpim);
        printf ("dpu_temperature_value 0x%lx\n", dpu1_mram->dpu_temperature_value);

        fdbin = open("OK",O_CREAT);
        close(fdbin); 

        status = EXIT_SUCCESS;
    } while(0);

    /* Exit gracefully */
    close(fdpim);
    exit(status);
}
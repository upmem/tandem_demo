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
#define SERVER_DPU_APP_TEXT "./dpu_app_server.text"
#define SERVER_DPU_APP_TEXT_ENC "./dpu_app_server.text.enc"
#define SERVER_DPU_APP_DATA "./dpu_app_server.data"
#define SERVER_DPU_APP_PUBKEY "./public_key.bin"
#define SERVER_DPU_APP_HASH "./dpu_app_server.sha256"
#define SERVER_DPU_APP_SIG "./dpu_app_server.sig"
#define TEMP_SAMPLE "./temp_sample"


static void load_mram(mram_t *area)
{
    load_sign_data(area, SERVER_DPU_APP_PUBKEY, SERVER_DPU_APP_SIG, SERVER_DPU_APP_TEXT_ENC, SERVER_DPU_APP_DATA);
#ifdef SIG_KO
    memset(area->signature, 0, 1);
#endif
    memset ((void *)area->encrypted_device_temp_sample, 0, AES_BLOCK_SIZE);
    memset ((void *)area->device_temp_sample, 0, AES_BLOCK_SIZE);
}

int main(void)
{
    mram_t *dpu0_mram, *dpu1_mram;
    int i, fdpim, fdbin;
    int status = EXIT_FAILURE;
    uint8_t expected_hash[SHA256_SIZE];
    uint8_t expected_app_text[APP_MAX_SIZE];
    static uint8_t zero[AES_BLOCK_SIZE];

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
        load_mram(dpu0_mram);
        load_mram(dpu1_mram);

        /* Offload AES decryption to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_AES, dpu0_mram->code, dpu1_mram->code, POLL_DPU) != 0) {
            break;
        }

        /* Check plaintext against expected value */
        fdbin = open(SERVER_DPU_APP_TEXT,O_RDONLY);
        if (fdbin < 0) {
            perror("Failed to open SERVER_DPU_APP_TEXT");
            break;
        }
        read(fdbin, expected_app_text, dpu0_mram->app_text_size);
        close(fdbin);

        /* Offload SHA256 calculation to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_HASH, dpu0_mram->code, dpu1_mram->code, POLL_DPU) != 0) {
            break;
        }

        if (memcmp(dpu1_mram->app_text, expected_app_text, dpu1_mram->app_text_size) !=0)
        {
            printf("#### Error app plaintext doesn't match the expected value\n");
            break;
        }
        printf("\t#### AES decryption all good!\n");

        /* Check hash value against expected value */
        /* Hash is calculated and copied by the dedicated DPU application */
        fdbin = open(SERVER_DPU_APP_HASH,O_RDONLY);
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
        printf("\t#### SHA256 all good!\n");

        /* Offload ECDSA P-256 signature verification to DPUs */
        if (dpu_pair_run(fdpim, PILOT_DPU_BINARY_ECDSA, dpu0_mram->code, dpu1_mram->code, DO_NOT_POLL_DPU) != 0) {
            break;
        }

        /* Check verification status */
        while (dpu1_mram->verification_status != 0){ }
        printf("\t#### ECDSA P-256 signature verification all good!\n");
        print_secure(fdpim);

        /* Tell the shell script that the application has been successfully executed on DPU */
        fdbin = open("OK", O_CREAT);
        if (fdbin < 0) {
            perror("Failed to open SERVER_DPU_APP_HASH");
            break;
        }
        close(fdbin); 

        printf ("\tWaiting from encrypted sensors data...\n");
        do {
            fdbin = open(TEMP_SAMPLE, O_RDONLY);
            sleep(1);
        } while (fdbin < 0);
        read(fdbin, (void *)dpu1_mram->encrypted_device_temp_sample, AES_BLOCK_SIZE);
        close(fdbin);

        printf ("\tEncrypted temperature sample received:\n\t");
        for (i = 0; i < AES_BLOCK_SIZE; i++) {
            printf ("%x", dpu1_mram->encrypted_device_temp_sample[i]);
        }
        printf ("\n");  
        printf ("\tWaiting for DPU decryption...\n");
        do {
            sleep(1);
        }
        while (memcmp((void *)dpu1_mram->device_temp_sample, zero, AES_BLOCK_SIZE) == 0);
        printf ("\tDecrypted temperature sample:\n\t");
        for (i = 0; i < AES_BLOCK_SIZE; i++) {
            printf ("%x", dpu1_mram->device_temp_sample[i]);
        }
        printf ("\n");
        status = EXIT_SUCCESS;
    } while(0);

    printf ("\tServer execution ends.\n");
    /* Exit gracefully */
    close(fdpim);
    exit(status);
}

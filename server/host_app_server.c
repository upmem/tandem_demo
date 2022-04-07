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
#include "pilot.h"

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
    /* Load signature data in MRAM */
    load_sign_data(area, SERVER_DPU_APP_PUBKEY, SERVER_DPU_APP_SIG, SERVER_DPU_APP_TEXT_ENC, SERVER_DPU_APP_DATA);
#ifdef SIG_KO
    memset(area->signature, 0, 1);
#endif
    memset ((void *)area->encrypted_device_temp_sample, 0, AES_BLOCK_SIZE);
    memset ((void *)area->device_temp_sample, 0, AES_BLOCK_SIZE);
}

static void log_results(mram_t *area) {
    int i;
    printf ("\tEncrypted temperature sample:\n\t");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        printf ("%x", area->encrypted_device_temp_sample[i]);
    }
    printf ("\n");  

    printf ("\tDecrypted temperature sample:\n\t");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        printf ("%x", area->device_temp_sample[i]);
    }
    printf ("\n");
}

int main(void)
{
    mram_t *dpu0_mram, *dpu1_mram;
    int fdpim, fdbin;
    int status = EXIT_FAILURE;
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

        /* load all the needed data in MRAM (e.g. encrypted app, signature, pub key) */
        load_mram(dpu0_mram);
        load_mram(dpu1_mram);

        /* 
         * Ask Pilot to perform application signature verification and decryption 
         * In this demo Pilot is emulated by the Host
        */
        if (pilot_secure_reset(fdpim, dpu0_mram->code, dpu1_mram->code) != 0) {
            break;
        }

        /* wait for verification status */
        while (dpu1_mram->verification_status != 0);
        
        if (result_sanity_checks(dpu1_mram, SERVER_DPU_APP_TEXT, SERVER_DPU_APP_HASH) != 0) {
            break;
        }

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

        printf ("\tSample received, share it with DPU for decryption...\n");
        read(fdbin, (void *)dpu1_mram->encrypted_device_temp_sample, AES_BLOCK_SIZE);
        close(fdbin);
        /* Waiting for DPU decryption */
        do {
            sleep(1);
        }
        while (memcmp((void *)dpu1_mram->device_temp_sample, zero, AES_BLOCK_SIZE) == 0);

        log_results(dpu1_mram);

        status = EXIT_SUCCESS;
    } while(0);

    printf ("\tServer execution ends.\n");
    /* Print secure MRAM for debug purposes */
    print_secure(fdpim);
    /* Exit gracefully */
    close(fdpim);
    exit(status);
}

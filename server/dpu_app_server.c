#include <stdint.h>
#include <mram.h>
#include "dpu_common.h"
#include "aes.h"
#include "key.h"
#include <string.h>

extern __mram_ptr void *__sys_sec_mram_start;
__mram_noinit mram_t mram;

#define MRAM_BLOCK_SIZE (8)

int main (void){
    uint8_t device_temp_sample[AES_BLOCK_SIZE];
    /* Static array are initialized to 0*/
    static uint8_t zero[AES_BLOCK_SIZE];
    dpu_crypto_aes_context ctx;
    char string [MRAM_BLOCK_SIZE*3] = "Server hello world!!\0";
    mram_write(string, __sys_sec_mram_start, sizeof(string));
    dpu_crypto_aes_init(&ctx);

    /* Wait for a valid temp sample*/
    //do {
    mram_read((const __mram_ptr void *)mram.encrypted_device_temp_sample, (void *)device_temp_sample, AES_BLOCK_SIZE);
    //} while (memcmp(device_temp_sample, zero, AES_BLOCK_SIZE) == 0);
    
    //dpu_crypto_aes_setkey_dec(&ctx, key, sizeof(key) *8);
    /*if (ret != 0) {
        break;
    }*/
    dpu_crypto_aes_crypt_ecb(&ctx, DPU_CRYPTO_AES_DECRYPT, device_temp_sample, device_temp_sample);
    /*if (ret != 0) {
        break;
    }*/
    mram_write ((const void *)device_temp_sample, (__mram_ptr void *)mram.device_temp_sample, AES_BLOCK_SIZE);
    //dpu_crypto_aes_free(&ctx);

    return 0;
}

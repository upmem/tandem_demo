#include <stdint.h>
#include <mram.h>
#include "dpu_common.h"
#include "aes.h"
#include "key.h"
#include "config.h"

#define MRAM_BLOCK_SIZE (8)

extern __mram_ptr void *__sys_sec_mram_start;
/* It corresponds to the start of the ns MRAM */
__mram_noinit mram_t mram;


int main (void){
    char string [MRAM_BLOCK_SIZE*3] = "Dev hello world!!\0";
    dpu_crypto_aes_context ctx;
    uint8_t temp_sample[AES_BLOCK_SIZE];

    /* Write to ns memory for debug purposes */
    mram_write(string, __sys_sec_mram_start, sizeof(string));
    do {
        dpu_crypto_aes_init(&ctx);

        if (dpu_crypto_aes_setkey_enc(&ctx, key, sizeof(key) *8) != 0){
            break;
        }

        mram_read((__mram_ptr void *)mram.device_temp_sample, (void *)temp_sample, AES_BLOCK_SIZE);


        if (dpu_crypto_aes_crypt_ecb(&ctx, DPU_CRYPTO_AES_ENCRYPT, temp_sample, temp_sample) != 0) {
            break;
        }

        mram_write(temp_sample, (__mram_ptr void *)mram.encrypted_device_temp_sample, AES_BLOCK_SIZE);

        dpu_crypto_aes_free(&ctx);

    } while(0);
    return 0;
}

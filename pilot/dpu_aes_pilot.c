#include <stdio.h>
#include <string.h>

#include <mram.h>
#include "aes.h"
#include "key.h"
//#include "dpu_jump.h"
#include "dpu_def.h"
#include "platform_util.h"
#include "config.h"


__mram_noinit mram_t mram;
extern __mram_ptr void *__sys_sec_mram_start;

#define APP_TMP_BUFFER_SIZE (2048)
/*
 * Checkup routine
 */
int main(void)
{
    int chunk, i, remain_data, ret = -1;
    dpu_crypto_aes_context ctx;
    uint8_t app_text_buf[APP_TMP_BUFFER_SIZE];
    do {
        dpu_crypto_aes_init(&ctx);

        /* Key schedule */
        if (dpu_crypto_aes_setkey_dec(&ctx, key, sizeof(key) * 8) != 0) {
            break;
        }

        for (chunk = 0;  chunk < mram.app_text_size/APP_TMP_BUFFER_SIZE; chunk++) {
            /* Read the encrypted application code (ciphertext) */
            mram_read((__mram_ptr void *)&mram.app_text[chunk * APP_TMP_BUFFER_SIZE], (void *)app_text_buf, APP_TMP_BUFFER_SIZE);
            /* AES-ECB decryption - plaintext overwrite the ciphertext */
            for (i=0; i < APP_TMP_BUFFER_SIZE; i+=16) {
                ret = dpu_crypto_aes_crypt_ecb(&ctx, DPU_CRYPTO_AES_DECRYPT, &app_text_buf[i], &app_text_buf[i]);
                if (ret != 0) {
                    break;
                }
            }

            if (ret != 0) {
                break;
            }
            /*
            * The application need to be copied back to MRAM
            * There is no way to transfer data from WRAM to IRAM directly
            */
            mram_write(app_text_buf, mram.app_text, APP_TMP_BUFFER_SIZE);
        }

        if (ret != 0) {
            break;
        }

        remain_data = mram.app_text_size%APP_TMP_BUFFER_SIZE;
        /* the application must be padded */
        if (remain_data % 16) {
            break;
        }
        //remain_data +=  (16 -(remain_data % 16));

        mram_read((__mram_ptr void *)&mram.app_text[mram.app_text_size/APP_TMP_BUFFER_SIZE], (void *)app_text_buf, remain_data);
        for (i=0; i < remain_data; i+=16) {
            ret = dpu_crypto_aes_crypt_ecb(&ctx, DPU_CRYPTO_AES_DECRYPT, &app_text_buf[i], &app_text_buf[i]);
            if (ret != 0) {
                break;
            }
        }
        mram_write(app_text_buf, mram.app_text, remain_data);

        /*
        * Copy the user application and data in IRMA/WRAM
        * We should never return from this function
        */
        //dpu_jump((uint32_t)mram.app_data, mram.app_data_size, (uint32_t) mram.app_text, mram.app_text_enc_size);
        dpu_crypto_aes_free(&ctx);
    } while (0);
    return 0;
}

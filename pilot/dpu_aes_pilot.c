#include <stdio.h>
#include <string.h>

#include <mram.h>
#include "aes.h"
#include "key.h"
#include "dpu_jump.h"
#include "dpu_common.h"
#include "platform_util.h"
#include "config.h"

#define APP_TMP_BUFFER_SIZE (2*1024)

extern __mram_ptr void *__sys_sec_mram_start;

__mram_noinit mram_t mram;
__dma_aligned uint8_t app_text_buf[APP_TMP_BUFFER_SIZE];

/*
 * Checkup routine
 */
int main(void)
{
    int chunk, i, ret = -1;
    dpu_crypto_aes_context ctx;
    int app_size =  mram.app_text_size;
    int remaining_data = app_size % APP_TMP_BUFFER_SIZE;
    __mram_ptr sec_mram_t *sec_mram = (__mram_ptr sec_mram_t *)__sys_sec_mram_start;
    do {
        /* Key schedule */
        ret = dpu_crypto_aes_setkey_dec(&ctx, key, sizeof(key) *8);
        if (ret != 0) {
            break;
        }

        for (chunk = 0;  chunk < app_size/APP_TMP_BUFFER_SIZE; chunk++) {
            /* Copy the ciphertext application in the stack in chunk of APP_TMP_BUFFER_SIZE*/
            mram_read((__mram_ptr void *)&mram.app_text[chunk * APP_TMP_BUFFER_SIZE], (void *)app_text_buf, APP_TMP_BUFFER_SIZE);
            /* AES-ECB decryption - plaintext overwrite the ciphertext in the local buffer */
            for (i=0; i < APP_TMP_BUFFER_SIZE; i+=16) {
                ret = dpu_crypto_aes_crypt_ecb(&ctx, DPU_CRYPTO_AES_DECRYPT, &app_text_buf[i], &app_text_buf[i]);
                if (ret != 0) {
                    break;
                }
            }

            if (ret != 0) {
                break;
            }

            /* Copy the plaintext to secure MRAM for further handling - accessible by DPUs only */
            mram_write(app_text_buf, &sec_mram->app_text[chunk * APP_TMP_BUFFER_SIZE], APP_TMP_BUFFER_SIZE);

            /* Copy the plaintext to non-secure MRAM for sanity checks - for demonstration purposes only */
            mram_write(app_text_buf, &mram.app_text[chunk * APP_TMP_BUFFER_SIZE], APP_TMP_BUFFER_SIZE);
        }

        if (remaining_data) {
            /* The ciphertext must by 16 bytes aligned */
            if ((remaining_data % 16) != 0) {
                break;
            }
            /* Read the encrypted application code (ciphertext) */
            mram_read((__mram_ptr void *)&mram.app_text[(app_size/APP_TMP_BUFFER_SIZE) * APP_TMP_BUFFER_SIZE], (void *)app_text_buf, remaining_data);

            /* AES-ECB decryption - plaintext overwrite the ciphertext */
            for (i=0; i < remaining_data; i+=16) {
                ret = dpu_crypto_aes_crypt_ecb(&ctx, DPU_CRYPTO_AES_DECRYPT, &app_text_buf[i], &app_text_buf[i]);
                if (ret != 0) {
                    break;
                }
            }
            if (ret != 0) {
                break;
            }

            /* Copy the plaintext to secure MRAM for further handling - accessible by DPUs only */
            mram_write(app_text_buf, &sec_mram->app_text[(app_size/APP_TMP_BUFFER_SIZE) * APP_TMP_BUFFER_SIZE], remaining_data);

            /* Copy the plaintext to non-secure MRAM for sanity checks - for demonstration purposes only */
            mram_write(app_text_buf, &mram.app_text[(app_size/APP_TMP_BUFFER_SIZE) * APP_TMP_BUFFER_SIZE], remaining_data);
        }
        dpu_crypto_aes_free(&ctx);
    } while (0);
    return 0;
}

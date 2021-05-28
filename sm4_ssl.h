#include <inttypes.h>

void SM4_ecb_encrypt(uint8_t *key, uint8_t *in, uint32_t len, uint8_t *out);
void SM4_ecb_decrypt(uint8_t *key, uint8_t *in, uint32_t len, uint8_t *out);
void SM4_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *in, uint32_t len, uint8_t *out);
void SM4_cbc_decrypt(uint8_t *key, uint8_t *iv, uint8_t *in, uint32_t len, uint8_t *out);
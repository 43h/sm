#ifndef _SM4_H_
#define _SM4_H_

#include "typedef.h"

//key len 128bit -- 16 byte
#define SM4_PKG_LEN 16
#define SM4_KEY_LEN	16

void sm4_ecb_encrypt(u8 *key, u8 *in, u8 len, u8 *out);
void sm4_ecb_decrypt(u8 *key, u8 *in, u8 len, u8 *out);
void sm4_cbc_encrypt(u8 *key, u8 *iv, u8 *in, u8 len, u8 *out);
void sm4_cbc_decrypt(u8 *key, u8 *iv, u8 *in, u8 len, u8 *out);

#endif /* _SM4_H_ */

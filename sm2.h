#ifndef _SM2_H_
#define _SM2_H_

#include "typedef.h"
#include "ecc.h"

extern u8 USER_ID[16];

void sm3_z(u8 *id, u32 idlen, ecc_point *pub, u8 *hash);

/*
 * produce private key and public key 
 */
 
int sm2_valid_private_key(u8 *prikey);
int sm2_make_prikey(u8 *prikey);
int sm2_make_pubkey(u8 *prikey, ecc_point *pubkey);
int sm2_make_keypair(u8 *prikey, ecc_point *pubkey);
int sm2_is_valid_public_key(ecc_point *publicKey);

/*
 * SM2-1 digital signature algorithm
 */
int sm2_sign(u8 *prikey, ecc_point *pubkey, u8 *msg, u32 len, u8 *r, u8 *s);
int sm2_verify(ecc_point *pubkey, u8 *msg, u32 len, u8 *r, u8 *s);

/*
 * SM2-2 key exchange protocol
 */
int sm2_ke_init_i(u8 *ra, ecc_point *Ra);

int sm2_ke_re_i(u8 *rb, u8 *db,
                   ecc_point *Ra, ecc_point *Pa,
                   u8 *Za, u8 *Zb,
                   ecc_point *V,
                   u8 *K, u32 klen,
                   ecc_point *Rb, u8 *Sb);

int sm2_ke_init_ii(u8 *ra, u8 *da,
                      ecc_point *Ra, ecc_point *Rb, ecc_point *Pb,
                      u8 *Za, u8 *Zb,
                      u8 *Sb,
                      u8 *K, u32 klen,
                      u8 *Sa);
int sm2_ke_re_ii(ecc_point *V, ecc_point *Ra, ecc_point *Rb,
                    u8 *Za, u8 *Zb,
                    u8 *Sa);
/*
 * SM2-3 public key encryption algorithm
 */
int sm2_encrypt(ecc_point *pubKey, u8 *M, u32 Mlen, u8 *C, u32 *Clen);
int sm2_decrypt(u8 *prikey, u8 *C, u32 Clen, u8 *M, u32 *Mlen);

#endif

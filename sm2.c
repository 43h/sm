#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "debug.h"
#include "random.h"
#include "vli.h"
#include "sm2.h"
#include "sm3.h"

//user id
u8 USER_ID[16] =
{
	0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38,
	0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38
};

//length of usrID
#define ENTL 16 ;

//elliptic curve
// y^2 = x^2 + ax + b
struct ecc_curve sm2_curve =
{
	.ndigits = ECC_MAX_DIGITS,
	.g = {
		.x =
		{
			0x715A4589334C74C7ull, 0x8FE30BBFF2660BE1ull,
			0x5F9904466A39C994ull, 0x32C4AE2C1F198119ull
		},
		.y =
		{
			0x02DF32E52139F0A0ull, 0xD0A9877CC62A4740ull,
			0x59BDCEE36B692153ull, 0xBC3736A2F4F6779Cull
		},
	},
	.p =
	{
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
	},
	.n =
	{
		0x53BBF40939D54123ull, 0x7203DF6B21C6052Bull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
	},
	.h =
	{
		0x0000000000000001ull, 0x0000000000000000ull,
		0x0000000000000000ull, 0x0000000000000000ull,
	},
	.a =
	{
		0xFFFFFFFFFFFFFFFCull, 0xFFFFFFFF00000000ull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
	},
	.b =
	{
		0xDDBCBD414D940E93ull, 0xF39789F515AB8F92ull,
		0x4D5A9E4BCF6509A7ull, 0x28E9FA9E9D9F5E34ull
	},
};

u8 one[32] =
{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

u8 two[32] =
{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02
};

//private key: d（[1, n-2]
//key should be string order
int sm2_is_valid_private_key(u8 *key)
{
	u64 pri[ECC_MAX_DIGITS];
	u64 max[ECC_MAX_DIGITS];

	ecc_bytes2native(pri, key, ECC_MAX_DIGITS);

	//set max = n - 2
	ecc_bytes2native(max, two, ECC_MAX_DIGITS);
	vli_sub(max, sm2_curve.n, max, ECC_MAX_DIGITS);

	//k <= n - 2
	if(vli_cmp(max, pri, ECC_MAX_DIGITS) >= 0)
	{
		//k > 0
		if(!vli_is_zero(pri, ECC_MAX_DIGITS))
		{
			return 1;
		}
	}

	return 0;
}

int sm2_make_prikey(u8 *prikey)
{
	int i = 10;

	do
	{
		vli_get_random((u8 *)prikey, ECC_NUMWORD);
		if(sm2_is_valid_private_key((u8 *) prikey))
		{
			return 0;
		}
	} while(i--);

	return -1;
}

/* test the public key,
 * the key should be in native order
 *
 * point 'O' is endless point
 * a) P != O
 * b) x（[0, p-1];  y（[0, p-1]
 * c) y^3 = x^3 + ax +b (mod)p
 * d) [n]P == O
 */
int sm2_valid_public_key(ecc_point *pubKey)
{
	u64 na[ECC_MAX_DIGITS] = {3}; /* a mod p = (-3) mod p */
	u64 tmp1[ECC_MAX_DIGITS];
	u64 tmp2[ECC_MAX_DIGITS];

	if(ecc_point_is_zero(&sm2_curve, pubKey))
	{
		return 0;
	}

	if(vli_cmp(sm2_curve.p, pubKey->x, sm2_curve.ndigits) != 1
	        || vli_cmp(sm2_curve.p, pubKey->y, sm2_curve.ndigits) != 1)
	{
		return 0;
	}

	/* tmp1 = y^2 */
	vli_mod_square_fast(tmp1, pubKey->y, sm2_curve.p, sm2_curve.ndigits);
	/* tmp2 = x^2 */
	vli_mod_square_fast(tmp2, pubKey->x, sm2_curve.p, sm2_curve.ndigits);
	/* tmp2 = x^2 + a = x^2 - 3 */
	vli_mod_sub(tmp2, tmp2, na, sm2_curve.p, sm2_curve.ndigits);
	/* tmp2 = x^3 + ax */
	vli_mod_mult_fast(tmp2, tmp2, pubKey->x, sm2_curve.p, sm2_curve.ndigits);
	/* tmp2 = x^3 + ax + b */
	vli_mod_add(tmp2, tmp2, sm2_curve.b, sm2_curve.p, sm2_curve.ndigits);

	/* Make sure that y^2 == x^3 + ax + b */
	if(vli_cmp(tmp1, tmp2, sm2_curve.ndigits) != 0)
	{
		return 0;
	}

	ecc_point O[1];
	ecc_point P[1];
	// p != O
	ecc_point_mult(&sm2_curve, O, &sm2_curve.g, sm2_curve.n, NULL);
	if((vli_cmp((u64 *)pubKey->x, (u64 *) O->x, ECC_MAX_DIGITS) == 0) &&
	        (vli_cmp((u64 *)pubKey->y, (u64 *)O->y, ECC_MAX_DIGITS) == 0))
	{
		return 0;
	}

	ecc_point_mult(&sm2_curve, P, pubKey, sm2_curve.n, NULL);
	if((vli_cmp((u64 *)P->x, (u64 *) O->x, ECC_MAX_DIGITS) == 0) &&
	        (vli_cmp((u64 *)P->y, (u64 *)O->y, ECC_MAX_DIGITS) == 0))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

//the key should be in string order
int sm2_is_valid_public_key(ecc_point *key)
{
	ecc_point pub[1];
	ecc_bytes2native((u64 *)pub->x, key->x, ECC_MAX_DIGITS);
	ecc_bytes2native((u64 *)pub->y, key->y, ECC_MAX_DIGITS);
	return sm2_valid_public_key(pub);
}

int sm2_make_pubkey(u8 *prikey, ecc_point *pubkey)
{
	ecc_point pub[1];
	u64 pri[ECC_MAX_DIGITS];

	ecc_bytes2native(pri, prikey, sm2_curve.ndigits);
	ecc_point_mult(&sm2_curve, pub, &sm2_curve.g, pri, NULL);
	ecc_native2bytes(pubkey->x, pub->x, sm2_curve.ndigits);
	ecc_native2bytes(pubkey->y, pub->y, sm2_curve.ndigits);

	return 0;
}

int sm2_make_keypair(u8 *prikey, ecc_point *pubkey)
{
	sm2_make_prikey(prikey);
	sm2_make_pubkey(prikey, pubkey);
	return 0;
}

/*
 * function:
 * description: key drive function
 * i（ [1,klen/v]
 *  Ha[i] = Hash(Z||ct)
 *  ct++
 *
 * if(klen%v == 0)
 *  Ha![klen/v] = Ha[klen/v]
 * else
 * Ha![klen/v] = Ha[klen/v] (left klen%v bits)
 *
 * K = Ha1 || Ha2|| ... ||Ha[klen/v -1] || Ha![klen/v]
 */
void sm3_kdf(u8 *Z, u32 zlen, u8 *K, u32 klen)
{
	u32 ct = 0x00000001;    //counter
	u8 ct_char[32];
	sm3_ctx md[1];

	int t = klen / ECC_NUMWORD;
	for(int i = 0; i < t; i++)
	{
		put_unaligned_be32(ct, ct_char);
		//s2: Hai=Hv(Z||ct)
		sm3_init(md);
		sm3_update(md, Z, zlen);
		sm3_update(md, ct_char, 4);
		sm3_final(md, K);
		K += 32;
		Z += 32;
		ct++;
	}

	t = klen % ECC_NUMWORD;

	if(t)
	{
		put_unaligned_be32(ct, ct_char);
		sm3_init(md);
		sm3_update(md, Z, zlen);
		sm3_update(md, ct_char, 4);
		sm3_final(md, ct_char);
		memcpy(K, ct_char, t);
	}
}

/*
 * function:
 * description: hash of UserA
 * ENTLa -- the length of userID
 * IDa   -- userID
 * a,b
 * Xg,Yg -- the G point
 * Xa,Ya -- the public key
 *
 * Za = Hash(ENTLa || IDa || a || b||  Xg || Yg || Xa || Ya)
 */
void sm3_z(u8 *id, u32 idlen, ecc_point *pub, u8 *hash)
{
	u8 a[ECC_NUMWORD];
	u8 b[ECC_NUMWORD];
	u8 x[ECC_NUMWORD];
	u8 y[ECC_NUMWORD];
	u8 idlen_char[2];
	sm3_ctx md[1];

	put_unaligned_be16(idlen << 3, idlen_char);

	ecc_bytes2native((u64 *)a, sm2_curve.a, sm2_curve.ndigits);
	ecc_bytes2native((u64 *)b, sm2_curve.b, sm2_curve.ndigits);
	ecc_bytes2native((u64 *)x, sm2_curve.g.x, sm2_curve.ndigits);
	ecc_bytes2native((u64 *)y, sm2_curve.g.y, sm2_curve.ndigits);

	sm3_init(md);
	sm3_update(md, idlen_char, 2);
	sm3_update(md, id, idlen);
	sm3_update(md, a, ECC_NUMWORD);
	sm3_update(md, b, ECC_NUMWORD);
	sm3_update(md, x, ECC_NUMWORD);
	sm3_update(md, y, ECC_NUMWORD);
	sm3_update(md, (u8 *)pub->x, ECC_NUMWORD);
	sm3_update(md, (u8 *)pub->y, ECC_NUMWORD);
	sm3_final(md, hash);
}


/*
 * e = H256(Za || M)
 */
void sm3_e(u8 *Za, u8 *msg, u32 len, u8 *e)
{
	sm3_ctx md[1];
	sm3_init(md);
	sm3_update(md, Za, 32);
	sm3_update(md, msg, len);
	sm3_final(md, e);
}

/*
  msg digst(r,s)
  Za = Hash(ENTLa || IDa || a || b||  Xg || Yg || Xa || Ya)
  A1-- M- = Za || M
  A2-- e  = Hash(M-)
  A3-- k （ [1, n-1]
  A4-- (x1, y1) = [k](Xg,Yg)
  A5-- r = (e + x1)mod n
  A6-- s = ((1 + da)^(-1) * (k - r*da))mod n
 */
int sm2_sign(u8 *prikey, ecc_point *pubkey, u8 *msg, u32 len, u8 *r_, u8 *s_)
{
	u64 pri[ECC_MAX_DIGITS];
	u8 Za[32];

	u8 e[32];

	u64 k[ECC_MAX_DIGITS];
	ecc_point p;

	u64 one[ECC_MAX_DIGITS] = {1};
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];

	//A1-- M'_ = Za || M
	//Za = H256(ENTL || IDa || a || b || Xg || Yg || Xa || Ya)
	sm3_z(USER_ID, 16, pubkey, Za);

	//A2-- e = H256(Za || M)
	sm3_e(Za, msg, len, e);

	//A3-- k（[1,n-1]
	#ifdef TEST_MODE
	u8 rand[] =
	{
		0x59, 0x27, 0x6e, 0x27,
		0xd5, 0x06, 0x86, 0x1a,
		0x16, 0x68, 0x0f, 0x3a,
		0xd9, 0xc0, 0x2d, 0xcc,
		0xef, 0x3c, 0xc1, 0xfa,
		0x3c, 0xdb, 0xe4, 0xce,
		0x6d, 0x54, 0xb8, 0x0d,
		0xea, 0xc1, 0xbc, 0x21
	};

	ecc_bytes2native(k, rand, sm2_curve.ndigits);

	#else
	u8 rand[32];
loop:
	vli_get_random(rand, ECC_NUMWORD);
	//k > 0
	if(vli_is_zero((u64 *)rand, sm2_curve.ndigits))
	{
		goto loop;
	}

	vli_set(k, (u64 *)rand, sm2_curve.ndigits);
	//k < n
	if(vli_cmp(sm2_curve.n, k, sm2_curve.ndigits) != 1)
	{
		goto loop;
	}
	#endif

	/*A4-- (X1,Y1) = k * G */
	ecc_point_mult(&sm2_curve, &p, &sm2_curve.g, k, NULL);

	/*A5-- r = (e + x1)mod n*/
	ecc_bytes2native((u64 *)e, e, sm2_curve.ndigits);
	vli_mod_add(r, (u64 *)e, p.x,  sm2_curve.n, sm2_curve.ndigits);


	#ifndef TEST_MODE
	/* If r == 0, goto loop. */
	if(vli_is_zero(r, sm2_curve.ndigits))
	{
		goto loop;
	}

	//if r + k == n,goto loop;
	vli_sub((u64 *)rand, sm2_curve.n, r, sm2_curve.ndigits);
	if(vli_cmp((u64 *)rand, k, sm2_curve.ndigits) == 0)
	{
		goto loop;
	}
	#endif
	//A6-- s = ( (1+d)^-1 * (k-r*d) )mod n
	ecc_bytes2native(pri, prikey, sm2_curve.ndigits);
	/* s = r*d */
	vli_mod_mult(s, r, pri, sm2_curve.n, sm2_curve.ndigits);
	/* k-r*d */
	vli_mod_sub(s, k, s, sm2_curve.n, sm2_curve.ndigits);
	/* 1+d */
	vli_mod_add(pri, pri, one, sm2_curve.n, sm2_curve.ndigits);
	/* (1+d)^-1 */
	vli_mod_inv(pri, pri, sm2_curve.n, sm2_curve.ndigits);

	vli_mod_mult(s, pri, s, sm2_curve.n, sm2_curve.ndigits);

	#ifndef TEST_MODE
	//if s == 0, goto A3
	if(vli_is_zero(s, sm2_curve.ndigits))
	{
		goto loop;
	}
	#endif
	//A7 --transform to bit-string
	ecc_native2bytes(r_, r, sm2_curve.ndigits);
	ecc_native2bytes(s_, s, sm2_curve.ndigits);

	return 1;
}

/*
  vertify digst(r',s')
  B1-- r'（[1, n-1]
  B2-- s'（ [1, n-1]
  B3-- M'- = Za || M'
  B4-- e' = H256(M'-)
  B5-- t = (r' + s')modn
  B6-- (x1', y1') = [s']G + [t]Pa
  B7-- R = (e' + x1')modn
  R =? r'
 */
int sm2_verify(ecc_point *pubkey, u8 *msg, u32 len, u8 *r_, u8 *s_)
{
	ecc_point result;
	ecc_point pub[1];
	u64 t[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];

	u8 e[32];

	u8 Za[32];

	ecc_bytes2native(pub->x, pubkey->x, sm2_curve.ndigits);
	ecc_bytes2native(pub->y, pubkey->y, sm2_curve.ndigits);
	ecc_bytes2native(r, r_, sm2_curve.ndigits);
	ecc_bytes2native(s, s_, sm2_curve.ndigits);

	//B1--  r > 0, s > 0
	if(vli_is_zero(r, sm2_curve.ndigits) || vli_is_zero(s, sm2_curve.ndigits))
	{
		/* r, s must not be 0. */
		return -1;
	}
	//B1--  r < n, r < n
	if(vli_cmp(sm2_curve.n, r, sm2_curve.ndigits) != 1
	        || vli_cmp(sm2_curve.n, s, sm2_curve.ndigits) != 1)
	{
		/* r, s must be < n. */
		return -1;
	}

	//B3-- Za = H256(ENTL || IDa || a || b || Xg || Yg || Xa || Ya)
	sm3_z(USER_ID, 16, pubkey, Za);

	//B4-- e' = H256(Za || M)
	sm3_e(Za, msg, len, e);

	// B5-- t = (r' + s') mod n
	vli_mod_add(t, r, s, sm2_curve.n, sm2_curve.ndigits);
	if(vli_is_zero(t, sm2_curve.ndigits))
	{
		return -1;
	}
	//B6-- (x1', y1') = [s']G + [t]Pa
	ecc_point_mult2(&sm2_curve, &result, &sm2_curve.g, pub, s, t);

	/*B7-- R = (e' + x1') (mod n) */
	ecc_bytes2native((u64 *)e, e, sm2_curve.ndigits);
	vli_mod_add(result.x, result.x, (u64 *)e, sm2_curve.n, sm2_curve.ndigits);
	if(vli_cmp(sm2_curve.n, result.x, sm2_curve.ndigits) != 1)
	{
		vli_sub(result.x, result.x, sm2_curve.n, sm2_curve.ndigits);
	}

	/* Accept only if v == r. */
	return vli_cmp(result.x, r, sm2_curve.ndigits);
}


/*x2_ = 2^w + (x2 &(2^w-1))*/
static void sm2_w(u64 *result, u64 *x)
{
	result[0] = x[0];
	result[1] = x[1];
	result[2] = 0;
	result[3] = 0;

	u8 *p = (u8 *)(result + 1);
	*(p + 7) |= 0x80;
}

static int sm2_kdf_v(ecc_point *point, u8 *ZA, u8 *ZB, u32 keyLen, u8 *key)
{
	static u8 Z[ECC_NUMWORD * 4];
	memcpy(Z, point->x, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD, point->y, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD * 2, ZA, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD * 3, ZB, ECC_NUMWORD);
	sm3_kdf(Z, ECC_NUMWORD * 4, key, keyLen);
	return 0;
}

//S = Hash(0x02 || yv || Hash(xv || Za || Zb || x1 || y1 || x2 || y2))
int sm3_s(u8 tag,  u8 *za, u8 *zb,
          ecc_point *u, ecc_point *a, ecc_point *b,
          u8 *s)
{
	sm3_ctx md[1];
	u8 hash[32];
	u8 flag = tag;

	sm3_init(md);
	sm3_update(md, (u8 *)(u->x), 32);
	sm3_update(md, za, 32);
	sm3_update(md, zb, 32);
	sm3_update(md, (u8 *)a->x, 32);
	sm3_update(md, (u8 *)a->y, 32);
	sm3_update(md, (u8 *)b->x, 32);
	sm3_update(md, (u8 *)b->y, 32);
	sm3_final(md, hash);

	sm3_init(md);
	sm3_update(md, &flag, 1);
	sm3_update(md, (u8 *)u->y, 32);
	sm3_update(md, hash, 32);
	sm3_final(md, s);
	return 0;
}

//A1-- ra （[1, n-1]
//A2-- Ra = [ra]G = (x1, y1)
//A3-- send 'Ra' to UserB
int sm2_ke_init_i(u8 *ra, ecc_point *Ra)
{
	//A2-- Ra(x1,y1) = [ra]G
	return sm2_make_pubkey(ra, Ra);
}

//B1-- rb （[1, n-1]
//B2-- Rb(x2,y2) = [rb]G
//B3-- x2_ = 2^127 + (x2 & (2^127 -1))
//B4-- tb = (db + x2 * rb) modn;
//B5-- test Ra(x1,y1)
//B6 V(xv,yv) = [h * tb](Pa + [x1_]Ra)
//B7-- KDF(xv || yV || Za || Zb,klen)
//B8-- Sb = Hash(0x02 || yv || Hash(xv || Za || Zb || x1 || y1 || x2 || y2))
//B9-- sent 'Rb' 'Sb' to UserA
int sm2_ke_re_i(u8 *rb, u8 *db,
                ecc_point *Ra, ecc_point *Pa,
                u8 *Za, u8 *Zb,
                ecc_point *V,
                u8 *K, u32 klen,
                ecc_point *Rb, u8 *Sb)
{
	//B2-- Rb(x2,y2) = [rb]G
	ecc_point Rb_[1];
	sm2_make_pubkey(rb, Rb);

	ecc_bytes2native(Rb_->x, Rb->x, sm2_curve.ndigits);
	ecc_bytes2native(Rb_->y, Rb->y, sm2_curve.ndigits);

	//B3-- x2_ = 2^127 + (x2 & (2^127 -1))
	u64 x2_[ECC_MAX_DIGITS];
	sm2_w(x2_, Rb_->x);

	//B4-- tb = (db + x2 * rb) modn;
	u64 rb_[4];
	u64 db_[4];
	u64 tmp_[4];
	u64 tb_[4];
	ecc_bytes2native(rb_, rb, sm2_curve.ndigits);
	ecc_bytes2native(db_, db, sm2_curve.ndigits);
	vli_mod_mult(tmp_, x2_, rb_, sm2_curve.n, sm2_curve.ndigits);
	vli_mod_add(tb_, db_, tmp_, sm2_curve.n, sm2_curve.ndigits);

	//B5-- test Ra(x1,y1)
	ecc_point Ra_[1];
	ecc_bytes2native(Ra_->x, Ra->x, sm2_curve.ndigits);
	ecc_bytes2native(Ra_->y, Ra->y, sm2_curve.ndigits);

	if(sm2_valid_public_key(Ra_) != 1)
	{
		return -1;
	}
	//B5 -- x1_ = 2^127 + (x1 & (2^127 -1))
	u64 x1_[4];
	sm2_w(x1_, Ra_->x);

	//B6 V(xv,yv) = [h * tb](Pa + [x1_]Ra)
	ecc_point tmp1_[1];
	ecc_point_mult(&sm2_curve, tmp1_, Ra_, x1_, NULL);

	ecc_point Pa_[1];
	ecc_bytes2native(Pa_->x, Pa->x, sm2_curve.ndigits);
	ecc_bytes2native(Pa_->y, Pa->y, sm2_curve.ndigits);

	ecc_point_add(&sm2_curve, tmp1_, Pa_, tmp1_);

	vli_mult(tb_, tb_, sm2_curve.h, sm2_curve.ndigits);
	ecc_point V_[1];
	ecc_point_mult(&sm2_curve, V_, tmp1_, tb_, NULL);
	ecc_native2bytes(V->x, V_->x, sm2_curve.ndigits);
	ecc_native2bytes(V->y, V_->y, sm2_curve.ndigits);

	//B7-- KDF(xv || yV || Za || Zb,klen)
	sm2_kdf_v(V, Za, Zb, klen, K);

	//B8-- Sb = Hash(0x02 || yv || Hash(xv || Za || Zb || x1 || y1 || x2 || y2))
	sm3_s(0x02, Za, Zb, V, Ra, Rb, Sb);
	return 0;
}
//A4-- Ra(x1,y1); x1_ = 2^w + (x1 & 2^w -1)
//A5-- ta = (da + x1 * ra) mod n
//A6-- Rb(x2,y2); x2_ = 2^w + x2 & (2^w -1)
//A7-- u = [h * ta](Pb + [x2_]Rb)== (xv,yv)
//A8--Ka = KDF(xv || yv || Za || Zb , klen)
//A9--S1 = Hash(0x02 || yv || Hash(xv || Za || Zb || x1 || y1 || x2 || y2))
//A9-- S1 =?Sb
//A10--Sa = Hash(0x03 || yv || Hash(xv || ZA || ZB || x1 || y1 || x2 || y2))
//        sent 'Sa' to UserB
int sm2_ke_init_ii(u8 *ra, u8 *da,
                   ecc_point *Ra, ecc_point *Rb, ecc_point *Pb,
                   u8 *Za, u8 *Zb,
                   u8 *Sb,
                   u8 *K, u32 klen,
                   u8 *Sa)
{
	//B2-- Rb(x2,y2) = [rb]G
	ecc_point Ra_[1];

	ecc_bytes2native(Ra_->x, Ra->x, sm2_curve.ndigits);
	ecc_bytes2native(Ra_->y, Ra->y, sm2_curve.ndigits);

	u64 x1_[ECC_MAX_DIGITS];
	sm2_w(x1_, Ra_->x);

	//A5-- ta = (da + x1 * ra) mod n
	u64 ra_[4];
	u64 da_[4];
	u64 tmp_[4];
	u64 ta_[4];
	ecc_bytes2native(ra_, ra, sm2_curve.ndigits);
	ecc_bytes2native(da_, da, sm2_curve.ndigits);
	vli_mod_mult(tmp_, x1_, ra_, sm2_curve.n, sm2_curve.ndigits);
	vli_mod_add(ta_, da_, tmp_, sm2_curve.n, sm2_curve.ndigits);


	//A6-- Rb(x2,y2); x2_ = 2^w + x2 & (2^w -1)
	ecc_point Rb_[1];
	u64 x2_[4];
	ecc_bytes2native(Rb_->x, Rb->x, sm2_curve.ndigits);
	ecc_bytes2native(Rb_->y, Rb->y, sm2_curve.ndigits);
	if(sm2_valid_public_key(Rb_) != 1)
	{
		return -1;
	}

	sm2_w(x2_, Rb_->x);

	//A7-- u = [h * ta](Pb + [x2_]Rb)== (xv,yv)
	ecc_point tmp1_[1];
	ecc_point_mult(&sm2_curve, tmp1_, Rb_, x2_, NULL);

	ecc_point Pb_[1];
	ecc_bytes2native(Pb_->x, Pb->x, sm2_curve.ndigits);
	ecc_bytes2native(Pb_->y, Pb->y, sm2_curve.ndigits);
	ecc_point_add(&sm2_curve, tmp1_, Pb_, tmp1_);

	vli_mult(ta_, ta_, sm2_curve.h, sm2_curve.ndigits);
	ecc_point U_[1];
	ecc_point_mult(&sm2_curve, U_, tmp1_, ta_, NULL);

	ecc_point U[1];
	ecc_native2bytes(U->x, U_->x, sm2_curve.ndigits);
	ecc_native2bytes(U->y, U_->y, sm2_curve.ndigits);

	//A8--Ka = KDF(xv || yv || Za || Zb , klen)
	sm2_kdf_v(U, Za, Zb, klen, K);

	//A9--S1 = Hash(0x02 || yu || Hash(xu || ZA || ZB || x1 || y1 || x2 || y2))
	u8 S1[32];
	sm3_s(0x02, Za, Zb, U, Ra, Rb, S1);
	//A9-- S1 =?Sb
	if(vli_cmp((u64 *)S1, (u64 *)Sb, 4) != 0)
	{
		return -1;
	}

	//A10--Sa = Hash(0x03 || yu || Hash(xu || ZA || ZB || x1 || y1 || x2 || y2))
	sm3_s(0x03, Za, Zb, U, Ra, Rb, Sa);
	return 0;
}

//B10-- S2 = Hash(0x03 || yv || Hash(xv || ZA || ZB || x1 || y1 || x2 || y2))
//B10-- S1 =? Sa
int sm2_ke_re_ii(ecc_point *V, ecc_point *Ra, ecc_point *Rb,
                 u8 *Za, u8 *Zb,
                 u8 *Sa)
{
	u8 S2[32];
	sm3_s(0x03, Za, Zb, V, Ra, Rb, S2);

	if(vli_cmp((u64 *)S2, (u64 *)Sa, 4) == 0)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

/* Hash(x2 || M || y2)*/
void sm3_c3(ecc_point *p, u8 *msg, u32 len, u8 *hash)
{
	sm3_ctx md[1];
	sm3_init(md);
	sm3_update(md, (u8 *)p->x, ECC_NUMWORD);
	sm3_update(md, msg, len);
	sm3_update(md, (u8 *)p->y, ECC_NUMWORD);
	sm3_final(md, hash);
}

int sm2_encrypt(ecc_point *pubKey, u8 *msg, u32 len,  u8 *C, u32 *Clen)
{
	u64 k[ECC_MAX_DIGITS];
	u8 *t = NULL;
	ecc_point pub[1];
	ecc_point *C1 = (ecc_point *)C;
	u8 *C3 = C + ECC_NUMWORD * 2;
	u8 *C2 = C + ECC_NUMWORD * 2 + SM3_DATA_LEN;

	ecc_point kP;

	int i = 0;

	ecc_bytes2native(pub->x, pubKey->x, sm2_curve.ndigits);
	ecc_bytes2native(pub->y, pubKey->y, sm2_curve.ndigits);

	//A1--   k （ [1, n-1]
	#ifdef TEST_MODE
	u8 rand[] =
	{
		0x59, 0x27, 0x6e, 0x27,
		0xd5, 0x06, 0x86, 0x1a,
		0x16, 0x68, 0x0f, 0x3a,
		0xd9, 0xc0, 0x2d, 0xcc,
		0xef, 0x3c, 0xc1, 0xfa,
		0x3c, 0xdb, 0xe4, 0xce,
		0x6d, 0x54, 0xb8, 0x0d,
		0xea, 0xc1, 0xbc, 0x21
	};
	ecc_bytes2native(k, rand, sm2_curve.ndigits);
	#else
	u8 rand[32];
loop:
	vli_get_random(rand, ECC_NUMWORD);
	//k > 0
	if(vli_is_zero((u64 *)rand, sm2_curve.ndigits))
	{
		goto loop;
	}

	vli_set(k, (u64 *)rand, sm2_curve.ndigits);
	//k < n
	if(vli_cmp(sm2_curve.n, k, sm2_curve.ndigits) != 1)
	{
		goto loop;
	}
	#endif

	/*A2-- C1(x1, y1) = k * G */
	ecc_point_mult(&sm2_curve, C1, &sm2_curve.g, k, NULL);
	ecc_native2bytes(C1->x, C1->x, sm2_curve.ndigits);
	ecc_native2bytes(C1->y, C1->y, sm2_curve.ndigits);

	/*A3-- S = h * Pb */
	ecc_point S;
	ecc_point_mult(&sm2_curve, &S, pub, sm2_curve.h, NULL);
	if(sm2_valid_public_key(&S) != 1)
	{
		return -1;
	}

	/*A4-- kP(x2, y2) = k * Pb */
	ecc_point_mult(&sm2_curve, &kP, pub, k, NULL);

	/*A5-- t=KDF(x2 ||y2, klen) */
	if(vli_is_zero(kP.x, sm2_curve.ndigits) | vli_is_zero(kP.y, sm2_curve.ndigits))
	{
		return -1;
	}
	ecc_native2bytes(kP.x, kP.x, sm2_curve.ndigits);
	ecc_native2bytes(kP.y, kP.y, sm2_curve.ndigits);

	t = (u8 *)calloc(len, 1);
	if(t == NULL)
	{
		return -1;
	}

	sm3_kdf((u8 *)(kP.x), ECC_NUMWORD * 2,  t, len);


	/*A6-- C2 = M ox t */
	for(i = 0; i < len; i++)
	{
		C2[i] = msg[i] ^ t[+i];
	}
	free(t);


	t = NULL;
	/*A7-- C3 = Hash(x2 || M || y2)*/
	sm3_c3(&kP, msg, len, C3);

	if(Clen)
		*Clen = len + ECC_NUMWORD * 2 + SM3_DATA_LEN;

	return 0;
}
int sm2_decrypt(u8 *prikey, u8 *C, u32 Clen, u8 *M, u32 *Mlen)
{
	u8 hash[SM3_DATA_LEN];
	u64 pri[ECC_MAX_DIGITS];
	ecc_point *C1 = (ecc_point *)C;
	u8 *C3 = C + ECC_NUMWORD * 2;
	u8 *C2 = C + ECC_NUMWORD * 2 + SM3_DATA_LEN ;
	ecc_point dB[1];

	int outlen = Clen - ECC_NUMWORD * 2 - SM3_DATA_LEN;
	int i = 0;

	//B1-- C1= (x2,y2)
	ecc_bytes2native(C1->x, C1->x, sm2_curve.ndigits);
	ecc_bytes2native(C1->y, C1->y, sm2_curve.ndigits);

	if(sm2_valid_public_key(C1) != 1)
		return -1;



	//B2 -- S = [h]C1
	ecc_point S;
	ecc_point_mult(&sm2_curve, &S, C1, sm2_curve.h, NULL);

	if(sm2_valid_public_key(&S) != 1)
	{
		return -1;
	}

	//B3-- [dB]C1 (x2,y2)
	ecc_bytes2native(pri, prikey, sm2_curve.ndigits);
	ecc_point_mult(&sm2_curve, dB, C1, pri, NULL);

	if(vli_is_zero(dB->x, sm2_curve.ndigits) | vli_is_zero(dB->y, sm2_curve.ndigits))
	{
		return -1;
	}

	//t = KDF(x2 || y2, klen)
	ecc_native2bytes(dB->x, dB->x, sm2_curve.ndigits);
	ecc_native2bytes(dB->y, dB->y, sm2_curve.ndigits);
	sm3_kdf((u8 *)dB, ECC_NUMWORD * 2, M, outlen);

	for(i = 0; i < outlen; i++)
		M[i] = C2[i] ^ M[i];


	sm3_c3(dB, M, outlen, hash);

	*Mlen = outlen;
	if(memcmp(hash, C3, SM3_DATA_LEN) != 0)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}


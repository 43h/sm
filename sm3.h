#ifndef _SM3_H_
#define _SM3_H_

#include "typedef.h"

//date len 256 bit--32 byte
#define SM3_DATA_LEN	32

typedef struct sm3_ctx
{
	u32 total[2];    /*!< number of bytes processed  */
	u32 state[8];    /*!< intermediate digest state  */
	u8  buffer[64];   /*!< data block being processed */
} sm3_ctx;

int sm3_init(sm3_ctx *ctx);
int sm3_update(sm3_ctx *ctx, const u8 *input, u32 ilen);
int sm3_final(sm3_ctx *ctx, u8 *output);
int sm3(const u8 *data, u32 len, u8 *out);

#endif

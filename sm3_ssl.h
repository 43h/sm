#ifndef _SM3_SSL_H_
#define _SM3_SSL_H_
#include <inttypes.h>
#include <stddef.h>

#define SM3_DIGEST_LENGTH 32
#define SM3_WORD unsigned int

#define SM3_CBLOCK      64
#define SM3_LBLOCK      (SM3_CBLOCK/4)

int SM3(const void *data, size_t len, uint8_t *hash);

#endif

#ifndef _BCH_H
#define _BCH_H

#include <stdint.h>

void prepare_ecc_buff(uint32_t *ecc_buff, const uint8_t *recv_ecc);

int decode_bch_const(uint8_t *data, uint32_t *ecc_buff, unsigned int len);

void encode_bch(uint32_t *ecc_buf, const uint8_t *data, unsigned int len, uint8_t *ecc);

#endif /* _BCH_H */

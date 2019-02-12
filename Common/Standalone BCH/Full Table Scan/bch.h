/*
 * Generic binary BCH encoding/decoding library
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright © 2011 Parrot S.A.
 *
 * Author: Ivan Djelic <ivan.djelic@parrot.com>
 *
 * Description:
 *
 * This library provides runtime configurable encoding/decoding of binary
 * Bose-Chaudhuri-Hocquenghem (BCH) codes.
*/
#ifndef _BCH_H
#define _BCH_H

//#if defined(__KERNEL__)
//#include <linux/types.h>
//#else
#include <stdint.h>
//#endif

void prepare_ecc_buff(uint32_t *ecc_buff, const uint8_t *recv_ecc);

int decode_bch_const(uint8_t *data, uint32_t *ecc_buff, unsigned int len);

void encode_bch(uint32_t *ecc_buf, const uint8_t *data, unsigned int len, uint8_t *ecc);

#endif /* _BCH_H */

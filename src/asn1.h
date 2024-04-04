/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASN1_H_
#define _ASN1_H_

#include <stdlib.h>
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#else
#include <stdint.h>
#include <stdbool.h>
#endif

typedef struct asn1_ctx {
    uint8_t *data;
    uint16_t len;
} asn1_ctx_t;

extern int asn1_ctx_init(uint8_t *, uint16_t, asn1_ctx_t *);
extern int asn1_ctx_clear(asn1_ctx_t *ctx);
extern uint16_t asn1_len(asn1_ctx_t *ctx);
extern uint32_t asn1_get_uint(asn1_ctx_t *ctx);

extern int walk_tlv(const asn1_ctx_t *ctxi,
                    uint8_t **p,
                    uint16_t *tag,
                    uint16_t *tag_len,
                    uint8_t **data);
extern uint8_t format_tlv_len(uint16_t len, uint8_t *out);
extern bool asn1_find_tag(const asn1_ctx_t *ctxi,
                          uint16_t itag,
                          asn1_ctx_t *ctxo);
extern uint16_t asn1_len_tag(uint16_t tag, uint16_t len);

#endif

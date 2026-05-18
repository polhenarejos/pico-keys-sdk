/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _TLV_H_
#define _TLV_H_

#include <stdint.h>
#include <stdbool.h>
#include "compat/compat.h"

PACK(
typedef struct tlv_ctx {
    uint8_t *data;
    uint16_t len;
}) tlv_ctx_t;

extern int tlv_ctx_init(uint8_t *, uint16_t, tlv_ctx_t *);
extern int tlv_ctx_clear(tlv_ctx_t *ctx);
extern uint16_t tlv_len(tlv_ctx_t *ctx);
extern uint32_t tlv_get_uint(tlv_ctx_t *ctx);

extern int tlv_walk(const tlv_ctx_t *ctxi, uint8_t **p, uint16_t *tag, uint16_t *tag_len, uint8_t **data);
extern uint8_t tlv_format_len(uint16_t len, uint8_t *out);
extern bool tlv_find_tag(const tlv_ctx_t *ctxi, uint16_t itag, tlv_ctx_t *ctxo);
extern uint16_t tlv_len_tag(uint16_t tag, uint16_t len);

#endif

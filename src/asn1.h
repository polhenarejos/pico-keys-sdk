/*
 * This file is part of the Pico HSM SDK distribution (https://github.com/polhenarejos/pico-hsm-sdk).
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
#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#else
#include <stdint.h>
#include <stdbool.h>
#endif

extern int walk_tlv(const uint8_t *cdata, size_t cdata_len, uint8_t **p, uint16_t *tag, size_t *tag_len, uint8_t **data);
extern int format_tlv_len(size_t len, uint8_t *out);
extern bool asn1_find_tag(const uint8_t *data, size_t data_len, uint16_t itag, size_t *tag_len, uint8_t **tag_data);
extern size_t asn1_len_tag(uint16_t tag, size_t len);

#endif

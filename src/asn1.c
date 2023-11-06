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

#include "asn1.h"

size_t asn1_len_tag(uint16_t tag, size_t len) {
    size_t ret = 1 + format_tlv_len(len, NULL) + len;
    if (tag > 0x00ff) {
        return ret + 1;
    }
    return ret;
}

int format_tlv_len(size_t len, uint8_t *out) {
    if (len < 128) {
        if (out) {
            *out = len;
        }
        return 1;
    }
    else if (len < 256) {
        if (out) {
            *out++ = 0x81;
            *out++ = len;
        }
        return 2;
    }
    else {
        if (out) {
            *out++ = 0x82;
            *out++ = (len >> 8) & 0xff;
            *out++ = len & 0xff;
        }
        return 3;
    }
    return 0;
}

int walk_tlv(const uint8_t *cdata,
             size_t cdata_len,
             uint8_t **p,
             uint16_t *tag,
             size_t *tag_len,
             uint8_t **data) {
    if (!p) {
        return 0;
    }
    if (!*p) {
        *p = (uint8_t *) cdata;
    }
    if (*p - cdata >= cdata_len) {
        return 0;
    }
    uint16_t tg = 0x0;
    size_t tgl = 0;
    tg = *(*p)++;
    if ((tg & 0x1f) == 0x1f) {
        tg <<= 8;
        tg |= *(*p)++;
    }
    tgl = *(*p)++;
    if (tgl == 0x82) {
        tgl = *(*p)++ << 8;
        tgl |= *(*p)++;
    }
    else if (tgl == 0x81) {
        tgl = *(*p)++;
    }
    if (tag) {
        *tag = tg;
    }
    if (tag_len) {
        *tag_len = tgl;
    }
    if (data) {
        *data = *p;
    }
    *p = *p + tgl;
    return 1;
}

bool asn1_find_tag(const uint8_t *data,
                   size_t data_len,
                   uint16_t itag,
                   size_t *tag_len,
                   uint8_t **tag_data) {
    uint16_t tag = 0x0;
    uint8_t *p = NULL;
    uint8_t *tdata = NULL;
    size_t tlen = 0;
    while (walk_tlv(data, data_len, &p, &tag, &tlen, &tdata)) {
        if (itag == tag) {
            if (tag_data != NULL) {
                *tag_data = tdata;
            }
            if (tag_len != NULL) {
                *tag_len = tlen;
            }
            return true;
        }
    }
    return false;
}

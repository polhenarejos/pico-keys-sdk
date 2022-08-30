/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
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

#ifndef _APDU_H_
#define _APDU_H_

#include <stdlib.h>
#include "pico/stdlib.h"

typedef struct app {
    const uint8_t *aid;
    int (*process_apdu)();
    struct app* (*select_aid)();
    int (*unload)();
} app_t;

extern int register_app(app_t * (*)());

#if defined(DEBUG_APDU) && DEBUG_APDU == 1
#define DEBUG_PAYLOAD(_p,_s) { \
    printf("Payload %s (%d bytes):\r\n", #_p,_s);\
    for (int _i = 0; _i < _s; _i += 16) {\
        printf("%07Xh : ",(unsigned int)(_i+_p));\
        for (int _j = 0; _j < 16; _j++) {\
            if (_j < _s-_i) printf("%02X ",(_p)[_i+_j]);\
            else printf("   ");\
            if (_j == 7) printf(" ");\
            } printf(":  "); \
        for (int _j = 0; _j < MIN(16,_s-_i); _j++) {\
            printf("%c",(_p)[_i+_j] == 0x0a || (_p)[_i+_j] == 0x0d ? '\\' : (_p)[_i+_j]);\
            if (_j == 7) printf(" ");\
            }\
            printf("\r\n");\
        } printf("\r\n"); \
    }
#else
#define DEBUG_PAYLOAD(_p,_s)
#endif

extern uint8_t num_apps;
extern app_t apps[4];
extern app_t *current_app;

struct apdu {
    uint8_t *header;
    uint32_t nc;
    uint32_t ne;
    uint8_t *data;
    uint16_t sw;
    uint8_t *rdata;
    uint16_t rlen;
} __packed;

#define CLA(a) a.header[0]
#define INS(a) a.header[1]
#define P1(a) a.header[2]
#define P2(a) a.header[3]

#define res_APDU apdu.rdata
#define res_APDU_size apdu.rlen

extern struct apdu apdu;

extern uint16_t set_res_sw (uint8_t sw1, uint8_t sw2);
extern int process_apdu();
extern size_t apdu_process(const uint8_t *buffer, size_t buffer_size);
extern void apdu_finish();
extern size_t apdu_next();

#endif

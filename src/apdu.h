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

#ifndef _APDU_H_
#define _APDU_H_

#include <stdlib.h>
#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#endif
#include <stdio.h>
#include <inttypes.h>

typedef struct app {
    const uint8_t *aid;
    int (*process_apdu)();
    struct app * (*select_aid)(struct app *, const uint8_t *, uint8_t);
    int (*unload)();
} app_t;

extern int register_app(app_t *(*)(app_t *, const uint8_t *, uint8_t));

typedef struct cmd {
    uint8_t ins;
    int (*cmd_handler)();
} cmd_t;


#if defined(DEBUG_APDU) && DEBUG_APDU == 1
#define DEBUG_PAYLOAD(_p, _s) { \
        printf("Payload %s (%d bytes):\r\n", #_p, (int) (_s)); \
        for (int _i = 0; _i < _s; _i += 16) { \
            printf("%" PRIxPTR "h : ", (uintptr_t) (_i+_p)); \
            for (int _j = 0; _j < 16; _j++) { \
                if (_j < _s-_i) printf("%02X ", (_p)[_i+_j]); \
                else printf("   "); \
                if (_j == 7) printf(" "); \
            } printf(":  "); \
            printf("\r\n"); \
        } printf("\r\n"); \
}
#define DEBUG_DATA(_p, _s)                               \
    {                                                    \
        printf("Data %s (%d bytes):\r\n", #_p, (int) (_s));      \
        char *tmp = (char *) calloc(1, 2 * _s + 1); \
        for (int _i = 0; _i < _s; _i++)                  \
        {                                                \
            sprintf(&tmp[2 * _i], "%02X", (_p)[_i]);       \
        }                                                \
        printf("%s\n", tmp);                             \
        free(tmp);                                       \
    }

#else
#define DEBUG_PAYLOAD(_p, _s)
#define DEBUG_DATA(_p, _s)
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
} __attribute__((__packed__));

#define CLA(a) a.header[0]
#define INS(a) a.header[1]
#define P1(a) a.header[2]
#define P2(a) a.header[3]

#define res_APDU (apdu.rdata)
#define res_APDU_size (apdu.rlen)

extern struct apdu apdu;

extern uint16_t set_res_sw(uint8_t sw1, uint8_t sw2);
extern int process_apdu();
extern size_t apdu_process(uint8_t, const uint8_t *buffer, size_t buffer_size);
extern void apdu_finish();
extern size_t apdu_next();
extern void apdu_thread();

#endif

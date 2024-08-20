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

#ifndef _APDU_H_
#define _APDU_H_

#include <stdlib.h>
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#endif
#include "compat.h"
#include <stdio.h>
#include <inttypes.h>

typedef struct app {
    const uint8_t *aid;
    int (*process_apdu)();
    int (*select_aid)(struct app *);
    int (*unload)();
} app_t;

extern int register_app(int (*)(app_t *), const uint8_t *);
extern int select_app(const uint8_t *aid, size_t aid_len);

typedef struct cmd {
    uint8_t ins;
    int (*cmd_handler)();
} cmd_t;


#if defined(DEBUG_APDU) && DEBUG_APDU == 1
#define DEBUG_PAYLOAD(_p, _s) { \
        printf("Payload %s (%d bytes):\n", #_p, (int) (_s)); \
        for (int _i = 0; _i < _s; _i += 16) { \
            printf("%" PRIxPTR "h : ", (uintptr_t) (_i + _p)); \
            for (int _j = 0; _j < 16; _j++) { \
                if (_j < _s - _i) printf("%02X ", (_p)[_i + _j]); \
                else printf("   "); \
                if (_j == 7) printf(" "); \
            } printf(":  "); \
            for (int _j = 0; _j < 16; _j++) { \
                if (_j < _s - _i && (_p)[_i + _j] > 32 && (_p)[_i + _j] != 127 && (_p)[_i + _j] < 176) printf("%c", (_p)[_i + _j]); \
                else printf(" "); \
                if (_j == 7) printf(" "); \
            } \
            printf("\n"); \
        } printf("\n"); \
}
#define DEBUG_DATA(_p, _s)                               \
    {                                                    \
        printf("Data %s (%d bytes):\n", #_p, (int) (_s));      \
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

PACK(struct apdu {
    uint8_t *header;
    uint32_t nc;
    uint32_t ne;
    uint8_t *data;
    uint16_t sw;
    uint8_t *rdata;
    uint16_t rlen;

});

#define CLA(a) a.header[0]
#define INS(a) a.header[1]
#define P1(a) a.header[2]
#define P2(a) a.header[3]

#define res_APDU (apdu.rdata)
#define res_APDU_size (apdu.rlen)

extern struct apdu apdu;

extern uint16_t set_res_sw(uint8_t sw1, uint8_t sw2);
extern int process_apdu();
extern uint16_t apdu_process(uint8_t, const uint8_t *buffer, uint16_t buffer_size);
extern void apdu_finish();
extern uint16_t apdu_next();
extern void apdu_thread();

#endif

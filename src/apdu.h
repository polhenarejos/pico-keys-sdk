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
    int (*select_aid)(struct app *, uint8_t);
    int (*unload)();
} app_t;

extern int register_app(int (*)(app_t *, uint8_t), const uint8_t *);
extern int select_app(const uint8_t *aid, size_t aid_len);

typedef struct cmd {
    uint8_t ins;
    int (*cmd_handler)();
} cmd_t;

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

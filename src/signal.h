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

#ifndef _SIGNAL_H_
#define _SIGNAL_H_

#include <stdint.h>

#define MAX_SIGNALS 32
#define MAX_NODES 4

static const uint8_t SIGNAL_NONE = 0;
static const uint8_t SIGNAL_BOOT = 1;
static const uint8_t SIGNAL_USB_MOUNTED = 2;
static const uint8_t SIGNAL_BUTTON_PRESS = 3;
static const uint8_t SIGNAL_BUTTON_RELEASE = 4;
static const uint8_t SIGNAL_USER_PRESENCE_REQUEST = 5;
static const uint8_t SIGNAL_USER_PRESENCE_COMPLETED = 6;
static const uint8_t SIGNAL_USER_PRESENCE_CANCELLED = 7;
static const uint8_t SIGNAL_USER_PRESENCE_TIMEOUT = 8;
static const uint8_t SIGNAL_INIT = 9;
static const uint8_t SIGNAL_RESCUE_NOT_FOUND = 10;

typedef enum {
    SIGNAL_FLAG_NONE = 0x0,
    SIGNAL_FLAG_ERROR_CONTINUE = 0x1,
    SIGNAL_FLAG_MAY_DUPLICATE = 0x2,
} signal_flag_t;

typedef int (*signal_handler_t)(uint8_t code, void *data);

typedef struct {
    uint32_t timeout;
} signal_user_presence_request_data_t;

typedef struct {
    signal_flag_t flags;
    signal_handler_t handler;
} signal_node_t;

typedef struct {
    signal_node_t nodes[MAX_NODES];
    uint8_t node_count;
} signal_t;

extern int signal_add(uint8_t code, signal_flag_t flags, signal_handler_t handler);
extern int signal_remove(uint8_t code, signal_handler_t handler);
extern int signal_emit_param(uint8_t code, void *data);
extern int signal_emit(uint8_t code);

#endif // _SIGNAL_H_

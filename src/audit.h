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

#ifndef _AUDIT_H_
#define _AUDIT_H_

#include <stdint.h>

static const uint8_t SIGNAL_AUDIT_EVT = 11;
#define AUDIT_EVT_APP_EVT   0x8000

typedef enum {
    AUDIT_EVT_LOG_READ = 0x0001,
    AUDIT_EVT_LOG_CLEARED,
    AUDIT_EVT_FIRMWARE_UPDATE,
    AUDIT_EVT_INIT,
    AUDIT_EVT_POWER_UP,
    AUDIT_EVT_SET_RTC,
} audit_evt_t;

typedef enum {
    AUDIT_EF_SUCCESS        = 0x0001,
    AUDIT_EF_FAIL           = 0x0002,
    AUDIT_EF_DENIED         = 0x0004,

    AUDIT_EF_USER           = 0x0010,
    AUDIT_EF_ADMIN          = 0x0020,

    AUDIT_EF_CRITICAL       = 0x0100,
    AUDIT_EF_TIME_UNSYNCED  = 0x0200,
} audit_entry_flags_t;

typedef enum {
    AUDIT_CMD_EVT = 1,
    AUDIT_CMD_SET_OBJECT = 2,
    AUDIT_CMD_SET_FLAGS = 3,
    AUDIT_CMD_LOG = 4
} audit_cmd_t;

typedef struct {
    audit_cmd_t cmd;
    uint16_t value;
} signal_audit_evt_data_t;

extern void audit_entry_set_current_event(uint16_t event);
extern void audit_entry_set_current_flags(audit_entry_flags_t flags);
extern void audit_entry_set_current_object(uint16_t object_id);
extern void audit_log_current_entry_with_result(uint16_t res);

#endif // _AUDIT_H_

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

#include "picokeys.h"
#include "signal.h"
#include "audit.h"

void audit_entry_set_current_event(uint16_t event) {
    signal_audit_evt_data_t data = {.cmd = AUDIT_CMD_EVT, .value = event};
    signal_emit_param(SIGNAL_AUDIT_EVT, &data);
}

void audit_log_current_entry_with_result(uint16_t result) {
    signal_audit_evt_data_t data = {.cmd = AUDIT_CMD_LOG, .value = result};
    signal_emit_param(SIGNAL_AUDIT_EVT, &data);
}

void audit_entry_set_current_flags(audit_entry_flags_t flags) {
    signal_audit_evt_data_t data = {.cmd = AUDIT_CMD_SET_FLAGS, .value = flags};
    signal_emit_param(SIGNAL_AUDIT_EVT, &data);
}
void audit_entry_set_current_object(uint16_t object_id) {
    signal_audit_evt_data_t data = {.cmd = AUDIT_CMD_SET_OBJECT, .value = object_id};
    signal_emit_param(SIGNAL_AUDIT_EVT, &data);
}

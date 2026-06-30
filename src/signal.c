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

static signal_t signals[MAX_SIGNALS] = {0};

int signal_add(uint8_t code, signal_flag_t flags, signal_handler_t handler) {
    if (code >= MAX_SIGNALS) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (handler == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (signals[code].node_count >= MAX_NODES) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (!(flags & SIGNAL_FLAG_MAY_DUPLICATE)) {
        for (int i = 0; i < MAX_NODES; i++) {
            if (signals[code].nodes[i].handler == handler) {
                return PICOKEYS_ERR_MEMORY_FATAL;
            }
        }
    }
    for (int i = 0; i < MAX_NODES; i++) {
        if (signals[code].nodes[i].handler == NULL) {
            signals[code].nodes[i].flags = flags;
            signals[code].nodes[i].handler = handler;
            signals[code].node_count++;
            return PICOKEYS_OK;
        }
    }
    return PICOKEYS_ERR_NO_MEMORY;
}

int signal_remove(uint8_t code, signal_handler_t handler) {
    if (code >= MAX_SIGNALS) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (handler == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (signals[code].node_count == 0) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    for (int i = 0; i < MAX_NODES; i++) {
        if (signals[code].nodes[i].handler == handler) {
            signals[code].nodes[i].flags = 0;
            signals[code].nodes[i].handler = NULL;
            signals[code].node_count--;
            return PICOKEYS_OK;
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

int signal_emit_param(uint8_t code, void *data) {
    if (code >= MAX_SIGNALS) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (signals[code].node_count == 0) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    for (int i = 0; i < MAX_NODES; i++) {
        if (signals[code].nodes[i].handler != NULL) {
            int ret = signals[code].nodes[i].handler(code, data);
            if (ret != 0 && (signals[code].nodes[i].flags & SIGNAL_FLAG_ERROR_CONTINUE) == 0) {
                return ret;
            }
        }
    }
    return PICOKEYS_OK;
}

int signal_emit(uint8_t code) {
    return signal_emit_param(code, NULL);
}

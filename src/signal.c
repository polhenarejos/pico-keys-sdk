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
static uint8_t num_signals = 0;

int signal_add(signal_code_t code, signal_flag_t flags, signal_handler_t handler) {
    if (num_signals >= MAX_SIGNALS) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (handler == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    signals[num_signals].code = code;
    signals[num_signals].flags = flags;
    signals[num_signals].handler = handler;
    num_signals++;
    return PICOKEYS_OK;
}

int signal_remove(signal_code_t code, signal_handler_t handler) {
    for (int i = 0; i < num_signals; i++) {
        if (signals[i].code == code && signals[i].handler == handler) {
            for (int j = i; j < num_signals - 1; j++) {
                signals[j] = signals[j + 1];
            }
            num_signals--;
            return PICOKEYS_OK;
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

int signal_emit_param(signal_code_t code, void *data) {
    for (int i = 0; i < num_signals; i++) {
        if (signals[i].code == code) {
            int ret = signals[i].handler(code, data);
            if (ret != 0 && (signals[i].flags & SIGNAL_FLAG_ERROR_CONTINUE) == 0) {
                return ret;
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

int signal_emit(signal_code_t code) {
    return signal_emit_param(code, NULL);
}

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

#ifndef _EAC_H_
#define _EAC_H_

#include "pico_keys.h"

typedef enum MSE_protocol {
    MSE_AES = 0,
    MSE_3DES,
    MSE_NONE
} MSE_protocol;

extern void sm_derive_all_keys(const uint8_t *input, size_t input_len);
extern void sm_set_protocol(MSE_protocol proto);
extern MSE_protocol sm_get_protocol();
extern uint8_t *sm_get_nonce();
extern int sm_sign(uint8_t *in, size_t in_len, uint8_t *out);
int sm_verify();
void sm_update_iv();
uint16_t sm_get_le();
extern int sm_unwrap();
uint16_t sm_remove_padding(const uint8_t *data, uint16_t data_len);
extern int sm_wrap();
extern bool is_secured_apdu();
extern uint8_t sm_session_pin[16];
extern uint16_t sm_session_pin_len;

#endif

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

#ifndef _OTP_PLATFORM_H_
#define _OTP_PLATFORM_H_

#include <stdint.h>
#include <stdbool.h>

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock);
bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey);
bool otp_platform_is_secure_boot_locked(void);
void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out);

#endif

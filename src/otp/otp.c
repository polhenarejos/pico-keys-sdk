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

#include "otp.h"
#include "otp_platform.h"
#include <stdlib.h>

const uint8_t *otp_key_1 = NULL;
const uint8_t *otp_key_2 = NULL;

int otp_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    return otp_platform_enable_secure_boot(bootkey, secure_lock);
}

bool otp_is_secure_boot_enabled(uint8_t *bootkey) {
    return otp_platform_is_secure_boot_enabled(bootkey);
}

bool otp_is_secure_boot_locked(void) {
    return otp_platform_is_secure_boot_locked();
}

void otp_init(void) {
    otp_platform_init(&otp_key_1, &otp_key_2);
}

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
#include "serial.h"
#include "mbedtls/sha256.h"
#if defined(ESP_PLATFORM)
#include "esp_efuse.h"
#endif
#include <stdio.h>

char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
uint8_t pico_serial_hash[32];
picokey_serial_t pico_serial;
#ifdef ESP_PLATFORM
#define pico_get_unique_board_id(a) do { uint32_t value; esp_efuse_read_block(EFUSE_BLK1, &value, 0, 32); memcpy((uint8_t *)(a), &value, sizeof(uint32_t)); esp_efuse_read_block(EFUSE_BLK1, &value, 32, 32); memcpy((uint8_t *)(a)+4, &value, sizeof(uint32_t)); } while(0)
#else
#ifndef PICO_PLATFORM
#define pico_get_unique_board_id(a) memset(a, 0, sizeof(*(a)))
#endif
#endif

void serial_init(void) {
    pico_get_unique_board_id(&pico_serial);
    memset(pico_serial_str, 0, sizeof(pico_serial_str));
    for (size_t i = 0; i < sizeof(pico_serial); i++) {
        snprintf(&pico_serial_str[2 * i], 3, "%02X", pico_serial.id[i]);
    }
    mbedtls_sha256(pico_serial.id, sizeof(pico_serial.id), pico_serial_hash, false);
}

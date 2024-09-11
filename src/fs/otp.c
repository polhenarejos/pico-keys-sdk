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

#include "file.h"
#include "pico_keys.h"
#include <stdio.h>
#include "otp.h"

#ifdef PICO_RP2350
#include "pico/bootrom.h"
#include "hardware/structs/otp.h"
#include "hardware/regs/otp_data.h"
#endif
#include "random.h"

#ifdef PICO_RP2350

static bool is_empty_buffer(const uint8_t *buffer, uint16_t buffer_len) {
    for (int i = 0; i < buffer_len; i++) {
        if (buffer[i] != 0x00) {
            return false;
        }
    }
    return true;
}

static int otp_write_data_mode(uint16_t row, uint8_t *data, uint16_t len, bool is_ecc) {
    otp_cmd_t cmd = { .flags = row | (is_ecc ? OTP_CMD_ECC_BITS : 0) | OTP_CMD_WRITE_BITS };
    uint32_t ret = rom_func_otp_access(data, len, cmd);
    if (ret) {
        printf("OTP Write failed with error: %ld\n", ret);
    }
    return ret;
}

static int otp_write_data(uint16_t row, uint8_t *data, uint16_t len) {
    return otp_write_data_mode(row, data, len, true);
}
/*
static int otp_write_data_raw(uint16_t row, uint8_t *data, uint16_t len) {
    return otp_write_data_mode(row, data, len, false);
}
*/
static uint8_t* otp_buffer(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_GUARDED_BASE + (row*2)));
    return (uint8_t *)p;
}

static bool is_empty_otp_buffer(uint16_t row, uint16_t len) {
    return is_empty_buffer(otp_buffer(row), len);
}

static bool is_otp_locked_page(uint8_t page) {
	volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + ((OTP_DATA_PAGE0_LOCK0_ROW + page*2)*2)));
    return ((p[0] & 0xFFFF0000) == 0x3C3C0000 && (p[1] & 0xFF) == 0x3C);
}

static void otp_lock_page(uint8_t page) {
    if (!is_otp_locked_page(page)) {
        uint32_t value = 0x3c3c3c;
        printf("Locking page %d, with row %d and value %lx\n", page, OTP_DATA_PAGE0_LOCK0_ROW + page*2 + 1, value);
        //otp_write_data_raw(OTP_DATA_PAGE0_LOCK0_ROW + page*2 + 1, (uint8_t *)&value, sizeof(value));
    }

    otp_hw->sw_lock[page] = 0b1100;
}
#endif

const uint8_t *otp_key_1 = NULL;
void init_otp_files() {
#ifdef PICO_RP2350

    uint8_t page = OTP_KEY_1 >> 6;
    if (is_empty_otp_buffer(OTP_KEY_1, 32)) {
        uint8_t mkek[32] = {0};
        random_gen(NULL, mkek, sizeof(mkek));
        otp_write_data(OTP_KEY_1, mkek, sizeof(mkek));
    }
    else {
        DEBUG_DATA(otp_buffer(OTP_KEY_1), 32);
    }
    otp_key_1 = otp_buffer(OTP_KEY_1);

    otp_lock_page(page);
#endif
}

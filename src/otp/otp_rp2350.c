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

#include <stdio.h>
#include <stdalign.h>
#include "picokeys.h"
#include "otp.h"
#include "otp_platform.h"

#include "pico/bootrom.h"
#include "hardware/structs/otp.h"
#include "hardware/regs/otp_data.h"

#include "random.h"
#include "mbedtls/ecdsa.h"

#define OTP_OLD_MKEK_ROW 0xEF0
#define OTP_OLD_DEVK_ROW 0xED0
#define OTP_MKEK_ROW     0xE90
#define OTP_DEVK_ROW     0xE80

#define OTP_KEY_1    OTP_MKEK_ROW
#define OTP_KEY_2    OTP_DEVK_ROW


static bool is_empty_buffer(const uint8_t *buffer, uint16_t buffer_len) {
    for (int i = 0; i < buffer_len; i++) {
        if (buffer[i] != 0x00) {
            return false;
        }
    }
    return true;
}

static int otp_write_data_mode(uint16_t row, const uint8_t *data, uint16_t len, bool is_ecc) {
    otp_cmd_t cmd = { .flags = row | (is_ecc ? OTP_CMD_ECC_BITS : 0) | OTP_CMD_WRITE_BITS };
    uint32_t ret = rom_func_otp_access((uint8_t *)data, len, cmd);
    if (ret) {
        printf("OTP Write failed with error: %ld\n", ret);
    }
    return ret;
}

static int otp_write_data(uint16_t row, const uint8_t *data, uint16_t len) {
    return otp_write_data_mode(row, data, len, true);
}

static int otp_write_data_raw(uint16_t row, const uint8_t *data, uint16_t len) {
    return otp_write_data_mode(row, data, len, false);
}

static const uint8_t* otp_buffer(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + (row*2)));
    return (const uint8_t *)p;
}

static const uint8_t* otp_buffer_raw(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_RAW_BASE + (row*4)));
    return (const uint8_t *)p;
}

static bool is_empty_otp_buffer(uint16_t row, uint16_t len) {
    return is_empty_buffer(otp_buffer_raw(row), len * 2);
}

static bool is_otp_locked_page(uint8_t page) {
	volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + ((OTP_DATA_PAGE0_LOCK0_ROW + page*2)*2)));
    return ((p[0] & 0xFFFF0000) == 0x3C3C0000 && (p[1] & 0xFF) == 0x3C);
}

static void otp_lock_page(uint8_t page) {
    if (!is_otp_locked_page(page)) {
        alignas(4) uint32_t value = 0x3c3c3c;
        otp_write_data_raw(OTP_DATA_PAGE0_LOCK0_ROW + page*2 + 1, (uint8_t *)&value, sizeof(value));
    }

    otp_hw->sw_lock[page] = 0b1100;
}

static void otp_invalidate_key(uint16_t row, uint16_t len) {
    if (!is_empty_otp_buffer(row, len)) {
        uint8_t *inval = (uint8_t *)calloc(len * 2, sizeof(uint8_t));
        if (inval) {
            memset(inval, 0xFF, len * 2);
            otp_write_data_raw(row, inval, len * 2);
            mbedtls_platform_zeroize(inval, len * 2);
            free(inval);
        }
    }
}

static int otp_chaff(uint16_t row, uint16_t len) {
    const uint8_t *raw = otp_buffer_raw(row);
    uint8_t *chaff = (uint8_t *)calloc(len * 2, sizeof(uint8_t));
    if (chaff) {
        memcpy(chaff, raw, len * 2);
        for (int i = 0; i < len * 2; i++) {
            chaff[i] ^= 0xFF;
        }
        int ret = otp_write_data_raw(row + 32, chaff, len * 2);
        mbedtls_platform_zeroize(chaff, len * 2);
        free(chaff);
        return ret;
    }
    return BOOTROM_ERROR_INVALID_STATE;
}

static int otp_migrate_key(uint16_t new_row, uint16_t old_row, uint16_t len) {
    if (is_empty_otp_buffer(new_row, len) && !is_empty_otp_buffer(old_row, len)) {
        const uint8_t *key = otp_buffer(old_row);
        uint8_t *new_key = (uint8_t *)calloc(len, sizeof(uint8_t));
        if (new_key) {
            memcpy(new_key, key, len);
            int ret = otp_write_data(new_row, new_key, len);
            if (ret == BOOTROM_OK) {
                otp_chaff(new_row, len);
                otp_invalidate_key(old_row, 32);
            }
            mbedtls_platform_zeroize(new_key, len);
            free(new_key);
            return ret;
        }
    }
    return BOOTROM_ERROR_INVALID_STATE;
}

static void otp_migrate_chaff(void) {
    otp_migrate_key(OTP_MKEK_ROW, OTP_OLD_MKEK_ROW, 32);
    otp_migrate_key(OTP_DEVK_ROW, OTP_OLD_DEVK_ROW, 32);
    otp_lock_page(OTP_MKEK_ROW >> 6);
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    const uint8_t *crit1 = otp_buffer(OTP_DATA_CRIT1_ROW);
    if ((crit1[0] & (1 << OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_LSB)) == 0) {
        return false;
    }
    alignas(2) uint8_t BOOTKEY[32] = {
        0xE1, 0xD1, 0x6B, 0xA7, 0x64, 0xAB, 0xD7, 0x12,
        0xD4, 0xEF, 0x6E, 0x3E, 0xDD, 0x74, 0x4E, 0xD5,
        0x63, 0x8C, 0x26, 0x0B, 0x77, 0x1C, 0xF9, 0x81,
        0x51, 0x11, 0x0B, 0xAF, 0xAC, 0x9B, 0xC8, 0x71
    };
    uint8_t bootkey_idx = 0;
    for (; bootkey_idx < 6; bootkey_idx++) {
        const uint8_t *bootkey_row = otp_buffer(OTP_DATA_BOOTKEY0_0_ROW + 0x10 * bootkey_idx);
        if (memcmp(bootkey_row, BOOTKEY, sizeof(BOOTKEY)) == 0) {
            break;
        }
    }
    if (bootkey_idx == 6) {
        return false;
    }
    const uint8_t *boot_flags1 = otp_buffer(OTP_DATA_BOOT_FLAGS1_ROW);
    if ((boot_flags1[0] & (1 << (bootkey_idx + OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB))) == 0) {
        return false;
    }
    if (bootkey) {
        *bootkey = bootkey_idx;
    }
    return true;
}

bool otp_platform_is_secure_boot_locked(void) {
    uint8_t bootkey_idx = 0xFF;
    if (otp_platform_is_secure_boot_enabled(&bootkey_idx) == false) {
        return false;
    }
    const uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    if ((boot_flags1[1] & ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey_idx)))) !=
        ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey_idx)))) {
        return false;
    }
    const uint8_t *crit1 = otp_buffer_raw(OTP_DATA_CRIT1_ROW);
    if ((crit1[0] & (1 << OTP_DATA_CRIT1_DEBUG_DISABLE_LSB)) == 0
        || (crit1[0] & (1 << OTP_DATA_CRIT1_GLITCH_DETECTOR_ENABLE_LSB)) == 0
        || ((crit1[0] & (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB)) != (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB))) {
        return false;
    }
    return bootkey_idx != 0xFF;
}

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    int ret = 0;

    alignas(2) uint8_t BOOTKEY[] = "\xe1\xd1\x6b\xa7\x64\xab\xd7\x12\xd4\xef\x6e\x3e\xdd\x74\x4e\xd5\x63\x8c\x26\xb\x77\x1c\xf9\x81\x51\x11\xb\xaf\xac\x9b\xc8\x71";
    if (is_empty_otp_buffer(OTP_DATA_BOOTKEY0_0_ROW + 0x10*bootkey, 32)) {
        PICOKEYS_CHECK(otp_write_data(OTP_DATA_BOOTKEY0_0_ROW + 0x10*bootkey, BOOTKEY, sizeof(BOOTKEY)));
    }

    const uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    alignas(4) uint8_t flagsb1[] = { boot_flags1[0] | (1 << (bootkey + OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB)), boot_flags1[1], boot_flags1[2], 0x00 };
    if (secure_lock) {
        flagsb1[1] |= ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey)));
    }

    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_BOOT_FLAGS1_ROW, flagsb1, sizeof(flagsb1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_BOOT_FLAGS1_R1_ROW, flagsb1, sizeof(flagsb1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_BOOT_FLAGS1_R2_ROW, flagsb1, sizeof(flagsb1)));

    const uint8_t *crit1 = otp_buffer_raw(OTP_DATA_CRIT1_ROW);
    alignas(4) uint8_t flagsc1[] = { crit1[0] | (1 << OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_LSB), crit1[1], crit1[2], 0x00 };
    if (secure_lock) {
        flagsc1[0] |= (1 << OTP_DATA_CRIT1_DEBUG_DISABLE_LSB);
        flagsc1[0] |= (1 << OTP_DATA_CRIT1_GLITCH_DETECTOR_ENABLE_LSB);
        flagsc1[0] |= (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB);
    }
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R1_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R2_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R3_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R4_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R5_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R6_ROW, flagsc1, sizeof(flagsc1)));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R7_ROW, flagsc1, sizeof(flagsc1)));

    if (secure_lock) {
        const uint8_t *page1 = otp_buffer_raw(OTP_DATA_PAGE1_LOCK1_ROW);
        uint8_t page1v = page1[0] | (OTP_DATA_PAGE1_LOCK1_LOCK_BL_VALUE_READ_ONLY << OTP_DATA_PAGE1_LOCK1_LOCK_BL_LSB);
        alignas(4) uint8_t flagsp1[] = { page1v, page1v, page1v, 0x00 };
        PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_PAGE1_LOCK1_ROW, flagsp1, sizeof(flagsp1)));
        const uint8_t *page2 = otp_buffer_raw(OTP_DATA_PAGE2_LOCK1_ROW);
        uint8_t page2v = page2[0] | (OTP_DATA_PAGE2_LOCK1_LOCK_BL_VALUE_READ_ONLY << OTP_DATA_PAGE2_LOCK1_LOCK_BL_LSB);
        alignas(4) uint8_t flagsp2[] = { page2v, page2v, page2v, 0x00 };
        PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_PAGE2_LOCK1_ROW, flagsp2, sizeof(flagsp2)));
    }

    goto err;
err:
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    return PICOKEYS_OK;
}

void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out) {
    otp_migrate_chaff();

    int ret = 0;
    uint16_t write_otp[2] = {0xFFFF, 0xFFFF};
    if (is_empty_otp_buffer(OTP_KEY_1, 32)) {
        uint8_t mkek[32] = {0};
        random_fill_buffer(mkek, sizeof(mkek));
        ret = otp_write_data(OTP_KEY_1, mkek, sizeof(mkek));
        if (ret != 0) {
            printf("Error writing OTP key 1 [%d]\n", ret);
        }
        otp_chaff(OTP_KEY_1, 32);
        mbedtls_platform_zeroize(mkek, sizeof(mkek));
        write_otp[0] = OTP_KEY_1;
    }
    *otp_key_1_out = otp_buffer(OTP_KEY_1);

    if (is_empty_otp_buffer(OTP_KEY_2, 32)) {
        mbedtls_ecdsa_context ecdsa;
        size_t olen = 0;
        uint8_t pkey[MBEDTLS_ECP_MAX_BYTES];
        while (olen != 32) {
            mbedtls_ecdsa_init(&ecdsa);
            mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_SECP256K1;
            mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_fill_iterator, NULL);
            mbedtls_ecp_write_key_ext(&ecdsa, &olen, pkey, sizeof(pkey));
            mbedtls_ecdsa_free(&ecdsa);
        }
        ret = otp_write_data(OTP_KEY_2, pkey, olen);
        if (ret != 0) {
            printf("Error writing OTP key 2 [%d]\n", ret);
        }
        mbedtls_platform_zeroize(pkey, sizeof(pkey));
        otp_chaff(OTP_KEY_2, 32);
        write_otp[1] = OTP_KEY_2;
    }
    *otp_key_2_out = otp_buffer(OTP_KEY_2);

    for (size_t i = 0; i < sizeof(write_otp) / sizeof(write_otp[0]); i++) {
        if (write_otp[i] != 0xFFFF) {
            otp_lock_page(write_otp[i] >> 6);
        }
    }
}
